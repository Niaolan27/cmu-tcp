# CP1 Plan

## Establishing the 3-way handshake

The handshake happens **inside the loop body** in `begin_backend`, not before it.
The socket tracks a handshake state; based on role (initiator/listener) and
state, the backend behaves differently on each loop iteration.

Rationale for keeping it in the loop: any code that blocks before (or instead
of) the loop body stops the death check at `backend.c:226-229` from running,
stops `sending_buf` from being serviced, and holds `recv_lock` so `cmu_read`
stalls. `cmu_close` sets `dying` and then calls `pthread_join`, so an
unresponsive backend hangs the application.

### Loop structure

- The loop polls with a **short bounded timeout** (tick), not `DEFAULT_TIMEOUT`.
  The tick is the loop's heartbeat: it sleeps in the kernel (no busy-spin) but
  returns often enough to check timers, service `sending_buf`, and check `dying`.
  - Tick length is the worst-case lateness of any timer. Target range 10-50ms
    against a 3000ms timeout. **Never 0** (busy-spin pegs a core).
  - `check_for_data`'s `TIMEOUT` case currently hardcodes `DEFAULT_TIMEOUT`
    (`backend.c:142`); this needs to become a parameter.
- Dispatch is on **(role, state)**. The earlier `type == TCP_INITIATOR` gate is
  dropped: the listener also needs per-iteration work (its SYN-ACK timer).

### Timers

Two retransmission timers, one per role, for the one packet each role is
responsible for resending:

| field | owner | guards |
|---|---|---|
| `sent_SYN_time` | initiator | SYN retransmission |
| `sent_SYNACK_time` | listener | SYN-ACK retransmission |

Rule on each tick: `if (ms_since(&sent_X_time) > DEFAULT_TIMEOUT)` -> resend,
then update the timestamp.

- Use `CLOCK_MONOTONIC` (the wall clock can jump backward under NTP, which would
  wedge the timer). Helper:

```c
static long ms_since(const struct timespec *then) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - then->tv_sec) * 1000L +
         (now.tv_nsec - then->tv_nsec) / 1000000L;
}
```

- A timer must **not** be reset by the arrival of an unrelated or invalid
  packet. `poll` returns on *any* datagram, so "poll returned" is not "my
  timeout expired." The elapsed check is the only thing that decides a resend.
- The third-leg ACK gets **no timer**. Nothing ever acknowledges it, so there is
  no condition that would stop such a timer. Re-ACKing is event-driven instead
  (see initiator SENT_ACK below).

### Initiator states

`INIT -> SENT_SYN -> SENT_ACK`

- **INIT** - means "no valid timestamp yet." Send the first SYN
  *unconditionally*, record `sent_SYN_time`, transition to SENT_SYN. This branch
  must never consult the timer: before the first send, `sent_SYN_time` holds no
  meaningful value, and an elapsed check against a zeroed timestamp would fire
  immediately.
- **SENT_SYN**
  - On each tick: if `DEFAULT_TIMEOUT` has elapsed, resend the SYN and update
    `sent_SYN_time`.
  - On a packet arrival: if it is a valid SYN-ACK, transmit an ACK and
    transition to SENT_ACK. If it is **invalid, remain in SENT_SYN and leave
    `sent_SYN_time` untouched.**
- **SENT_ACK** - handshake complete from this side's point of view; may begin
  sending data packets.
  - Sending data optimistically is safe: unacknowledged data is retransmitted
    anyway, so at worst a lost third-leg ACK costs one timeout. There is no
    fourth packet that would ever confirm the ACK arrived, so waiting for
    confirmation is not an option.
  - If a (duplicate) SYN-ACK arrives while in SENT_ACK, respond with another
    ACK. SENT_ACK is therefore **not terminal** with respect to handshake
    packets.
  - Note: `SYN|ACK` is `0xC`. `handle_message`'s `switch (flags)` uses exact
    equality (`backend.c:60`), so it matches neither `ACK_FLAG_MASK` nor
    `SYN_FLAG_MASK` and falls into `default`. Flags must be tested with `&`.

Pseudocode for initiator:
```
while(1){
    switch(state)
        case(INIT):
            sock->isn = generate_random_seq_num()
            sock->window.last_ack_received = sock->isn
            send_syn_packet(seq = sock->window.last_ack_received, ack = sock->window.next_seq_expected)
            sent_syn_time = now()
            state = SENT_SYN
            break
        case(SENT_SYN):
            time_since_last_syn = now() - sent_syn_time
            if (time_since_last_syn > DEFAULT_TIMEOUT){
                send_syn_packet(seq = sock->isn, ack = 0)
                sent_syn_time = now()
            }
            break

    // hold back sending data until HANDSHAKE_ESTABLISHED
}

handle_message(){
    // a bunch of code
    // check for syn_ack packet -> respond with ack
    // drop syn_ack packet if state is HANDSHAKE_ESTABLISHED
    case (SYN_FLAG_MASK | ACK_FLAG_MASK):
        if ((state == SENT_SYN) && check_valid_syn_ack(packet)){
            sock->window.next_seq_expected = packet.seq_num + 1
            sock->window.last_ack_received = packet.ack_num
            send_ack_packet(ack = sock->window.next_seq_expected, seq_num = sock->window.last_ack_received)
            state = HANDSHAKE_ESTABLISHED
        }
        else if ((state == HANDSHAKE_ESTABLISHED) && check_valid_syn_ack(packet)){
            send_ack_packet(ack = sock->window.next_seq_expected, seq_num = sock->window.last_ack_received)
        }
        break
    // more cases
}

check_valid_syn_ack(packet){
    return (packet.ack == sock->isn + 1)
}
```

### Listener states

`INIT -> RECEIVED_SYN -> RECEIVED_ACK`

- **INIT** - purely reactive. On receiving a valid SYN: transmit a SYN-ACK,
  record `sent_SYNACK_time`, transition to RECEIVED_SYN.
  - This ordering works because a listener's `sock->conn` starts as
    `INADDR_ANY` (`cmu_tcp.c:85-88`) and is only populated as a side effect of
    `recvfrom`'s source-address out-param (`backend.c:133-134`, `148-150`). The
    arriving SYN is what gives the listener somewhere to send the SYN-ACK.
- **RECEIVED_SYN**
  - On each tick: if `DEFAULT_TIMEOUT` has elapsed, resend the SYN-ACK and
    update `sent_SYNACK_time`.
  - On receiving an ACK: transition to RECEIVED_ACK; handshake over.
- **RECEIVED_ACK** - established.

```
while(1){
    switch(state)
        case(RECEIVED_SYN):
            // check if DEFAULT_TIMEOUT has elapsed since last syn-ack
            time_since_last_synack = now() - sock->sent_synack_time
            if (time_since_last_synack > DEFAULT_TIMEOUT){
                send_syn_ack_packet(ack = sock->window.next_seq_expected, seq = sock->window.last_ack_received)
                sock->sent_synack_time = now()
            }

}

handle_message(){
    switch(packet)
        case(SYN_FLAG_MASK):
            if (state == INIT) {
                sock->isn = generate_random_seq_num()
                sock->window.last_ack_received = sock->isn
                sock->window.next_seq_expected = packet->seq + 1
                send_syn_ack_packet(ack = sock->window.next_seq_expected, seq = sock->window.last_ack_received)
                sock->sent_synack_time = now() // new field
                state = RECEIVED_SYN
            }
        case (ACK_FLAG_MASK):
            if ((state == RECEIVED_SYN) && check_valid_ack(packet)){
                state = HANDSHAKE_ESTABLISHED
            }
}

int check_valid_ack(packet) {
    return (packet->ack == sock->window.last_ack_received + 1)
}
```

### Concurrency note

`handle_message` is only called from `check_for_data`, which is only called from
`begin_backend` and `single_send` - all on the backend thread. So handshake
state and timer fields need **no locking** between the loop body and the packet
handler. A lock would only be required if something in `cmu_tcp.c` (app thread)
had to read them.

---

## TODO: sequence numbers

**Not yet specified. This is the core of the handshake and blocks
implementation.** The state machine above is scaffolding; synchronizing the two
sequence spaces is the actual purpose.

To resolve:

- `cmu_socket` currently zeroes both directions (`cmu_tcp.c:51-55`), with a
  `FIXME` saying ISNs should be random and `next_seq_expected` should come from
  the peer's SYN. Decide the ISN scheme and where it is set.
- For each of the three packets (SYN, SYN-ACK, ACK), in both directions: what
  goes in `seq`, and what goes in `ack`?
- On receipt of each, what socket state is written, and from which header field?
- Does a SYN consume a byte of sequence space? Data point already available:
  `test_cp1_basic_ack_packets.py:48-55` sends `seq_num=1000, flags=SYN_MASK` and
  requires the reply's `ack_num == 1000 + 1`.
- Which of these values must survive into data transfer, so that the first data
  byte continues the sequence space the handshake established?

## TODO: validity checks

**Not yet specified.** "Valid SYN-ACK" (initiator, SENT_SYN) and "valid SYN"
(listener, INIT) are load-bearing - an initiator that accepts *any* SYN-ACK
behaves differently from one that checks it against the SYN it actually sent.

To resolve:

- Which header fields are checked, and against what stored state?
- What happens to a packet that fails the check (ignored silently? any reply?).

```
```
## TODO: duplicate and unexpected packets

Normal loss path, not an edge case: if the listener's SYN-ACK drops, the
initiator's SYN timer fires and resends a SYN, which arrives at a listener
already in RECEIVED_SYN.

To resolve:

- **Duplicate SYN in RECEIVED_SYN**: ignore and wait for `sent_SYNACK_time`, or
  respond immediately with a fresh SYN-ACK? Both converge; one is faster. If it
  re-handles the SYN, does anything get re-initialized that must *not* be?
  (Consider what was recorded when the first SYN was processed.)
- **Data packet in RECEIVED_SYN**: the initiator sends its ACK and immediately
  starts sending data, so if that ACK is lost, data arrives at an unestablished
  listener. Current plan drops it and relies on the sender's retransmission.
  State this explicitly.
- **ACK carrying a payload**: the provided test sends `flags=ACK_MASK` *with* a
  payload (`test_cp1_basic_ack_packets.py:85-95`) and expects the payload
  acknowledged. Today `handle_message` would hit the `ACK_FLAG_MASK` case and
  silently drop those bytes.
- **Stray SYN at a RECEIVED_ACK listener**: currently falls into
  `handle_message`'s `default` branch, which fires off an ACK for it. Decide
  whether that is wanted.

## TODO: retransmission caps

Open. Nothing in the repo requires a cap (no constant, no test). The handout's
CP1 section is the authority.

- If the listener resends SYN-ACKs forever and the initiator has disappeared,
  the backend never breaks out, so `cmu_close` -> `pthread_join` hangs. Note
  that `backend.c:235` breaks only on `death && buf_len == 0`.
- If a cap is added, "give up" has no obvious reporting path: `cmu_socket`
  already returned `EXIT_SUCCESS` (`cmu_tcp.c:107-108`), and `cmu_read` /
  `cmu_write` have no error path for "never connected."

## Design choice recorded

The handshake can only complete via the SYN-ACK/ACK exchange. `single_send`
already stamps an ack number on every data packet (`backend.c:191`), so a data
packet's ack field *could* substitute for a lost third-leg ACK, but the plan
deliberately does not use it: the listener ignores unestablished traffic. Cost
is one `DEFAULT_TIMEOUT` of dead air when the third ACK drops; benefit is
simpler dispatch logic.

---

## Sliding window (Go-Back-N)

The window is driven by the **backend loop**, not by a blocking `single_send`.
`single_send` becomes a non-blocking "fill the window" step: it sends whatever
the window currently allows and returns. ACKs slide the window in
`handle_message`; the retransmit timer is checked on each loop tick. This is
also the shape CP2 needs (flow and congestion control only change the window
size).

### Why not inside `single_send`

Today `single_send` (`backend.c:296-304`) loops until every byte of its batch is
acked. Keeping the window inside it would:

- **Block the loop body** - the same problem the handshake plan avoids. While it
  runs, new `cmu_write` data can't join the window (it drains to empty at the
  end of every batch), and a waiting `cmu_read` isn't signaled
  (`backend.c:391`) even though `check_for_data` keeps filling `received_buf`.
- **Need state that outlives the call anyway** - unacked bytes, the next seq to
  send, and the timer must persist until ACKs arrive. Today the batch is a local
  copy freed right after the call returns (`backend.c:369-376`).
- **Split ACK processing** - `handle_message` already advances
  `last_ack_received`, so the window already slides outside `single_send`.
- **Use `poll` as the timer** - `check_for_data(sock, TIMEOUT, DEFAULT_TIMEOUT)`
  (`backend.c:300`) returns on *any* packet, and the current loop resends
  whenever that packet doesn't ack `seq`. With a window, ACKs arrive constantly.
  Same rule as the handshake timers: elapsed time is the only thing that decides
  a resend.

### State

| field | meaning |
|---|---|
| `window.last_ack_received` | **base**: oldest unacked seq (existing field) |
| `window.next_seq_to_send` | seq of the next *new* byte; high-water mark of what was sent |
| `outbound_buf`, `outbound_len` | bytes from base onward: in flight, then not yet sent |
| `sent_data_time` | retransmit timer start (monotonic), for the oldest unacked segment |

Window size for CP1 is `CP1_WINDOW_SIZE` (`grading.h`, `MSS * 32`).

Invariants (all `uint32_t` arithmetic, so wraparound is safe):

- `outbound_buf[0]` is the byte with seq `last_ack_received`.
- `in_flight = next_seq_to_send - last_ack_received`, and
  `0 <= in_flight <= min(outbound_len, CP1_WINDOW_SIZE)`.
- Bytes `[0, in_flight)` are sent and unacked; `[in_flight, outbound_len)` are
  unsent.
- The timer is **running iff `in_flight > 0`**. No separate flag:
  `sent_data_time` is only consulted when something is in flight.

### Backend loop

Per iteration, after the handshake timers:

```
lock(send_lock)
if (established && sending_len > 0) {
    append sending_buf to outbound_buf     // copied out as today, but kept
    free sending_buf; sending_len = 0
}
pending = sending_len
unlock(send_lock)

if (dying && pending == 0 && outbound_len == 0) break   // see Exit below

if (established) {
    if (in_flight > 0 && ms_since(&sent_data_time) > DEFAULT_TIMEOUT) {
        resend_window(sock)                // Go-Back-N
    }
    single_send(sock)                      // fill the window; never blocks
}

check_for_data(sock, TIMEOUT, LOOP_TICK_MS)   // ACKs slide the window here
signal wait_cond if received_len > 0
```

### Sending

```
single_send(sock) {
    while (in_flight < CP1_WINDOW_SIZE && in_flight < outbound_len) {
        len = min(MSS, outbound_len - in_flight, CP1_WINDOW_SIZE - in_flight)
        if (in_flight == 0) sent_data_time = now()   // pipe was empty: start timer
        send_data_segment(sock, next_seq_to_send, outbound_buf + in_flight, len)
        next_seq_to_send += len
    }
}
```

- `send_data_segment` is the existing `create_packet` + `sendto` code from
  `single_send` pulled into a helper, with `seq` passed in. Today `seq` is read
  from `last_ack_received` (`backend.c:282`), which is only correct with one
  packet in flight.
- No `check_for_data` inside `single_send` any more.

### Retransmission

```
resend_window(sock) {
    for (off = 0; off < in_flight; off += len) {
        len = min(MSS, in_flight - off)
        send_data_segment(sock, last_ack_received + off, outbound_buf + off, len)
    }
    sent_data_time = now()
}
```

- Go-Back-N: on timeout, everything in flight is resent, starting from base.
- `next_seq_to_send` is unchanged, so it stays the high-water mark that ACK
  validation checks against.

### ACK processing (`handle_message`, `ACK_FLAG_MASK` case)

```
ack = get_ack(hdr)
if (state == RECEIVED_SYN) {
    if (check_valid_ack(sock, hdr)) {
        state = HANDSHAKE_ESTABLISHED
        last_ack_received = ack       // acks the SYN's seq; nothing to trim
        next_seq_to_send = ack
    }
    break
}
if (after(ack, last_ack_received) && !after(ack, next_seq_to_send)) {
    drop the first (ack - last_ack_received) bytes of outbound_buf
    last_ack_received = ack
    if (in_flight > 0) sent_data_time = now()   // restart for new oldest segment
}
// ack <= base: old or duplicate, ignore (CP2 counts these).
// ack > next_seq_to_send: acks bytes never sent, ignore.
```

### Receiver side

- The `default` (data) case acks `get_seq(hdr) + get_payload_len(pkt)`
  (`backend.c:172`) - the end of *whatever packet arrived*, sent before the
  in-order check (`backend.c:187`). Harmless under stop-and-wait. With a window,
  if packet 1 is lost and packet 2 arrives, that ACK covers packet 1's bytes,
  and the sender trims data the receiver never got.
- Go-Back-N receiver: accept only `seq == next_seq_expected`, discard anything
  else, and always ACK **`next_seq_expected`** (cumulative), *after* updating it.

### Handshake hand-off

- On every transition to `HANDSHAKE_ESTABLISHED`, set
  `next_seq_to_send = last_ack_received` (= ISN + 1). So `in_flight == 0` and
  the first data byte continues the sequence space right after the SYN.
  - Initiator: in the SYN-ACK case, after `last_ack_received = get_ack(hdr)`.
  - Listener: in the ACK case, as above.
- The handshake ACK moves base past the SYN's seq but must **not** go through
  the trim path: the SYN's byte was never in `outbound_buf`.

### Concurrency

- `outbound_buf`, `next_seq_to_send`, and `sent_data_time` are touched only by
  the loop, `single_send`, and `handle_message`, all on the backend thread, so
  they need **no lock** (same argument as the handshake fields).
- `sending_buf` is still shared with `cmu_write`; only the hand-off into
  `outbound_buf` takes `send_lock`, as today.

### Exit

- `backend.c:364` breaks on `death && buf_len == 0`. With a window,
  `sending_buf` can be empty while bytes are still unacked in `outbound_buf`;
  breaking then drops in-flight data. Exit requires **both** to be empty.
- Consequence: if the peer has gone, the sender retransmits forever and
  `cmu_close` hangs. Same open question as retransmission caps above.

## TODO: window open items

- **Trimming cost.** `memmove` on every ACK is O(`outbound_len`). Since the loop
  moves all of `sending_buf` at once, one large `cmu_write` makes every ACK copy
  the whole remainder. Alternative: keep a start offset and compact only when
  appending.
- **Segment boundaries on resend** are recomputed from base in MSS chunks, so
  they may not match the originals if a short segment was sent. Correct with
  byte-based cumulative ACKs, but a misaligned resend can be discarded by the
  receiver and cost an extra timeout.

## Design choice recorded (window)

Alternative considered for timeouts: rewind `next_seq_to_send` to base and let
`single_send` resend. Fewer code paths, but `next_seq_to_send` stops being the
high-water mark, so an ACK for data sent before the rewind fails the
`!after(ack, next_seq_to_send)` check and that data is resent needlessly. Plan
uses an explicit `resend_window` instead.
