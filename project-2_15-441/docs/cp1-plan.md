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

## Sliding window (Go-Back-N)

**Status: implemented** in `backend.c` (`single_send`, `resend_window`,
`handle_message`, `begin_backend`). 

The window is driven by the **backend loop**, not by a blocking `single_send`.
`single_send` becomes a non-blocking "fill the window" step: it sends whatever
the window currently allows and returns. ACKs slide the window in
`handle_message`; the retransmit timer is checked on each loop tick. This is
also the shape CP2 needs (flow and congestion control only change the window
size).

### State
- `outbound_buf` contains the bytes which need to be sent
- `window.last_ack_received` is the base of the sliding window
- `window.next_seq_to_send` is the next byte outside of the window
- `sent_data_time` helps us track timeout for sending data

Window size for CP1 is `CP1_WINDOW_SIZE` (`grading.h`, `MSS * 32`).

Invariants (all `uint32_t` arithmetic, so wraparound is safe):

- `outbound_buf[0]` is the byte with seq `last_ack_received`.
- `in_flight = next_seq_to_send - last_ack_received`, and
  `0 <= in_flight <= min(outbound_len, CP1_WINDOW_SIZE)`.
- Bytes `[0, in_flight)` are sent and unacked; `[in_flight, outbound_len)` are
  unsent.
- The timer is **running iff `in_flight > 0`**. No separate flag:
  `sent_data_time` is only consulted when something is in flight.

### Timer rules

`sent_data_time` is written in exactly three places:

1. `single_send` sends into an empty pipe (`in_flight == 0`): start.
2. An ACK moves base forward and data is still in flight: restart, so the timer
   now covers the new oldest segment.
3. `resend_window` runs: restart.

Nothing else touches it. In particular, a duplicate ACK or an unrelated packet
does **not** restart it. If waiting were `check_for_data(sock, TIMEOUT,
DEFAULT_TIMEOUT)`, every arrival would restart the 3s; after a loss the
receiver sends a duplicate ACK for each later segment, so each one would push
recovery back. The loop checks `ms_since(&sent_data_time) > DEFAULT_TIMEOUT` on
every pass, the same pattern as the SYN and SYN-ACK timers.

### Backend loop

Per iteration, after the handshake timers:

```
lock(send_lock)
if (established && sending_len > 0) {
    append sending_buf to outbound_buf     // copied out as today, but kept
    free sending_buf; sending_len = 0
}
pending = sending_len
unlock(send_lock)                          // before the break, unlike today

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

- Each pass handles at most one incoming packet. That is enough: when packets
  are queued, `poll` returns immediately, so a burst of ACKs drains at full
  loop speed. The `LOOP_TICK_MS` wait only applies when nothing is arriving.
- An ACK processed at the end of one pass is acted on at the top of the next,
  so freed window space is refilled within one pass.

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
- Data packets set the **ACK flag**, with `ack = next_seq_expected`, as the
  course tests expect (every packet after the SYN carries an ACK).

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
  That is only what is still unacked, not the original batch: if part of the
  window was acked before the timer fired, those bytes are already trimmed.
- `next_seq_to_send` is unchanged, so it stays the high-water mark that ACK
  validation checks against.

### ACK processing (`handle_message`, `ACK_FLAG_MASK` case)

Every packet after the SYN carries the ACK flag, so this case sees both pure
ACKs and data packets.

```
ack = get_ack(hdr)
if (state == RECEIVED_SYN) {
    if (!check_valid_ack(sock, hdr)) break
    state = HANDSHAKE_ESTABLISHED
    last_ack_received = ack           // acks the SYN's seq; nothing to trim
    next_seq_to_send = ack
} else if (state == HANDSHAKE_ESTABLISHED) {
    handle_ack(sock, ack)             // slide the window
} else {
    break
}
if (payload_len > 0) handle_data(sock, pkt)

handle_ack(sock, ack) {
    if (after(ack, last_ack_received) && !after(ack, next_seq_to_send)) {
        drop the first (ack - last_ack_received) bytes of outbound_buf
        last_ack_received = ack
        if (in_flight > 0) sent_data_time = now()   // restart for new oldest segment
    }
    // ack <= base: old or duplicate, ignore (CP2 counts these).
    // ack > next_seq_to_send: acks bytes never sent, ignore.
}

handle_data(sock, pkt) {
    if (seq == next_seq_expected) {   // in order: keep it
        append payload to received_buf
        next_seq_expected += payload_len
    }                                 // otherwise discard
    send ACK with ack = next_seq_expected   // cumulative, either way
}
```

- The ACK field of a data packet is processed like any other ACK, so ACKs
  piggybacked on data slide the window too.
- **Pure ACKs are never answered**; only packets with a payload get an ACK
  back. That keeps two peers from ACKing each other's ACKs forever, and the
  course test expects no reply to the third-leg ACK.
- If the third-leg ACK is lost, the initiator's first data packet carries the
  same `ack` value, so it completes the handshake at the listener and its
  payload is accepted. No timeout is spent waiting for a retransmit.
- Packets with a payload and **no** flags are still accepted as data once
  established, through the `default` case.
- The gate on `HANDSHAKE_ESTABLISHED` matters: before establishment
  `next_seq_to_send` hasn't been set, so the window's range check means
  nothing, and a stray ACK could move base.

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
