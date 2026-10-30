#!/usr/bin/env python3
"""Sends a file from the client container to the server container under
network conditions set with tcconfig, then compares the received file with the
original.

Run it from inside either container:

    cd /vagrant/project-2_15-441
    python3 tests/run_transfer.py --loss 1
    python3 tests/run_transfer.py --client-loss 2 --server-loss 0 --delay 50ms

tcset shapes each container's outgoing packets, so loss on the client drops
data and loss on the server drops ACKs. The client's congestion-control trace
(a CSV row per change in cwnd, ssthresh, or state) goes to --cwnd-log. Both
containers are put back to the Vagrantfile's shaping afterwards.
"""

import argparse
import os
import subprocess
import sys
import time

from fabric import Connection

from common import CODE_DIR, IP_ADDRS

# The Vagrantfile's shaping, restored after each run.
DEFAULT_RATE = "100Mbps"
DEFAULT_DELAY = "20ms"

OUTPUT = "/tmp/transfer.output"
SERVER_LOG = "/tmp/transfer_server.log"
SERVER_SESSION = "transfer_server"
FIND_IFNAME = "ip -o -4 addr show | awk '/ 10\\.0\\.1\\./ {print $2}'"


def shape(conn, rate, delay, loss):
    """Replaces the shaping on conn's 10.0.1.x interface."""
    ifname = conn.run(FIND_IFNAME, hide=True).stdout.strip()
    cmd = f"sudo tcset {ifname} --rate {rate} --delay {delay} --overwrite"
    if loss:
        cmd += f" --loss {loss}%"
    conn.run(cmd, hide=True)
    print(f"{conn.host} ({ifname}): rate={rate} delay={delay} loss={loss}%")


def sha256(conn, path):
    result = conn.run(f"sha256sum {path}", hide=True, warn=True)
    return result.stdout.split()[0] if result.ok else None


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--file",
        default=f"{CODE_DIR}/tests/large.input",
        help="file to send; created from /dev/urandom if missing",
    )
    parser.add_argument(
        "--size",
        default="20M",
        help="size of a newly created --file, in `head -c` units "
        "(default: 20M)",
    )
    parser.add_argument("--rate", default=DEFAULT_RATE)
    parser.add_argument(
        "--delay",
        default=DEFAULT_DELAY,
        help="added to each side's outgoing packets, so RTT is about double",
    )
    parser.add_argument(
        "--loss", type=float, default=0, help="loss %% on both sides"
    )
    parser.add_argument(
        "--client-loss",
        type=float,
        help="loss %% on client -> server packets (data); overrides --loss",
    )
    parser.add_argument(
        "--server-loss",
        type=float,
        help="loss %% on server -> client packets (ACKs); overrides --loss",
    )
    parser.add_argument("--cwnd-log", default=f"{CODE_DIR}/cwnd.csv")
    parser.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="seconds before the client is killed (default: 1800)",
    )
    args = parser.parse_args()
    client_loss = args.loss if args.client_loss is None else args.client_loss
    server_loss = args.loss if args.server_loss is None else args.server_loss
    # The client runs over SSH from its home directory. /vagrant is mounted at
    # the same path in both containers, so absolute paths resolve the same.
    args.file = os.path.abspath(args.file)
    args.cwnd_log = os.path.abspath(args.cwnd_log)

    # /vagrant is shared, so a file created here is visible to the client.
    subprocess.run(
        f"test -f {args.file} || head -c {args.size} /dev/urandom > "
        f"{args.file}",
        shell=True,
        check=True,
    )

    passed = False
    with (
        Connection(
            host=IP_ADDRS["server"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as server,
        Connection(
            host=IP_ADDRS["client"],
            user="vagrant",
            connect_kwargs={"password": "vagrant"},
        ) as client,
    ):
        try:
            client.run(f"make -C {CODE_DIR}", hide=True)
            shape(client, args.rate, args.delay, client_loss)
            shape(server, args.rate, args.delay, server_loss)

            server.run(f"rm -f {OUTPUT}", hide=True)
            server.run(
                f"tmux kill-session -t {SERVER_SESSION}", hide=True, warn=True
            )
            server.run(
                f"tmux new -s {SERVER_SESSION} -d "
                f"'{CODE_DIR}/server {OUTPUT} > {SERVER_LOG} 2>&1'"
            )
            time.sleep(0.5)

            size = client.run(f"stat -c %s {args.file}", hide=True)
            print(f"Sending {args.file} ({size.stdout.strip()} bytes)...")
            result = client.run(
                f"CWND_LOG={args.cwnd_log} timeout {args.timeout} "
                f"{CODE_DIR}/client {args.file}",
                warn=True,
            )
            if result.exited == 124:
                print(f"Client still running after {args.timeout} s; killed")
            else:
                # The server stays up a few RTOs after the last byte.
                server.run(
                    "timeout 60 sh -c 'while tmux has-session -t "
                    f"{SERVER_SESSION} 2>/dev/null; do sleep 1; done'",
                    hide=True,
                    warn=True,
                )
            print("Server output (last lines):")
            server.run(f"tail -3 {SERVER_LOG}", warn=True)

            sent = sha256(client, args.file)
            received = sha256(server, OUTPUT)
            passed = result.ok and sent is not None and sent == received
            if received is None:
                print(f"Server never wrote {OUTPUT}")
            else:
                print(f"Hashes {'match' if sent == received else 'DIFFER'}")
            print(f"cwnd trace: {args.cwnd_log}")
        finally:
            server.run(
                f"tmux kill-session -t {SERVER_SESSION}", hide=True, warn=True
            )
            shape(client, DEFAULT_RATE, DEFAULT_DELAY, 0)
            shape(server, DEFAULT_RATE, DEFAULT_DELAY, 0)

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
