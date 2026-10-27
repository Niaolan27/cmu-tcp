#!/usr/bin/env python3
"""Runs the checkpoint 2 loss sweep. For each loss probability p, sends a file
from the client (sender) to the server (receiver) --runs times and records how
long each transfer took. tcconfig holds the rate and delay fixed on both nodes
and applies loss only on the client, so only data packets are dropped.

Run it on the client. In the Vagrant containers, the defaults are right:

    cd /vagrant/project-2_15-441
    python3 tests/loss_sweep.py --runs 10 --out loss_sweep.csv

On two AWS instances, clone the repository to the same path on both, and give
the instances' private addresses and your SSH login:

    python3 tests/loss_sweep.py --server <receiver IP> --client <sender IP> \\
        --user ubuntu --key ~/key.pem --clear-shaping --runs 10 \\
        --out loss_sweep.csv

Each p sends its own random file, sized by SIZES so a transfer takes several
seconds. Rows are appended to --out as runs finish, so an interrupted sweep
keeps what it measured. Afterwards both nodes are put back to the
Vagrantfile's shaping, or have their shaping removed with --clear-shaping.
"""

import argparse
import csv
import os
import re
import time

from fabric import Connection

# This script's project-2_15-441 directory, assumed to be at the same path on
# both nodes.
CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RATE = "5Mbps"
DELAY = "20ms"
LOSSES = [0.1, 0.2, 0.5, 1, 2, 5, 10]  # Percent.
# Bytes to send at each loss percentage, from one calibration run per p in
# Vagrant: about 15 s per transfer.
SIZES = {
    0.1: 6_000_000,
    0.2: 6_000_000,
    0.5: 3_000_000,
    1: 3_000_000,
    2: 1_000_000,
    5: 384_000,
    10: 96_000,
}
FIELDS = ["loss_pct", "run", "bytes", "seconds", "throughput_mbps", "hash_ok"]

# The Vagrantfile's shaping, restored afterwards unless --clear-shaping.
DEFAULT_RATE = "100Mbps"
DEFAULT_DELAY = "20ms"

OUTPUT = "/tmp/transfer.output"
SERVER_LOG = "/tmp/transfer_server.log"
SERVER_SESSION = "transfer_server"


def interface(conn):
    """Returns the name of the interface that holds conn's address."""
    result = conn.run("ip -o -4 addr show", hide=True)
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields[3].split("/")[0] == conn.host:
            return fields[1]
    raise RuntimeError(f"No interface on {conn.host} has that address")


def shape(conn, rate, delay, loss):
    """Replaces the shaping on conn's interface."""
    ifname = interface(conn)
    cmd = f"sudo tcset {ifname} --rate {rate} --delay {delay} --overwrite"
    if loss:
        cmd += f" --loss {loss}%"
    conn.run(cmd, hide=True)
    print(f"{conn.host} ({ifname}): rate={rate} delay={delay} loss={loss}%")


def unshape(conn):
    """Removes all shaping from conn's interface."""
    ifname = interface(conn)
    conn.run(f"sudo tcdel {ifname} --all", hide=True)
    print(f"{conn.host} ({ifname}): shaping removed")


def sha256(conn, path):
    result = conn.run(f"sha256sum {path}", hide=True, warn=True)
    return result.stdout.split()[0] if result.ok else None


def connect(host, args):
    # The Vagrant containers take a password. AWS instances take a key, or
    # the agent that ssh -A forwards, which is tried before the password.
    if args.key:
        auth = {"key_filename": os.path.expanduser(args.key)}
    else:
        auth = {"password": "vagrant"}
    return Connection(host=host, user=args.user, connect_kwargs=auth)


def transfer(client, server, path, size, args):
    """Sends path once. Returns the client's reported duration in seconds (None
    if it didn't finish) and whether the server's copy matches."""
    server.run(f"rm -f {OUTPUT}", hide=True)
    server.run(f"tmux kill-session -t {SERVER_SESSION}", hide=True, warn=True)
    server.run(
        f"tmux new -s {SERVER_SESSION} -d "
        f"'{args.code_dir}/server {OUTPUT} > {SERVER_LOG} 2>&1'"
    )
    time.sleep(0.5)

    result = client.run(
        f"server15441={args.server} timeout {args.timeout} "
        f"{args.code_dir}/client {path}",
        hide=True,
        warn=True,
    )
    match = re.search(r"Sent \d+ bytes in ([\d.]+) s", result.stdout)

    # The client returns once every byte is ACKed, slightly before the server
    # has written the last of them; the server then lingers a few RTOs, which
    # this sweep doesn't need.
    server.run(
        f'timeout 30 sh -c \'until [ "$(stat -c %s {OUTPUT} 2>/dev/null)" '
        f"= {size} ]; do sleep 0.2; done'",
        hide=True,
        warn=True,
    )
    hash_ok = sha256(client, path) == sha256(server, OUTPUT)
    server.run(f"tmux kill-session -t {SERVER_SESSION}", hide=True, warn=True)
    return (float(match.group(1)) if match else None), hash_ok


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--losses",
        type=float,
        nargs="+",
        default=LOSSES,
        help="loss percentages to sweep (default: %(default)s)",
    )
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--out", default=f"{CODE_DIR}/loss_sweep.csv")
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="seconds before a transfer is killed (default: 600)",
    )
    parser.add_argument(
        "--server",
        default="10.0.1.1",
        help="the receiver's private IP address (default: %(default)s)",
    )
    parser.add_argument(
        "--client",
        default="10.0.1.2",
        help="the sender's private IP address, i.e. this machine's "
        "(default: %(default)s)",
    )
    parser.add_argument(
        "--user", default="vagrant", help="SSH user (default: %(default)s)"
    )
    parser.add_argument(
        "--key",
        help="SSH private key; without it, an agent forwarded by ssh -A or "
        "Vagrant's password is used",
    )
    parser.add_argument(
        "--code-dir",
        default=CODE_DIR,
        help="project-2_15-441 on both nodes (default: %(default)s)",
    )
    parser.add_argument(
        "--clear-shaping",
        action="store_true",
        help="remove all shaping afterwards instead of restoring the "
        "Vagrantfile's 100 Mbps and 20 ms",
    )
    args = parser.parse_args()
    args.out = os.path.abspath(args.out)

    with (
        connect(args.server, args) as server,
        connect(args.client, args) as client,
        open(args.out, "a", newline="") as out,
    ):
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        if out.tell() == 0:
            writer.writeheader()
        try:
            for conn in (client, server):
                conn.run(f"make -C {args.code_dir}", hide=True)
            for loss in args.losses:
                size = SIZES[loss]
                path = f"/tmp/sweep_{size}.input"
                client.run(
                    f"test -f {path} || head -c {size} /dev/urandom > {path}",
                    hide=True,
                )
                shape(client, RATE, DELAY, loss)
                shape(server, RATE, DELAY, 0)
                for run in range(1, args.runs + 1):
                    seconds, hash_ok = transfer(
                        client, server, path, size, args
                    )
                    mbps = size * 8 / seconds / 1e6 if seconds else None
                    writer.writerow(
                        {
                            "loss_pct": loss,
                            "run": run,
                            "bytes": size,
                            "seconds": seconds,
                            "throughput_mbps": mbps,
                            "hash_ok": hash_ok,
                        }
                    )
                    out.flush()
                    if seconds:
                        shown = f"{mbps:.3f} Mbps in {seconds} s"
                    else:
                        shown = "did not finish"
                    print(
                        f"p={loss}% run {run}: {shown}"
                        f"{'' if hash_ok else '  HASH MISMATCH'}",
                        flush=True,
                    )
        finally:
            server.run(
                f"tmux kill-session -t {SERVER_SESSION}", hide=True, warn=True
            )
            for conn in (client, server):
                if args.clear_shaping:
                    unshape(conn)
                else:
                    shape(conn, DEFAULT_RATE, DEFAULT_DELAY, 0)
    print(f"Results: {args.out}")


if __name__ == "__main__":
    main()
