#!/usr/bin/env python3
"""Generate small, loopback-only traffic patterns for netwatch-rs alerts."""

import argparse
import random
import socket
import struct
import sys
import time

LOOPBACK_HOSTS = {"127.0.0.1", "::1"}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="target host (loopback only)")
    parser.add_argument("--mode", choices=["scan", "syn", "dns", "all"], default="all")
    parser.add_argument("--ports", type=int, default=20, help="distinct ports for scan mode")
    parser.add_argument("--count", type=int, default=60, help="packets for syn/dns modes")
    parser.add_argument("--delay", type=float, default=0.02, help="delay between packets")
    args = parser.parse_args()
    if args.host not in LOOPBACK_HOSTS:
        parser.error("--host must be 127.0.0.1 or ::1")
    if args.ports < 1 or args.ports > 100 or args.count < 1 or args.count > 200:
        parser.error("--ports must be 1..100 and --count 1..200")
    return args


def connect(host, port):
    family = socket.AF_INET6 if host == "::1" else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.05)
        sock.connect_ex((host, port))


def port_scan(args):
    print(f"scan: {args.ports} ports on {args.host}")
    for offset in range(args.ports):
        connect(args.host, 20 + offset)
        time.sleep(args.delay)


def syn_spike(args):
    print(f"syn: {args.count} connection attempts to {args.host}:65500")
    for _ in range(args.count):
        connect(args.host, 65500)
        time.sleep(args.delay)


def dns_query(name):
    packet = struct.pack("!HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        packet += bytes([len(label)]) + label.encode("ascii")
    return packet + b"\x00" + struct.pack("!HH", 1, 1)


def dns_burst(args):
    print(f"dns: {args.count} queries from localhost")
    family = socket.AF_INET6 if args.host == "::1" else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.05)
        for index in range(args.count):
            name = f"burst-{index}-{random.randrange(1_000_000)}.example.test"
            sock.sendto(dns_query(name), (args.host, 53))
            time.sleep(args.delay)


def main():
    args = parse_args()
    try:
        if args.mode in ("scan", "all"):
            port_scan(args)
        if args.mode in ("syn", "all"):
            syn_spike(args)
        if args.mode in ("dns", "all"):
            dns_burst(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
