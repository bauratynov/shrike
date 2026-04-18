#!/usr/bin/env python3
"""
lbr-ingest.py — convert `perf script -F ip,brstack` output into a
shrike `--reached-file` address list.

Usage:
    perf record -e cpu/branch-instructions/ -b ./target
    perf script -F ip,brstack > perf.txt
    tools/lbr-ingest.py perf.txt > reached.txt
    shrike --reached-file reached.txt target > hot.txt

The perf script output looks like:
    401234  0x7fff... -> 0x400abc ...
We extract every FROM/TO address, uniq them, and emit one per
line in 0x-prefixed hex. Comments and empty lines in the input
are ignored. This is the first half of the roadmap's LBR work;
the second half (deep integration that annotates rather than
filters) lands as a 4.x patch bump.
"""

from __future__ import annotations

import re
import sys
from typing import Iterable

HEX_PAT = re.compile(r"0x[0-9a-fA-F]+")


def addresses_from(lines: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for match in HEX_PAT.findall(line):
            seen.add(match.lower())
    return seen


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: lbr-ingest.py PERF_SCRIPT_OUTPUT\n")
        return 2
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
        addrs = addresses_from(fh)
    for addr in sorted(addrs):
        print(addr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
