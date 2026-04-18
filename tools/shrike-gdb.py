"""
shrike-gdb.py — GDB integration for shrike.

Source it in your .gdbinit or load on demand:

    (gdb) source tools/shrike-gdb.py
    (gdb) shrike-scan

The `shrike-scan` command runs the shrike binary against the
currently-loaded executable and dumps the gadgets it finds into
the GDB session, each as a convenience variable $shrike_N that
holds the gadget's absolute address. Useful for interactive ROP
development: set a breakpoint, step into a vulnerable function,
then walk the chain via $shrike_0, $shrike_1, ...

Requires the `shrike` binary on $PATH (or SHRIKE_BINARY set).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

try:
    import gdb   # type: ignore
except ImportError:   # running under a non-GDB Python
    gdb = None        # type: ignore


SHRIKE_BINARY = os.environ.get("SHRIKE_BINARY", "shrike")


def _current_file() -> str:
    if gdb is None:
        raise RuntimeError("gdb.Python API not available")
    # gdb.current_progspace().filename gives the main inferior path.
    ps = gdb.current_progspace()
    if ps is None or ps.filename is None:
        raise RuntimeError("no inferior loaded — `file /path/to/bin` first")
    return ps.filename


def _run_shrike(path: str, extra_args: list[str]) -> list[dict]:
    exe = shutil.which(SHRIKE_BINARY) or SHRIKE_BINARY
    out = subprocess.check_output(
        [exe, "--json", "--quiet", *extra_args, path],
        text=True, errors="replace",
    )
    gadgets: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            gadgets.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return gadgets


class ShrikeScan(gdb.Command if gdb else object):
    """Scan the current inferior for ROP gadgets and expose them
    as $shrike_0, $shrike_1, ..."""

    def __init__(self) -> None:
        if gdb is None: return
        super().__init__("shrike-scan", gdb.COMMAND_USER)

    def invoke(self, arg: str, from_tty: bool) -> None:
        if gdb is None: return
        path = _current_file()
        args = gdb.string_to_argv(arg) if arg else []
        gadgets = _run_shrike(path, args)
        print(f"shrike: {len(gadgets)} gadgets")
        for i, g in enumerate(gadgets[:32]):
            addr = int(g["addr"], 16)
            gdb.execute(f"set $shrike_{i} = {addr}")
            line = f"  $shrike_{i} = 0x{addr:016x}"
            if "insns" in g:
                line += "  " + " ; ".join(g["insns"])
            print(line)
        if len(gadgets) > 32:
            print(f"  ... (+{len(gadgets) - 32} more, increase limit if needed)")


if gdb is not None:
    ShrikeScan()
