"""shrike — Python bindings for the shrike ROP gadget scanner.

The scanner itself is a static binary written in C99. The bindings
in this package wrap the CLI — `shrike(1)` is invoked as a
subprocess with `--json`, and its JSON-Lines output is streamed
back to the caller as Python dicts. No ctypes, no shared library
loading, no build-time Python headers: it just works wherever a
`shrike` binary is on `$PATH` (or at the path passed to
`scan(..., binary=)`).

v2.0.0 will add a ctypes-based fast path that calls libshrike.so
directly. Until then the subprocess route gives the same data
stream and is portable across every manylinux wheel.

Example:

    import shrike

    for g in shrike.scan("/bin/ls"):
        if g["category"] == "pop":
            print(f"{g['addr']}: {g['insns']}")
"""

from .cli import (
    scan,
    scan_raw,
    recipe,
    reg_index,
    version,
    ShrikeError,
    DEFAULT_BINARY,
)

__all__ = [
    "scan",
    "scan_raw",
    "recipe",
    "reg_index",
    "version",
    "ShrikeError",
    "DEFAULT_BINARY",
]
