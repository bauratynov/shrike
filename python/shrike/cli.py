"""Subprocess-based wrapper around the shrike CLI.

All public functions take a `binary` keyword arg — defaults to the
shrike executable on $PATH. CI wheels pin this via an env var so
the bundled binary inside the wheel wins.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Iterable, Iterator, List, Mapping, Optional, Sequence

DEFAULT_BINARY = os.environ.get("SHRIKE_BINARY", "shrike")


class ShrikeError(RuntimeError):
    """Raised when the shrike binary exits non-zero or isn't found."""


def _resolve(binary: str) -> str:
    if os.path.sep in binary or os.path.isabs(binary):
        return binary
    path = shutil.which(binary)
    if path is None:
        raise ShrikeError(
            f"shrike binary {binary!r} not found on $PATH. "
            f"Set SHRIKE_BINARY or pass binary= to override."
        )
    return path


def _run(
    args: Sequence[str],
    binary: str = DEFAULT_BINARY,
    input_bytes: Optional[bytes] = None,
) -> str:
    exe = _resolve(binary)
    try:
        proc = subprocess.run(
            [exe, *args],
            input=input_bytes,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ShrikeError(str(exc)) from exc

    if proc.returncode not in (0, 2):
        # 0 = ok, 2 = bad invocation. Non-zero past that = real error.
        stderr = proc.stderr.decode("utf-8", errors="replace")
        raise ShrikeError(
            f"shrike exited {proc.returncode}: {stderr.strip()}"
        )
    if proc.returncode == 2:
        stderr = proc.stderr.decode("utf-8", errors="replace")
        raise ShrikeError(f"bad shrike invocation: {stderr.strip()}")
    return proc.stdout.decode("utf-8", errors="replace")


def version(binary: str = DEFAULT_BINARY) -> str:
    """Return the shrike binary's version string.

    Shells `shrike --version` and strips the "shrike " prefix. The
    bindings do no runtime/compile-time skew detection yet — that
    lands alongside the ctypes fast path in v2.
    """
    out = _run(["--version"], binary=binary).strip()
    if out.startswith("shrike "):
        return out[len("shrike "):]
    return out


def _stream_json(output: str) -> Iterator[dict]:
    """Parse one JSON object per non-empty line."""
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            # Summary / decorative lines are fine to skip.
            continue


def scan(
    path: str,
    *,
    binary: str = DEFAULT_BINARY,
    max_insn: Optional[int] = None,
    unique: bool = False,
    category: Optional[Iterable[str]] = None,
    bad_bytes: Optional[Iterable[int]] = None,
    extra_args: Optional[Sequence[str]] = None,
) -> Iterator[dict]:
    """Scan an ELF / PE / Mach-O file and yield gadgets as dicts.

    Each yielded dict has the shape documented in
    STABILITY.md under "JSON Lines schema":
    `{"addr": "0x...", "arch": "x86_64|aarch64|riscv64",
      "insns": [...], "bytes": "...",
      "category": "pop|mov|...", "shstk_blocked": bool,
      "starts_endbr": bool}`.

    The binary is invoked with `--json --quiet` plus whatever
    filters the caller requested. On a scan error, `ShrikeError`
    is raised before the generator yields anything.
    """
    args: List[str] = ["--json", "--quiet"]
    if max_insn is not None:
        args += ["--max-insn", str(max_insn)]
    if unique:
        args.append("--unique")
    if category:
        args += ["--category", ",".join(category)]
    if bad_bytes:
        args += ["--bad-bytes", ",".join(f"0x{b:02x}" for b in bad_bytes)]
    if extra_args:
        args += list(extra_args)
    args.append(path)

    output = _run(args, binary=binary)
    yield from _stream_json(output)


def scan_raw(
    path: str,
    *,
    arch: str,
    base: int,
    binary: str = DEFAULT_BINARY,
    extra_args: Optional[Sequence[str]] = None,
) -> Iterator[dict]:
    """Scan a headerless blob — e.g. an objcopy'd .text section.

    `arch` is the target ISA (`"x86_64"`, `"aarch64"`, `"riscv"`);
    `base` is the virtual address the first byte maps to.
    """
    args: List[str] = [
        "--json", "--quiet",
        "--raw", "--raw-arch", arch,
        "--raw-base", f"0x{base:x}",
    ]
    if extra_args:
        args += list(extra_args)
    args.append(path)
    output = _run(args, binary=binary)
    yield from _stream_json(output)


def recipe(
    path: str,
    recipe_src: str,
    *,
    binary: str = DEFAULT_BINARY,
    fmt: str = "text",
) -> str:
    """Run the chain composer and return its output verbatim.

    `fmt` is one of `"text"` (default) or `"pwntools"`. The return
    value is the raw CLI output — caller wraps or parses as needed.
    """
    args = ["--recipe", recipe_src, "--format", fmt, path]
    return _run(args, binary=binary)


def reg_index(
    path: str,
    *,
    binary: str = DEFAULT_BINARY,
    python: bool = False,
) -> Mapping[str, Sequence[str]]:
    """Return the register-control index as a dict-of-lists.

    If `python=True`, shrike's Python-dict emitter is used and the
    result is eval'd back (it's a known-safe literal). Otherwise
    the JSON emitter is used and parsed with `json.loads`.
    """
    if python:
        out = _run(["--reg-index", "--reg-index-python", path], binary=binary)
        # The Python emitter produces a self-contained dict
        # literal assignment; pull the dict out via ast.literal_eval.
        import ast
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("shrike_reg_index = "):
                return ast.literal_eval(line.split("=", 1)[1].strip())
        raise ShrikeError("could not locate reg-index dict in output")
    out = _run(["--reg-index", "--reg-index-json", path], binary=binary)
    return json.loads(out)
