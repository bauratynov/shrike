"""Smoke tests for the Python bindings.

These don't require a shrike binary — they just verify the
module imports cleanly and its public API is the documented
shape. End-to-end tests that shell out to the binary live in
tests/test_subprocess.py and run in the Linux CI matrix only.
"""

from __future__ import annotations

import inspect
import sys
import types


def test_module_imports() -> None:
    import shrike
    assert isinstance(shrike, types.ModuleType)


def test_public_api_present() -> None:
    import shrike
    for name in ("scan", "scan_raw", "recipe", "reg_index",
                 "version", "ShrikeError", "DEFAULT_BINARY"):
        assert hasattr(shrike, name), f"missing {name!r}"


def test_scan_is_generator_factory() -> None:
    import shrike
    # scan() returns a generator object when called (we don't
    # actually iterate it here — would need a binary).
    sig = inspect.signature(shrike.scan)
    assert "path" in sig.parameters


def test_shrike_error_is_runtime_error() -> None:
    from shrike import ShrikeError
    assert issubclass(ShrikeError, RuntimeError)


def main() -> int:
    fails = 0
    for name, fn in list(globals().items()):
        if not name.startswith("test_"): continue
        try:
            fn()
            print(f"pass  {name}")
        except AssertionError as exc:
            fails += 1
            print(f"FAIL  {name}: {exc}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
