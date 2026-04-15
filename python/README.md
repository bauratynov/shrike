# shrike — Python bindings

Thin wrapper around the `shrike` CLI. Subprocess-based today;
ctypes fast path lands in v2.0.0.

```python
import shrike

# Iterate every gadget in /bin/ls.
for g in shrike.scan("/bin/ls"):
    print(g["addr"], g["insns"])

# Filter to pop-class gadgets, skip any address containing a null byte.
for g in shrike.scan("/bin/ls", category=["pop"], bad_bytes=[0x00]):
    print(g["addr"], g["insns"])

# Resolve a chain recipe and print the composer output.
print(shrike.recipe("/bin/ls",
                    "rdi=*; rsi=*; rdx=*; rax=59; syscall",
                    fmt="text"))

# Register-control index as a plain dict.
idx = shrike.reg_index("/bin/ls")
print(idx["registers"]["rdi"])
```

## Install

Until v1.7.1 publishes to PyPI, drop `python/shrike/` onto your
`PYTHONPATH` and install a `shrike` binary somewhere on `$PATH`
(or set the `SHRIKE_BINARY` environment variable).

```
pip install -e python/
export PATH=$PWD:$PATH    # or wherever the shrike binary lives
python -c "import shrike; print(next(shrike.scan('/bin/ls')))"
```

## Why subprocess and not ctypes?

The v1.x C API is deliberately *not* frozen — STABILITY.md covers
the CLI, JSON schema, SARIF, and exit codes, but not the library
symbols. A ctypes binding that pinned against `libshrike.so.1.x`
would need to be rewritten for 2.0.0 when the proper C API lands.

So: 1.7.0 subprocesses the CLI and parses JSON-Lines. Same data
stream, no API drift exposure. 2.0.0 adds a real `libshrike.so`
binding alongside.

## License

MIT, same as the binary.
