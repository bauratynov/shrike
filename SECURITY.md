# Security Policy

## Supported versions

Starting at 1.0.0, `shrike` ships with a stable API contract. The
following are guaranteed not to break without a major version bump:

- CLI flag names and meaning listed in `shrike --help` and `shrike(1)`
- JSON output schema (keys + semantics, not whitespace)
- SARIF output shape
- Exit codes 0 / 1 / 2

Pre-1.0 releases are development previews; flag semantics may shift
between minors.

## Reporting a vulnerability

If you find a memory-safety issue, a parser crash on a crafted
input, or an output that silently mis-advertises a hardening
verdict, email:

**Baurzhan Atynov** — `bauratynov@gmail.com`

Please include:
- affected version / commit
- minimal reproducer (a zipped input file is ideal)
- observed vs expected behaviour

You will get a reply within 72 hours. Fixes are prioritised over
features.

## Threat model

`shrike` is a static analyser. It only reads files. It does not
execute, modify, or load the binaries it inspects. Memory safety on
adversarial inputs is the primary concern:

- Every offset in `src/elf64.c` is bounds-checked before
  dereferencing.
- Length decoder rejects unsupported prefixes / illegal-in-64
  opcodes cleanly.
- AFL++/libFuzzer harness under `fuzz/` is run on every v*.0
  release candidate.

## Release artefact integrity

Release tarballs on GitHub are signed with **minisign** starting at
1.0.0. The public key is committed in `packaging/minisign.pub`.

```bash
minisign -Vm shrike-linux-x86_64.tar.gz -p packaging/minisign.pub
```
