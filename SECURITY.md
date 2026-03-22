# Security Policy

## Scope

`shrike` is a defensive audit tool. It reads ELF64 binaries read-only,
enumerates ROP/JOP gadgets, and prints them. It does not execute the
binaries, does not patch them, does not load them into a process, and
does not communicate with any network service.

## Reporting a vulnerability

If you believe you have found a security issue in `shrike` itself —
memory safety bug in the ELF loader, parser crash on a crafted
malicious binary, or a confused-deputy pattern — please email the
maintainer rather than opening a public issue:

**Baurzhan Atynov** — `bauratynov@gmail.com`

Include:
- description of the issue,
- minimal reproducer (crafted ELF file, zipped),
- affected commit / version,
- expected correct behaviour.

You will get a response within 72 hours. Fixes are prioritised over
features.

## Threat model

- **Malformed ELF input.** Every file offset in `src/elf64.c` is
  bounds-checked against file size before dereferencing. Garbage bytes
  are refused with an error, not parsed into undefined behaviour.
- **Truncated instructions.** The length decoder returns -1 when an
  instruction would extend past the available buffer, and the scanner
  treats those candidates as invalid.
- **Adversarially crafted `.text`.** A malicious ELF may attempt to
  exploit parser bugs. All parsing paths aim to be memory-safe at
  the C99 level; ASan + UBSan runs in CI on every commit.

## Not a vulnerability

- False positives (gadget chains that decode consistently but aren't
  reached at runtime) are expected — that is the nature of static
  gadget enumeration.
- Missed gadgets involving VEX-encoded instructions (`C4`/`C5`
  prefixes), 3DNow, or rare x87 forms. These are explicit design
  limits, not bugs.
- Gadgets emitted from padding / data bytes inside executable
  segments. That's how real ROP works and shrike models it honestly.

## Companion tools

- [lbr-hunt](https://github.com/bauratynov/lbr-hunt) — runtime ROP
  detection via Intel LBR, the dynamic counterpart to shrike's
  static enumeration.
- [checkhard](https://github.com/bauratynov/checkhard) — ELF
  hardening auditor (PIE, NX, RELRO, canary, ...).
