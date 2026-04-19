# Known limitations

Stuff that doesn't work, won't work, or works badly. Read this
before filing a bug.

## Architectural

### x86-64
- **No 16-bit addressing forms** in the operand decoder. If your
  binary has `mov ax, [bx+si]` shapes, they render as
  `db 0x?, 0x?, ...`. Who's emitting 16-bit addressing in 2026?
- **No VEX/EVEX prefixes.** AVX gadgets render as `.byte` dump.
  Hits modern crypto libraries hard (openssl uses AVX heavily).
- **FS/GS segment prefixes** not normalised in output. A gadget
  `mov rax, fs:[0x28]` renders without the `fs:` qualifier.

### aarch64
- **PAC pointer authentication** — RETAA/RETAB detected, but
  AUTIASP / AUTIBSP preambles in a gadget just look like
  unknown opcodes (`.word 0x...`). Works on non-PAC binaries.
- **No SVE / NEON rendering**. Scalar integer + LDP/STP pairs
  only.
- **32-bit Thumb / ARM** out of scope. aarch64 only. Explicitly
  not on any roadmap.

### RV64
- **No M/A/F/D extension rendering.** We know the length via
  the RVC encoding, but multiplication / atomics / floats all
  show as `.word 0x...`. Gadget finding still works; output
  is ugly.
- **Compressed branches (C.BEQZ etc.)** don't register as
  terminators. So far OK — they're not indirect branches.

### PPC64
- **Little-endian only.** Big-endian ppc64be (AIX, old Linux)
  rejected by the loader. Fix is one xor on the read function;
  not shipping until someone asks.
- **No decoded branch target** for `bctr` / `blr`. The CTR /
  LR registers are architectural state we don't model.

### MIPS
- **Delay slot ignored.** This is not a bug, it's a scope
  decision. MIPS gadgets end at the branch itself. Chain
  consumers must budget one payload slot for the delay-slot
  instruction manually. Fix tracked as V5 sprint work.
- **No microMIPS / MIPS16e.** 32-bit classical MIPS encoding
  only.

## Loader

### ELF64
- **No RELA / REL parsing.** Shrike scans bytes; relocations
  are irrelevant to static gadget finding. Reported as "why
  didn't you decode `mov rax, <reloc>` properly" occasionally;
  WONTFIX — the bytes are what ld.so will execute.
- **PT_GNU_PROPERTY parsing is strict.** If the .note section
  has non-aligned entries (some older gcc), we skip the note
  and report "no CET flags". Consider running `readelf -n` to
  diff against ground truth.

### PE
- **PE32 (32-bit i386 Windows)** rejected. PE32+ (64-bit) only.
  The DataDirectory offset differs and I don't have a
  test corpus.
- **Overlays are NOT scanned.** If a signed binary has bytes
  past `max(PointerToRawData + SizeOfRawData)`, we ignore
  them. This is correct for most cases — overlays in legit
  binaries are digital signatures, not code. But packers
  (UPX, Themida) sometimes stash unpacked code there; shrike
  won't find it.
- **No .NET / CLI image handling.** The CLI header
  (DataDirectory[14]) is detected but not parsed; gadgets
  from managed code won't be found.
- **No Authenticode verification.** We don't care who signed
  it; we care what bytes it contains.

### Mach-O
- **32-bit Mach-O (MH_MAGIC)** rejected. 64-bit only for v1.x.
- **Fat binary disagreement tolerated.** If `fat_arch.cputype`
  says `arm64` but the inner `mach_header.cputype` says
  `x86_64`, the inner wins and we trust it. Apple's own tools
  enforce agreement; a divergent fat is malformed.
- **arm64e PAC** gadgets appear as authorisation-heavy
  sequences we don't dispatch. Scanning works, semantics
  don't.

## Chain synthesizer

- **Greedy, not optimal.** If your recipe can be satisfied by
  multiple disjoint gadget sequences with different stack
  costs, we pick the first-observed-smallest-popcount. That's
  usually fine but angrop's full-search approach will beat it
  on edge cases.
- **No stack realignment.** If the chain transition needs the
  stack 16-byte aligned before a call (MOVAPS can fault
  otherwise), you have to hand-insert an alignment gadget.
  Tracked for v3.x.
- **No register-pair aware picking.** An `xchg rax, rdx ; ret`
  gadget could satisfy `rax=X; rdx=Y` if we could reason
  about it. We can't. Issue on radar.

## Output

- **SARIF `level` is always `"note"`.** Some scanners want
  `error` / `warning` discrimination. I think every gadget
  is the same severity (presence, not triaged risk).
  Downstream can remap by category.
- **pwntools output assumes the `ROP` class exists.** If your
  pwntools is too old (pre 4.0), it won't parse. Not planning
  to target older versions.
- **JSON-Lines output can exceed 10 MB** on large libc scans.
  Use `--limit` if your consumer streams poorly.

## Operational

- **mmap-only loader.** No pipe / stdin input. You want to scan
  a memory dump? Write it to a file first.
- **Single-process.** No parallelism. Scanning 400 MB of libc
  takes ~0.8s on a modern CPU; parallelising shaves maybe
  100ms and costs test complexity. v3.x.
- **No incremental / cached scan.** Re-running on the same
  binary re-scans from scratch. For CI pipelines that might
  want caching: compute `--json` once, pipe it forward.

## Development

- **Tested primarily on Linux.** macOS and Windows builds not
  verified. The code should be portable (no OS-specific
  headers outside loader code), but `make install` assumes
  GNU install. Patches welcome.
- **Stability of internal headers.** `<shrike/elf64.h>` and
  friends carry `SHRIKE_DEPRECATED` annotations — they WILL
  be removed one day. If you pin to them, budget for a port.

## Things I explicitly won't fix

- Support for MIPS16e, ARMv5, SPARC, Itanium
- Scanning across multiple shared libraries in a single
  invocation as if they were loaded together (the link-order
  ambiguity alone is too much)
- Windows binary runtime (shrike targets Linux; builds on
  macOS are best-effort)
- .NET CIL gadget finding (wrong level of abstraction)
- Any kind of GUI
