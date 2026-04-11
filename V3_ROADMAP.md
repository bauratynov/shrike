# shrike 3.0 — 29-sprint roadmap

**From v2.0.0 (stable C API, native loaders, chain synthesis,
Python binding) → v3.0.0 (semantic analysis, new architectures,
dynamic discovery, exploit synthesis, formal verification).**

v2 builds the library. v3 turns shrike into an analysis platform:
not just "here is the list of gadgets" but "here is the chain
that will work on this binary, proved correct, for five
architectures, with your bug class detected automatically."

Sprint discipline is the same as 0.10 → 1.0 → 2.0:
`research agent → design → code → commit → tag → CI green → push`.

---

## Stage VII — Semantic depth (v2.1.x, 5 sprints)

Replace string-based gadget descriptions with a typed effect IR
and a tiny symbolic execution backend. Stop pretending gadget
analysis is grep; start treating it as program analysis.

### v2.1.0 — gadget effect IR
- **Goal:** typed per-instruction effect record
  `{reads: regset, writes: regset, stack_delta: int, mem_reads,
  mem_writes}` lives alongside the existing decoded form.
- **Research Q:** angr's VEX IR / BAP's BIL / Ghidra's P-code —
  which has the cheapest minimum viable slice for ROP-era
  effects only?

### v2.1.1 — symbolic execution backend (tiny)
- **Goal:** bit-vector symbolic state over the IR; concrete
  starting state + symbolic stack; fixpoint over a gadget's
  instruction sequence to produce a postcondition.
- **Research Q:** how simple can this be and still catch the
  patterns angrop relies on? Target: ≤ 500 LOC of bitvec logic.

### v2.1.2 — JOP (jump-oriented) enumeration
- **Goal:** the v0.18 `--jop` shortcut is just a filter over ret
  gadgets. Upgrade to first-class JOP: indirect `jmp reg` /
  `jmp [reg+disp]` terminators, gadget classifier that prefers
  dispatcher-call-gadget shapes.
- **Research Q:** the Bletsch et al. JOP paper — minimum
  dispatcher shape on x86-64 and aarch64.

### v2.1.3 — COP (call-oriented) enumeration
- **Goal:** indirect `call reg` terminators + classifier;
  separate output from ROP/JOP; works with the same recipe DSL.
- **Research Q:** CCFIR / ROPguard — how do defenses
  distinguish COP from legitimate indirect calls?

### v2.1.4 — data-oriented (DOP) gadget finder
- **Goal:** find "data-only" gadget sequences that achieve
  arbitrary read / arbitrary write without altering control
  flow — for post-CFI exploit research.
- **Research Q:** Hu et al. DOP — what's the minimum effect
  shape to declare a sequence "DOP-useful"?

## Stage VIII — New architectures (v2.2.x, 4 sprints)

Shrike at v2 does x86-64 + AArch64 + RISC-V native. v3 picks up
the long tail so "scan this firmware" stops being an ELF-on-x86
assumption.

### v2.2.0 — Windows PE + PDB symbol enrichment
- **Goal:** parse companion .pdb; annotate gadgets with the
  symbol name of the containing function. Output shape:
  `0x401234  kernel32!GetProcAddress+0x12  pop rbp ; ret`.
- **Research Q:** minimum PDB MSF parsing depth; public symbol
  stream only, no type info.

### v2.2.1 — Mach-O 32-bit + arm64e PAC + Obj-C selectors
- **Goal:** extend v1.3 Mach-O loader to 32-bit; strip PAC bits
  on arm64e addresses; annotate gadgets that appear inside
  Objective-C selectors with class/method names.
- **Research Q:** arm64e PAC bit layout at rest vs runtime;
  `__objc_classlist` + `__objc_methname` cross-reference.

### v2.2.2 — PowerPC 64 scanner
- **Goal:** fixed-32-bit decoder; `blr` + `bctr` terminator
  recognition; register-control over `r3..r10` (syscall ABI).
- **Research Q:** PPC64 ELFv2 ABI calling convention; how
  epilogues look under modern gcc.

### v2.2.3 — MIPS32 / MIPS64 scanner
- **Goal:** fixed-32-bit decoder; `jr $ra`, `jalr`, `syscall`
  terminators; delay-slot awareness (the gotcha that makes
  MIPS gadget finding harder than it looks).
- **Research Q:** how do existing MIPS ROP tools handle the
  branch-delay slot? Do they fold it into the gadget or emit
  separately?

## Stage IX — Dynamic discovery (v2.3.x, 3 sprints)

Static scanning lists every *potential* gadget. Dynamic
discovery lists the ones that *actually get reached*. Pairs
shrike with `lbr-hunt` and friends.

### v2.3.0 — LBR runtime logger integration
- **Goal:** `shrike --lbr-trace file.csv foo` cross-references
  LBR branch records from `lbr-hunt` with scanned gadgets;
  outputs "reached" vs "unreached" classification.
- **Research Q:** Intel LBR TOS semantics, MSR_LASTBRANCH_*
  field layout under perf_event_open.

### v2.3.1 — perf-guided coverage
- **Goal:** run the target under `perf record --call-graph=lbr`;
  parse `perf.data`; annotate gadgets with sample count.
- **Research Q:** `perf.data` format (callchain entries);
  cheapest way to parse without linking libperf.

### v2.3.2 — ptrace-based gadget-use detector
- **Goal:** `shrike --live PID` attaches ptrace, single-steps
  the process, and logs when RIP/PC lands inside a known
  gadget. Useful for watching ROP chains fire in a live
  exploit attempt.
- **Research Q:** ptrace overhead on single-step; is this fast
  enough to watch a 10k-gadget chain without the target
  noticing, or does it need PTRACE_O_TRACESYSGOOD tricks?

## Stage X — Ecosystem integration (v2.4.x, 4 sprints)

### v2.4.0 — CodeQL query library
- **Goal:** `queries/shrike/` ships CodeQL queries that flag
  gadget-rich code patterns at source time. GitHub Code
  Scanning consumes them same as the existing SARIF output.

### v2.4.1 — Binary Ninja plugin
- **Goal:** drop-in plugin that reads shrike's JSON-Lines and
  renders gadgets in the Binja UI; reverse link — Binja
  selection filters shrike output.
- **Research Q:** Binja Python Plugin API surface for "load
  custom annotations by address."

### v2.4.2 — IDA Pro plugin
- **Goal:** same idea, IDA-side. `.py` plugin, uses IDA's
  `idc.set_cmt` for inline annotations.

### v2.4.3 — GDB / LLDB pretty-printers + commands
- **Goal:** `(gdb) shrike scan` command runs the scanner on
  the current inferior's mapped regions, emits gadgets as
  convenient `$shrike_N` GDB convenience variables.
- **Research Q:** Python GDB API: how to iterate
  `info proc mappings` programmatically.

## Stage XI — Exploit synthesis (v2.5.x, 4 sprints)

v2.0's chain synthesizer can compose a `rdi=*; rsi=*; rdx=*;
rax=59; syscall` recipe. v3 goes further: bug class in, full
exploit out.

### v2.5.0 — shellcode primitive library
- **Goal:** reusable recipe templates for common primitives
  (execve, connect-back, mprotect+shellcode, open+read+write).
  Each primitive is a `recipe.d/*.shrike` file.

### v2.5.1 — automated exploit skeleton generator
- **Goal:** `shrike --exploit-skel` takes a bug class
  (buffer_overflow, format_string, double_free) + a target
  binary, synthesizes a pwntools harness that uses the chain
  composer.

### v2.5.2 — exploit reliability heuristics
- **Goal:** score chains by ASLR-survivability (how many bytes
  differ across runs), stack-alignment requirement, bad-byte
  avoidance. Rank competing chains by reliability.

### v2.5.3 — binary patching output
- **Goal:** `shrike --patch-in-place` applies a chain directly
  to a binary (hot-patch a read-only segment with mprotect
  trampolines for CTF author use, not defense).

## Stage XII — Formal verification (v2.6.x, 3 sprints)

### v2.6.0 — SMT proof of chain correctness
- **Goal:** given a recipe and a selected chain, emit an SMT2
  file that proves (no-clobber: requested registers have the
  requested values after execution; stack-balance: ESP/SP is
  where we said it would be; effect-minimality: no writes to
  memory outside declared primitives). Run via `z3`.
- **Research Q:** Z3 bindings vs shelling out to `z3 -smt2`;
  the latter keeps shrike dependency-free.

### v2.6.1 — SMT-guided gadget picker
- **Goal:** when the greedy synthesizer picks a bad gadget,
  feed the constraint to Z3 and get a better one. Fall back
  to greedy when Z3 is unavailable.

### v2.6.2 — machine-checkable exploit claims
- **Goal:** export a chain + its correctness proof in a
  Coq-compatible format so third-party reviewers can verify
  without trusting shrike.
- **Research Q:** smallest viable Coq export dialect; what do
  bedrock / CompCert use for their binary-level claims?

## Stage XIII — Polish & ship (v2.7 → v3.0, 6 sprints)

### v2.7.0 — SIMD-accelerated scanner
- **Goal:** AVX2 terminator search; 4-8× speedup on the
  outer byte-scan loop for x86-64. No ISA fallback — detect
  at runtime, fall back to the C99 scanner.

### v2.7.1 — parallelism
- **Goal:** worker pool across input binaries and across
  segments of a single binary; linear scaling up to NPROC.

### v2.8.0 — comprehensive benchmark
- **Goal:** `bench/cross-tool/` runs shrike, ropr, ROPgadget,
  rp++, angrop against a shared corpus; publishes a
  CSV + markdown report. Goal: be the fastest OR the most
  semantically accurate, not both.

### v2.9.0 — shrike-book
- **Goal:** long-form guide in `docs/book/`. Topics: ROP
  background, gadget taxonomy, chain composition, hardening
  audit playbook, custom recipe authoring. Target: ~80 pages.

### v2.9.1 — SemVer audit + deprecation warnings
- **Goal:** every v2 flag or API being removed or renamed in
  3.0 emits a stderr deprecation warning when invoked in 2.9.

### v2.9.2 — migration guide
- **Goal:** `docs/migration-2-to-3.md` enumerates every
  breaking change. Mirrors what `docs/migration-1-to-2.md`
  did for the v1 → v2 cutover.

### v3.0.0 — release
- **Goal:** CLI, C API, Python API, SARIF, JSON-Lines all
  frozen at 3.x per an updated STABILITY.md. Book promoted
  to README. Benchmark baseline frozen.

---

## Execution protocol (same as prior runs)

For each sprint `N → N+1`:

1. **Research agent** investigates the Research Q for sprint
   N+1 before design.
2. Findings guide sprint scope + design choices.
3. Implementation → commit → tag → CI green → push.
4. CHANGELOG entry, README + roadmap tick.

Total v2.1.0 → v3.0.0: **29 sprints**. Combined with the 24
sprints of V2_ROADMAP, shrike ships **53 sprints** of planned
work from v1.1.0 to v3.0.0.

---

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Symbolic exec sprawl | high | cap at bit-vector semantics; defer memory models to v4 |
| Platform loaders fragile on real firmware | high | `--strict` vs `--lenient` flags; document the happy path |
| CodeQL / Binja / IDA plugins bit-rot against upstream API changes | medium | CI job loads each host and runs the plugin smoke test |
| SMT integration pulls in heavy dep | medium | shell out to `z3` binary; don't link libz3 |
| v3 scope creep past 29 sprints | high | publish a "frozen at v3.0" contract; new features wait for v3.x |
| Downstream confused by v1/v2/v3 APIs coexisting | low | generous deprecation windows; `--legacy` compatibility flags retained |
