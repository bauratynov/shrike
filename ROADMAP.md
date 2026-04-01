# shrike — 29-sprint product roadmap

From **v0.9.0** (current — ROP gadget finder with diff + categorisation)
to **v1.0.0** (production‑ready security‑tooling product).

Each sprint is one focused increment with:
- **Goal** — user‑visible outcome
- **Scope** — what lands in the commit(s)
- **Research Q** — the question a research agent investigates **before** the
  sprint starts, informing the design

Sprint execution loop:
`research agent → code the sprint → commit + tag + CI → push`.

---

## Stage I — Exploit-dev depth (sprints 10–15)

Make `shrike` a first-class participant in real ROP / JOP workflows.

### v0.10.0 — register-control index
- **Goal**: `--reg-index` prints a table of "which register can I pop,
  at which addresses?" The single most-asked question in early
  exploit-dev.
- **Research Q**: How does pwntools' `ROP` class build its
  register-control map? What register-aliasing tricks (e.g. `mov eax, edi`)
  are worth indexing in v1?

### v0.11.0 — recipe DSL, single-line chain composer
- **Goal**: `shrike --recipe 'rdi=*; rax=59; syscall'` emits the
  smallest gadget chain that realises the recipe.
- **Research Q**: What's the complexity of gadget-chain synthesis?
  Survey ROPgadget's `--ropchain`, angr's `rop` library, and
  AutoROP for state-of-the-art approaches.

### v0.12.0 — pwntools-compatible output
- **Goal**: `--format pwntools` prints a Python snippet that
  imports the gadget addresses and builds a payload. Composability
  with the de-facto exploit-dev framework.
- **Research Q**: What does pwntools' `ROP` API currently accept?
  Can we emit a self-sufficient Python file, or is it tighter to
  emit just the address constants?

### v0.13.0 — SARIF output for CI
- **Goal**: `--format sarif` emits a SARIF 2.1.0 report —
  ingestible by GitHub Code Scanning, GitLab SAST, Azure DevOps.
  Turns shrike into a first-class DevSecOps citizen.
- **Research Q**: Which SARIF rules / result types fit gadget
  findings? Look at Semgrep and Bandit SARIF conventions.

### v0.14.0 — stack pivot atlas
- **Goal**: `--pivots` dedicated report listing every
  `add rsp / mov rsp / xchg rsp` form with the delta it applies.
  Stack pivots are the ROP equivalent of a calling convention.
- **Research Q**: What stack-pivot idioms does BHDC's
  `rp++` enumerate? Is there an ARM64 analogue worth first-classing?

### v0.15.0 — semantic dedup (`--canonical`)
- **Goal**: Collapse gadgets that are semantically equivalent
  (e.g. `pop rdi ; ret` and `pop rdi ; retn 0` end up in one row)
  behind a `--canonical` flag. Keeps audits tractable.
- **Research Q**: How does Ropper handle "semantic" vs "syntactic"
  dedup? Is there a normalisation step we can adopt?

## Stage II — Analysis primitives (sprints 16–20)

### v0.16.0 — W^X violation scanner
- **Goal**: Detect binaries with `PT_LOAD` regions that are writable
  **and** executable (the canonical "JIT without W^X" smell).
  Companion to checkhard's segment audit.
- **Research Q**: What are the most common legitimate W+X cases in
  the wild (Go binaries, JITs)? Document the false-positive surface.

### v0.17.0 — ROPecker-style chain heuristic
- **Goal**: Mark gadget cluster regions where the density of
  terminators exceeds the ROPecker threshold. Useful for triage.
- **Research Q**: What were the original ROPecker thresholds
  (paper: NDSS 2014), and how do modern PIE binaries alter them?

### v0.18.0 — JOP / COP atlas (`--jop-map`)
- **Goal**: Indirect-call / indirect-jmp gadgets indexed by the
  register they dispatch through. `jmp rax` vs `jmp [rbx+0x18]`
  matter differently for attackers.
- **Research Q**: What are the practical JOP primitives in recent
  Linux kernel exploits? Survey Project Zero write-ups from 2022–2025.

### v0.19.0 — control-flow integrity status
- **Goal**: For each binary, report whether CET IBT is enabled
  (via `.note.gnu.property`), CET SHSTK claim, BTI property on
  aarch64. Unified "CFI posture" line.
- **Research Q**: What's the exact `NT_GNU_PROPERTY` layout for
  `GNU_PROPERTY_X86_FEATURE_1_AND` and its aarch64 analogue?

### v0.20.0 — cross-input gadget graph
- **Goal**: With multiple inputs, build a graph of "gadget X in A
  chains to gadget Y in B". Early groundwork for exploit chain
  synthesis.
- **Research Q**: What data structure does BARF use for its
  reachability queries? Can we keep it heap-free?

## Stage III — Platform breadth (sprints 21–24)

### v0.21.0 — PE/COFF support (Windows binaries)
- **Goal**: Scan `.exe`, `.dll`, `.sys` — same categoriser,
  same CET classifier, new loader.
- **Research Q**: What are the PE section attributes for
  IMAGE_SCN_MEM_EXECUTE, and where does the IAT live relative to
  gadget density?

### v0.22.0 — Mach-O support (macOS / iOS binaries)
- **Goal**: Scan Mach-O 64-bit binaries including fat (universal).
- **Research Q**: How does the Mach-O load-command sequence
  identify `__TEXT,__text`? What's the arm64e PAC signing impact?

### v0.23.0 — RISC-V RV64GC scanner
- **Goal**: Third ISA. Fixed 32-bit + 16-bit compressed
  instructions; terminator is `jalr x0, x1, 0` (ret) and `ecall`.
- **Research Q**: How does the C extension interact with gadget
  density? Are there standard register-control idioms?

### v0.24.0 — raw binary blob mode
- **Goal**: `--raw --arch x86_64 --base 0x...` — scan a headerless
  blob (firmware, shellcode, ROMs).
- **Research Q**: What's the standard firmware-header format survey
  (U-Boot, UEFI section offsets) worth supporting first?

## Stage IV — Ecosystem integrations (sprints 25–28)

### v0.25.0 — Ghidra plugin (`.java` companion)
- **Goal**: Import shrike's JSON output into Ghidra, annotate
  addresses with category tags.
- **Research Q**: What's the stable Ghidra plugin API for address
  annotations in 11.x?

### v0.26.0 — CycloneDX SBOM enrichment
- **Goal**: `--sbom-enrich sbom.json` adds a `hardening`
  custom-property to each component based on a checkhard sibling
  call. First concrete checkhard/shrike product bundle.
- **Research Q**: What's the v1.6 CycloneDX schema expectation for
  security-property custom fields?

### v0.27.0 — Web API / HTTP server mode
- **Goal**: `shrike serve :8080` exposes a small REST surface:
  `POST /scan` (multipart upload → JSON report).
- **Research Q**: What existing security tools ship HTTP mode
  (e.g. `rizin` debugger, `semgrep` LSP) and what patterns work?

### v0.28.0 — Packaging (deb, rpm, Homebrew)
- **Goal**: `apt install shrike` / `brew install shrike`. Tarball
  releases signed with minisign. Reproducible builds.
- **Research Q**: What's the minimum debian/control + fpm recipe
  for a single-binary tool with a man page?

## Stage V — Release readiness (sprints 29–34)

Six final polish sprints take shrike from "useful" to "shippable 1.0".

### v0.29.0 — fuzz infrastructure
- **Goal**: `honggfuzz` + `AFL++` wrappers for xdec and scan. Seed
  corpus of real binaries.
- **Research Q**: OSS-Fuzz onboarding template for C99 projects —
  current 2026 state.

### v0.30.0 — performance benchmarks + baseline
- **Goal**: `bench/` directory with criterion-style repeatable
  throughput on /bin/bash, libc, libcrypto. Regression alarms.
- **Research Q**: Standard benchmark suite that other ROP tools
  publish against; where we land relative to ROPgadget and rp++.

### v0.31.0 — docs + man page + examples directory
- **Goal**: `man 1 shrike`, `examples/` with 10 real recipes,
  `docs/architecture.md`.
- **Research Q**: What comparable projects have docs that make
  first-time users productive within five minutes?

### v0.32.0 — release channel + signature + changelog website
- **Goal**: GitHub releases with minisign signatures, release
  notes templated from CHANGELOG, small docs site (Docusaurus or
  mkdocs-material).
- **Research Q**: Lightweight static docs stack that survives
  `git clone + make docs` without Node dep explosion.

### v0.33.0 — product hunt / hn launch kit
- **Goal**: Launch materials (one-pager, demo GIF, hero
  screenshot, FAQ). Target a coordinated HN/Reddit/Twitter push.
- **Research Q**: What patterns work for a v1 security-tool launch
  in 2026 — case studies of successful OSS launches (semgrep,
  trivy, gitleaks).

### v1.0.0 — API freeze + stability commitment
- **Goal**: Declare stable: CLI flags, JSON schema, exit codes,
  C API in headers. Start 1.x deprecation policy.
- **Research Q**: SemVer-discipline patterns of projects that
  successfully maintained 1.x for 3+ years without breakage
  (clang, jq, ripgrep).

---

## Execution protocol

For each sprint N → N+1:
1. **Research agent** investigates the Research Q for sprint N+1.
2. Findings guide sprint scope + design choices.
3. Implementation → commit → tag → CI green → push.
4. CHANGELOG entry, README roadmap tick.
5. Advance to next sprint.

Total: **29 sprints** from v0.10 to v1.0.0.

Estimated calendar time at one focused-day per sprint:
**~6–8 weeks wall clock** for a single senior engineer.
