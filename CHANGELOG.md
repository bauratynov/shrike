# Changelog

All notable changes to `shrike` are listed here. Project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-04-18

**First stable release.** API, JSON schema, SARIF shape, and
exit-code contract frozen under [STABILITY.md](STABILITY.md).

Every feature shipped in the 0.x line is carried forward.

### Highlights of what's stable
- x86-64 + AArch64 scanners
- 8-way category classifier
- CET / BTI via `.note.gnu.property`
- Register-control index (text / pwntools / JSON)
- `--recipe` DSL chain composer
- Stack pivot atlas · binary `--diff` · `--raw` blob mode
- Text · JSON-Lines · SARIF 2.1.0 · pwntools Python · CycloneDX
- Canonical semantic dedup
- Ghidra import script
- HTTP gateway
- Docker / deb / rpm packaging
- AFL++ + libFuzzer harness
- Signed release artefacts (minisign)

## 0.x releases

29 tagged minors from v0.10 to v0.33 built the 1.0 surface.

- 0.1-0.9 — scanner foundation, CI, diff, categories, filters,
  arch support, SVG heroes, packaging
- 0.10 — register-control index
- 0.11 — recipe DSL
- 0.12 — pwntools output
- 0.13 — SARIF output
- 0.14 — stack pivot atlas
- 0.15 — canonical semantic dedup
- 0.16 — `--wx-check`
- 0.17 — ROPecker density heatmap
- 0.18 — `--jop` shortcut
- 0.19 — `--cet-posture`
- 0.20 — `--intersect`
- 0.21 — `--raw` headerless blobs
- 0.22 / 0.23 — PE + Mach-O detection hints
- 0.24 — RISC-V detection hint
- 0.25 — Ghidra import script
- 0.26 — CycloneDX enrichment
- 0.27 — HTTP gateway
- 0.28 — packaging (Docker + deb + rpm)
- 0.29 — fuzz harness
- 0.30 — benchmarks
- 0.31 — man page + examples
- 0.32 — release channel + SECURITY.md
- 0.33 — launch kit
