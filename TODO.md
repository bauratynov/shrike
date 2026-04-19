# TODO

Rough, dated notes. Not a roadmap — see V*_ROADMAP.md for
planned work. This is "things I want to fix but haven't" and
"ideas that aren't thought-through yet".

## Bugs / nits

- [ ] `--quiet` prints the summary with `shrike: 1 inputs`
      even for single-binary mode. Should say `1 input`.
      Tracked 2026-03-24.
- [ ] `regex_t` on musl 1.2.3 reports a different error code
      for `[[:digit:]]` than glibc. Error message in main.c
      is glibc-worded. Minor annoyance; add a regcomp wrapper.
- [ ] cppcheck complains about `strtoull` in recipe.c when the
      second arg is `NULL` — it can be for untrusted inputs
      but only after we've already validated. Cast suppresses
      it. Ugly.
- [ ] Canonical dedup strips `endbr64` before hashing. Should
      probably keep it because two gadgets that differ only by
      endbr presence are meaningfully different for CET-aware
      exploits. Added 2026-04-03, not fixed.

## Performance

- [ ] `scan_x86` walks every byte position then tries to
      decode. Could SIMD-prefilter for terminator bytes
      (0xC3, 0xC2, 0x0F05, 0xCD) and only full-decode at
      hits. ~5-8x speedup estimated. Blocked on having a
      real benchmark corpus I trust.
- [ ] `format_gadget_render` runs the full decoder twice on
      canonical-dedup paths (once for key, once for final
      output). Cache the first render.
- [ ] `strset_t` resizes by 2x — wastes space. Not a priority
      on current workload (peak ~1MB set).

## Decoder

- [ ] VEX C4 / C5 prefix handling in xdec. Needed for AVX-512
      rendering. Big change, prefix byte acrobatics. Will
      probably spawn a `xdec_vex.c` rather than growing the
      main table.
- [ ] aarch64 LDR / STR immediate (not pair) forms. Common in
      prologues, currently falls through to `.word`. Should
      be 30 lines. 2026-04-02 TODO.
- [ ] RISC-V M/A/F/D extension rendering. Length decoder
      already handles them; just need the mnemonic tables.
- [ ] x86 0x66-prefix word-sized POP/PUSH forms. `push ax`
      etc. Rare but they exist in CTF binaries.

## Loader

- [ ] PE PE32 (32-bit Windows) support. DataDirectory layout
      differs from PE32+. Maybe 1-2 days. Blocker: I don't
      have a PE32 test corpus.
- [ ] Mach-O arm64e PAC bit stripping on addresses before
      reporting. Currently gadgets in PAC'd .dylibs have
      addresses with high bits set → looks wrong.
- [ ] ELF32 loader. No plans; not on any roadmap. Mentioned
      only because people ask.
- [ ] ppc64be (AIX, old Linux). One XOR away; not shipping
      until someone asks with a real binary.

## Chain synthesizer

- [ ] Stack alignment tracking. A chain that calls a
      MOVAPS-using function can fault on misaligned stack.
      Shrike picks gadgets blind to this.
- [ ] `xchg` / `mov dst, src` as register-transfer primitives.
      Currently we only credit pop-ret. Some binaries have
      almost no pops but tons of MOVs; we're useless there.
- [ ] Consider subset-match across multi-pop gadgets: if
      needed = {rdi, rsi, rdx} and gadget A covers {rdi, rsi}
      while gadget B covers {rdx, r15}, compose A+B with
      padding. Currently we fail to match. Non-trivial.
- [ ] Pass a `target_os` hint to the recipe to auto-pick
      syscall numbers (execve = 59 on Linux x86_64,
      221 on aarch64 / RV64). Currently the recipe hardcodes.

## Output

- [ ] SARIF: include `properties.shrike.bytes` for each
      result. Some SARIF consumers support it. Non-standard
      but harmless.
- [ ] pwntools emitter: emit a comment with the exact
      byte sequence alongside each gadget address. Makes
      debugging chain breakage easier.
- [ ] JSON-Lines: `reached` boolean when `--reached-file` is
      set, instead of filtering. Annotation is more useful
      than filter for dev workflows.

## Tooling

- [ ] `tools/shrike-diff-report.py` — nicer HTML output for
      `--diff` between two libc versions.
- [ ] GDB plugin: auto-identify ROP-pivotable regions in
      inferior's memory map. `info rop` or similar.
- [ ] Ghidra script: reverse direction — select an address
      range in Ghidra, shell out to shrike, annotate back.

## Meta

- [ ] Write a proper "getting started" tutorial in
      `docs/book/`. Currently README is fine for experienced
      users but new-to-ROP folks need more hand-holding.
- [ ] Packaging: Homebrew tap, Arch AUR PKGBUILD, Nix flake.
      Low effort per target, high marginal value.
- [ ] Black Hat Arsenal submission. CFP opens around May for
      USA, July for EU. Prepare the 3-min pitch deck.
- [ ] Record a 5-min demo screencast for the README. People
      trust video more than READMEs these days.

## Ideas I'm not sure about

- A GitHub Action that runs shrike on every PR to your binary
  build and posts the gadget count delta as a bot comment.
  Would be neat for hardening-conscious projects.
- Clustering similar gadgets via n-gram hashing to surface
  "structural near-duplicates" that escape canonical dedup.
  No clear use case yet — just shiny.
- Integration with emulators (qemu-user snapshots) to verify
  that a chain actually achieves what it claims when run.
  Crosses into exploitation, may not want to ship that.
