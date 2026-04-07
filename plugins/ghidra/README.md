# shrike → Ghidra import

`shrike_import.py` takes the JSON-Lines produced by
`shrike --json <binary>` and annotates each gadget's address in a
Ghidra program with:

- an EOL comment containing the mnemonic
- a `SHRIKE` bookmark tagged by gadget category

## Workflow

```bash
shrike --json /bin/ls > ls.jsonl
# Open /bin/ls in Ghidra, then:
#   Window → Script Manager → run shrike_import.py
#   pick ls.jsonl when prompted
```

## Requirements

- Ghidra 10.x or 11.x (Jython 2.7) or Ghidra 11.1+ with Ghidrathon
  (Python 3). No CPython runtime needed for the default Jython path.

## Scope

Deliberately tiny (one file, ~60 LOC). A full plugin with menus and
decompiler integration is a separate track; this script is the
minimum that lets reverse engineers consume shrike's output
natively.
