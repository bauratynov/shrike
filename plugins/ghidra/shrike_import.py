# shrike_import.py — Ghidra / Ghidrathon companion script.
#
# Reads JSON-Lines produced by `shrike --json <binary>` and annotates
# each gadget address in the current Ghidra program with a
# repeatable comment and a "SHRIKE" bookmark categorised by
# gadget class (pop / mov / arith / syscall / indirect).
#
# Usage:
#   1. In Ghidra: Window → Script Manager → run this file
#      (enable the Ghidra Python interpreter or Ghidrathon for 3.x).
#   2. The script prompts for a .jsonl file; select the output of
#      `shrike --json target.elf > gadgets.jsonl`.
#
# Apache-compatible. No Ghidra plugin registration needed — it is a
# standalone script, so the contract is stable across Ghidra 10-11.x.

#@category shrike
#@menupath shrike.Import Gadgets from JSON

import json

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import CodeUnit


CATEGORY_BOOKMARK_TYPE = "SHRIKE"


def _tag_addr(script, addr_hex, info):
    addr = script.getAddressFactory().getAddress(addr_hex)
    if addr is None:
        return

    category = info.get("category", "other")
    insns    = info.get("insns", [])
    note     = "; ".join(insns)

    cu = script.getCurrentProgram().getListing().getCodeUnitAt(addr)
    if cu is not None:
        cu.setComment(CodeUnit.EOL_COMMENT, "shrike: " + note)

    script.createBookmark(addr, CATEGORY_BOOKMARK_TYPE, category)


def run(script):
    path = script.askFile("shrike JSON-Lines", "Open")
    if path is None:
        return

    count = 0
    with open(str(path), "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            addr = obj.get("addr")
            if not addr:
                continue
            _tag_addr(script, addr, obj)
            count += 1

    script.println("shrike: imported %d gadgets" % count)


# Ghidra script boilerplate — `currentProgram` / `askFile` injected by runtime
run(getScriptContext().getScript() if False else __import__('__main__').getScriptContext())
