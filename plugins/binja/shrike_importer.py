"""
Binary Ninja plugin: shrike ROP gadget importer.

Install by symlinking or copying this directory into
`~/.binaryninja/plugins/shrike/`. The plugin adds a
"Shrike — Import gadgets" action to the Tools menu; picking it
prompts for a shrike `--json` output file and annotates each
gadget's address with its disassembly as a bookmark + comment.

Binary Ninja 3.0+. Pure-Python, no native API assumptions.
"""

import json
import binaryninja as bn
from binaryninja.interaction import get_open_filename_input
from binaryninja import PluginCommand


def _import(bv):
    path = get_open_filename_input("Select shrike --json output",
                                    "JSON Lines (*.jsonl *.json)")
    if not path:
        return
    annotated = 0
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                g = json.loads(line)
            except ValueError:
                continue
            addr_s = g.get("addr")
            if not addr_s: continue
            try:
                addr = int(addr_s, 16)
            except ValueError: continue
            tag = "shrike:" + (g.get("category") or "gadget")
            insns = g.get("insns", [])
            comment = "{} {}".format(tag, " ; ".join(insns))
            bv.set_comment_at(addr, comment)
            bv.add_tag(addr, "shrike", tag)
            annotated += 1
    bn.log_info("shrike: annotated {} gadget(s)".format(annotated))


PluginCommand.register(
    "Shrike\\Import gadgets (JSON-Lines)",
    "Annotate every shrike gadget address with its disassembly",
    _import,
)
