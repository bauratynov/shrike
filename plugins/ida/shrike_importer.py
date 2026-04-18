"""
IDA Pro plugin: shrike ROP gadget importer.

Install by dropping this file in `$IDAUSR/plugins/`. Run via
Edit -> Plugins -> shrike importer. Prompts for a JSON-Lines
file produced by `shrike --json <binary>` and annotates each
gadget address with its disassembly as an inline comment.

For IDA 7.5+. Uses idaapi / ida_idaapi / idc primitives only —
no IDAPython SIP dependency, no newer type hints.
"""

import json
import idaapi
import idc
import ida_kernwin


def import_json(path):
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
            insns = g.get("insns", [])
            tag = "shrike:" + (g.get("category") or "gadget")
            comment = "{} {}".format(tag, " ; ".join(insns) if insns else "")
            idc.set_cmt(addr, comment, 0)
            annotated += 1
    return annotated


class ShrikeImporter(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Import shrike JSON-Lines output as IDA comments"
    help = "shrike importer: annotates gadget addresses"
    wanted_name = "shrike importer"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def term(self):
        pass

    def run(self, arg):
        path = ida_kernwin.ask_file(False, "*.jsonl",
                                    "Select shrike --json output")
        if not path: return
        n = import_json(path)
        idaapi.msg("shrike: annotated {} gadget(s)\n".format(n))


def PLUGIN_ENTRY():
    return ShrikeImporter()
