#!/usr/bin/env python3
"""
Check that a patched exe survives being rebased the way Windows loads it.

Wine loads DXHRDC.exe at its preferred base and applies no relocations, so a patch
that writes over a live fixup works there and breaks on Windows. This applies every
live HIGHLOW fixup to both the stock and the patched exe with the same slide, then
requires that rebasing and patching commute: every patched byte outside .reloc must
come through the rebase unchanged, and every unpatched byte must match the rebased
stock exe.

    python3 tools/rebase_check.py STOCK.exe PATCHED.exe [--delta 0xD50000 ...]

Exit status 0 when every slide checks out, 1 otherwise. Stdlib only.
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from patch_simultaneous_input import (  # noqa: E402
    IMAGE_REL_BASED_HIGHLOW, base_relocs, make_maps, pe_sections)


def rebase(data, delta):
    """Apply every live HIGHLOW fixup with the given slide, as the Windows loader does."""
    out = bytearray(data)
    base, va2off, _, _ = make_maps(data)
    for rva, typ, _ in base_relocs(data):
        if typ != IMAGE_REL_BASED_HIGHLOW:
            continue
        off = va2off(base + rva)
        if off is None:
            continue
        v = struct.unpack_from("<I", out, off)[0]
        struct.pack_into("<I", out, off, (v + delta) & 0xFFFFFFFF)
    return out


def reloc_span(data):
    _, secs = pe_sections(data)
    for name, _, _, raddr, rsize in secs:
        if name == ".reloc":
            return raddr, raddr + rsize
    return 0, 0


def check(stock, patched, delta):
    rs, rp = rebase(stock, delta), rebase(patched, delta)
    lo, hi = reloc_span(patched)
    bad = []
    for i in range(len(patched)):
        if lo <= i < hi:
            continue                     # the table itself is allowed to differ
        if patched[i] != stock[i]:
            if rp[i] != patched[i]:      # a fixup landed on our bytes
                bad.append(i)
        elif rp[i] != rs[i]:             # rebasing diverged where we changed nothing
            bad.append(i)
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("stock")
    ap.add_argument("patched")
    ap.add_argument("--delta", action="append", type=lambda s: int(s, 0),
                    help="slide(s) to test; default covers a few 64 KB-aligned values")
    args = ap.parse_args()

    stock = open(args.stock, "rb").read()
    patched = open(args.patched, "rb").read()
    if len(stock) != len(patched):
        print("ERROR: files differ in size", file=sys.stderr)
        return 2

    ok = True
    for delta in args.delta or [0x10000, 0xD50000, 0x3FF0000, 0x5A20000]:
        bad = check(stock, patched, delta)
        if bad:
            ok = False
            spans = ", ".join("0x%06X" % b for b in bad[:8])
            print("slide +0x%07X: FAIL, %d byte(s) corrupted at file offset %s%s"
                  % (delta, len(bad), spans, " ..." if len(bad) > 8 else ""))
        else:
            print("slide +0x%07X: ok" % delta)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
