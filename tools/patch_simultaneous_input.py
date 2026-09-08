#!/usr/bin/env python3
"""
DXHR / DXHR:DC  --  "simultaneous keyboard+mouse and gamepad input" patch.

Vanilla behaviour
-----------------
The engine keeps a single global byte  g_usingMouseKeyboard  (0x00B23E54 in the
Director's Cut Steam/GOG build).  An arbitration function (FUN_004B0360) sets it
to 1 when the mouse/keyboard reports activity and to 0 when an XInput pad does.

Both input producers *gate their entire state-filling code* on that byte:

  cdc::PCMouseKeyboard::update   (0x004B10B0)
      cmp byte [g_usingMouseKeyboard], 0
      je   skip            ; <- pad active: mouse/keyboard contributes nothing

  cdc::PCXInputProducer::update  (0x004B3490)
      cmp byte [g_usingMouseKeyboard], 0
      jne  activity_only   ; <- kbm active: pad contributes nothing

  cdc::PCXInputProducer::setVibration (0x004B3320)
      cmp byte [g_usingMouseKeyboard], 0
      je   compute         ; <- kbm active: motor speeds forced to 0

cdc::InputSystem::CombineInputs sums the states of all registered producers, and
the two producers write to disjoint slots of the shared InputState, so removing
those gates makes buttons, movement and axes from both devices arrive in the same
frame.

Looking
-------
The look/aim update (FUN_007AC8C0) branches on the same byte, and its two arms
read different values: the mouse arm applies the raw mouse delta, the gamepad arm
runs stick acceleration and aim assist.

  FUN_007AC8C0 (0x007AD162)
      cmp byte [g_usingMouseKeyboard], 0
      je   gamepad_aim_path   ; <- mouse delta is not read at all

The two arms cannot both run, so looking has to pick one source per frame, and
that pick has to be correct rather than forced.  The arbitrated byte is not
reliable evidence: it comes from coarse latch-based activity detectors and does
not track the mouse while a pad is also in use.  The mouse delta itself is.

The `looksrc` site replaces the `cmp` with a call to an injected thunk that reads
the combined mouse delta for the frame:

    g_inputSystems[0]->currentState->{deltaX,deltaY} != 0  ?  mouse arm
                                                          :  gamepad arm

Only cdc::PCMouseKeyboard writes those two floats, so this is an unambiguous
"did the mouse move this frame" test.  The thunk returns with ZF set so the
original `je` after the call still does the branching, and it clobbers nothing
but flags.  It is position-independent (call/pop to get EIP, then an EIP-relative
displacement), so it needs no new base relocation and survives ASLR.

Sites
-----
  kbm       NOP the `je`  in PCMouseKeyboard::update   -> mouse/kb always polled
  pad       NOP the `jne` in PCXInputProducer::update  -> pad always polled
  looksrc   look/aim picks its arm from the real mouse delta, per frame
  rumble    `je` -> `jmp` in setVibration              -> rumble always works

Optional, off by default:
  mousethresh  mouse activity threshold  5     -> 0
  padthresh    pad thumbstick idle window 0x3FFF -> 0x1FFF
     Both only widen the coarse detectors feeding g_usingMouseKeyboard.  They do
     not fix looking, and leaving them off keeps button prompts and aim-assist
     gating at their shipped behaviour.

  look         NOP the `je` in FUN_007AC8C0 -> aiming ALWAYS uses the mouse arm
     (--force-mouse-look).  Guarantees mouse aiming at the cost of right-stick
     look, stick acceleration and aim assist.  Kept as a fallback for `looksrc`.
"""

import argparse
import hashlib
import os
import re
import shutil
import struct
import sys


# --------------------------------------------------------------------------- #
# minimal PE helpers (no dependencies)
# --------------------------------------------------------------------------- #
def pe_sections(data):
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("not a PE file")
    num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    base = struct.unpack_from("<I", data, pe_off + 24 + 28)[0]
    sec_off = pe_off + 24 + opt_size
    secs = []
    for i in range(num_sec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
        secs.append((name, base + vaddr, max(vsize, rsize), raddr, rsize))
    return base, secs


def make_maps(data):
    base, secs = pe_sections(data)

    def va2off(va):
        for name, vaddr, vsize, raddr, rsize in secs:
            if vaddr <= va < vaddr + vsize and (va - vaddr) < rsize:
                return raddr + (va - vaddr)
        return None

    def off2va(off):
        for name, vaddr, vsize, raddr, rsize in secs:
            if raddr <= off < raddr + rsize:
                return vaddr + (off - raddr)
        return None

    text = next(s for s in secs if s[0] == ".text")
    return base, va2off, off2va, text


def find_one(data, pattern, what, start=0, end=None):
    """pattern is a regex over bytes; require exactly one match."""
    hits = [m for m in re.finditer(pattern, data[start:end], re.DOTALL)]
    if len(hits) != 1:
        raise LookupError("expected exactly 1 match for %s, found %d" % (what, len(hits)))
    return hits[0].start() + start, hits[0]


class Site:
    """One logical patch. `parts` is a list of (file_offset, vanilla, patched)."""

    def __init__(self, name, parts, desc, default=True):
        self.name, self.parts, self.desc, self.default = name, parts, desc, default

    def state(self, data):
        seen = set()
        for off, orig, new in self.parts:
            cur = bytes(data[off:off + len(new)])
            seen.add("patched" if cur == new else "vanilla" if cur == orig else "UNKNOWN")
        if seen == {"patched"}:
            return "patched"
        if seen == {"vanilla"}:
            return "vanilla"
        return "UNKNOWN"

    def write(self, data, patched):
        for off, orig, new in self.parts:
            blob = new if patched else orig
            data[off:off + len(blob)] = blob

    @property
    def off(self):
        return self.parts[0][0]


# --------------------------------------------------------------------------- #
# the injected look-source thunk
# --------------------------------------------------------------------------- #
def build_look_thunk(cave_va, g_inputsystems_va):
    """
        push eax
        call .L1
    .L1:pop  eax                  ; eax = VA(.L1); no relocation needed
        mov  eax, [eax + D]       ; D is EIP-relative -> g_inputSystems[0]
        test eax, eax
        jz   .out                 ; leaves ZF=1 -> caller's `je` takes gamepad arm
        mov  eax, [eax + 0x10]    ; InputSystem::currentState
        test eax, eax
        jz   .out
        push ecx
        mov  ecx, [eax + 0x58]    ; InputState::deltaX  (float bits)
        add  ecx, ecx             ; shift out the sign bit; ZF=1 iff +/-0.0
        jnz  .pop2
        mov  ecx, [eax + 0x5C]    ; InputState::deltaY
        add  ecx, ecx
    .pop2:
        pop  ecx                  ; pop/ret do not touch flags
    .out:
        pop  eax
        ret
    """
    disp = g_inputsystems_va - (cave_va + 6)   # +6 == VA of .L1
    return (b"\x50"
            b"\xE8\x00\x00\x00\x00"
            b"\x58"
            b"\x8B\x80" + struct.pack("<i", disp) +
            b"\x85\xC0"
            b"\x74\x15"
            b"\x8B\x40\x10"
            b"\x85\xC0"
            b"\x74\x0E"
            b"\x51"
            b"\x8B\x48\x58"
            b"\x03\xC9"
            b"\x75\x05"
            b"\x8B\x48\x5C"
            b"\x03\xC9"
            b"\x59"
            b"\x58"
            b"\xC3")


THUNK_LEN = 40
CAVE_MIN = 44


def references_into(data, off2va, text, lo_va, hi_va):
    """Any rel32 branch or absolute pointer aiming inside [lo_va, hi_va)?"""
    tstart, tend = text[3], text[3] + text[4]
    i = tstart
    while i < tend - 5:
        if data[i] in (0xE8, 0xE9):
            va = off2va(i)
            if va is not None:
                tgt = va + 5 + struct.unpack_from("<i", data, i + 1)[0]
                if lo_va <= tgt < hi_va:
                    return True
        i += 1
    for va in range(lo_va, hi_va):
        if data.find(struct.pack("<I", va)) >= 0:
            return True
    return False


def find_cave(data, va2off, off2va, text, look_call_off):
    """Reuse the cave the call site already points at, else claim fresh padding."""
    if data[look_call_off] == 0xE8:
        rel = struct.unpack_from("<i", data, look_call_off + 1)[0]
        cave_va = off2va(look_call_off) + 5 + rel
        off = va2off(cave_va)
        if off is None:
            raise LookupError("existing look thunk points outside the image")
        return cave_va, off

    tstart, tend = text[3], text[3] + text[4]
    for m in re.finditer(b"\xCC{%d,}" % CAVE_MIN, bytes(data[tstart:tend])):
        off = m.start() + tstart
        cave_va = off2va(off)
        if cave_va is None:
            continue
        if references_into(data, off2va, text, cave_va, cave_va + THUNK_LEN):
            continue
        return cave_va, off
    raise LookupError("no unreferenced %d-byte code cave found in .text" % CAVE_MIN)


# --------------------------------------------------------------------------- #
def locate_sites(data):
    base, va2off, off2va, text = make_maps(data)
    tstart, tend = text[3], text[3] + text[4]
    sites = []

    # --- 1. the XInput "activity only" block inside PCXInputProducer::update
    act_pat = (rb"\x66\x83\xBE\x94\x00\x00\x00\x00\x75."
               rb"\x80\xBE\x96\x00\x00\x00\x00\x77."
               rb"\x80\xBE\x97\x00\x00\x00\x00\x77.")
    act_off, _ = find_one(data, act_pat, "PCXInputProducer activity block", tstart, tend)
    act_va = off2va(act_off)

    # --- 2. the `jne act_va` that skips the pad state fill, and the cmp before it
    jne_pat = re.compile(rb"\x80\x3D(....)\x00(?:\x0F\x85(....)|\x90{6})", re.DOTALL)
    cand = []
    for m in jne_pat.finditer(bytes(data[tstart:tend])):
        off = m.start() + tstart
        va = off2va(off)
        if m.group(2) is not None:
            if va + 13 + struct.unpack("<i", m.group(2))[0] != act_va:
                continue
        elif not (0 < act_off - off < 0x400):
            continue
        cand.append((off, struct.unpack("<I", m.group(1))[0]))
    if len(cand) != 1:
        raise LookupError("expected 1 pad gate, found %d" % len(cand))
    pad_off, flag_va = cand[0]
    flagb = re.escape(struct.pack("<I", flag_va))

    sites.append(Site("pad", [(
        pad_off + 7,
        b"\x0F\x85" + struct.pack("<i", act_va - (off2va(pad_off) + 13)),
        b"\x90" * 6)],
        "cdc::PCXInputProducer::update: NOP `jne activity_only` (VA 0x%08X) -> "
        "gamepad state is always filled" % off2va(pad_off + 7)))

    # --- 3. PCMouseKeyboard::update gate
    kbm_pat = (rb"\x80\xBB\x90\x00\x00\x00\x00\x0F\x84...."
               rb"\x80\xBB\x86\x00\x00\x00\x00\x0F\x84...."
               rb"\x80\x3D" + flagb + rb"\x00(?:\x0F\x84....|\x90{6})")
    kbm_off, _ = find_one(data, kbm_pat, "PCMouseKeyboard::update gate", tstart, tend)
    je_off = kbm_off + 33
    skip_va = off2va(kbm_off + 13) + 13 + struct.unpack_from("<i", data, kbm_off + 22)[0]
    sites.append(Site("kbm", [(
        je_off,
        b"\x0F\x84" + struct.pack("<i", skip_va - (off2va(je_off) + 6)),
        b"\x90" * 6)],
        "cdc::PCMouseKeyboard::update: NOP `je skip` (VA 0x%08X) -> "
        "mouse/keyboard state is always filled" % off2va(je_off)))

    # --- 4. mouse activity threshold (feeds g_usingMouseKeyboard only)
    mt_pat = (rb"\x03\xC8\x83\xF9[\x05\x00]\x0F\x9E\xC0\x84\xC2\x75."
              rb"\xC6\x86\x91\x00\x00\x00\x01")
    mt_off, _ = find_one(data, mt_pat, "mouse activity threshold", tstart, tend)
    sites.append(Site("mousethresh", [(mt_off + 4, b"\x05", b"\x00")],
                      "mouse activity threshold (VA 0x%08X): |dX|+|dY| > 5 -> != 0"
                      % off2va(mt_off + 4), default=False))

    # --- 5. pad thumbstick idle window (feeds g_usingMouseKeyboard only)
    pt_off = act_off + 0x23
    cur = bytes(data[pt_off:pt_off + 15])
    if not (len(cur) == 15 and cur[0] == 0xBA and cur[10] == 0xB9):
        raise LookupError("pad activity threshold not where expected")

    def _window(half):
        return cur[:1] + struct.pack("<i", -half) + cur[5:11] + struct.pack("<I", half)

    sites.append(Site("padthresh", [(pt_off, _window(0x3FFF), _window(0x1FFF))],
                      "pad activity threshold (VA 0x%08X): thumbstick idle window "
                      "+/-0x3FFF -> +/-0x1FFF" % off2va(pt_off), default=False))

    # --- 6. the look/aim device gate in FUN_007AC8C0
    look_pat = (rb"(?:\x80\x3D" + flagb + rb"\x00|\xE8....\x90\x90)"
                rb"(?:\x0F\x84....|\x90{6})\x80\x7C\x24\x40\x00\x0F\x85....")
    look_off, _ = find_one(data, look_pat, "look/aim device gate", tstart, tend)
    cmp_orig = b"\x80\x3D" + struct.pack("<I", flag_va) + b"\x00"
    je_off = look_off + 7
    sg_rel = struct.unpack_from("<i", data, look_off + 20)[0]
    pad_arm_va = off2va(look_off + 18) + 6 + sg_rel
    je_orig = b"\x0F\x84" + struct.pack("<i", pad_arm_va - (off2va(je_off) + 6))

    # g_inputSystems: `xor eax,eax / mov [esi*4 + g_inputSystems], eax / inc esi / cmp esi,4`
    gis_off, gis_m = find_one(
        data, rb"\xEB\x02\x33\xC0\x89\x04\xB5(....)\x46\x83\xFE\x04\x7C.",
        "g_inputSystems array", tstart, tend)
    gis_va = struct.unpack("<I", gis_m.group(1))[0]

    cave_va, cave_off = find_cave(data, va2off, off2va, text, look_off)
    thunk = build_look_thunk(cave_va, gis_va)
    assert len(thunk) == THUNK_LEN
    call = b"\xE8" + struct.pack("<i", cave_va - (off2va(look_off) + 5)) + b"\x90\x90"

    sites.append(Site("looksrc", [
        (look_off, cmp_orig, call),
        (cave_off, b"\xCC" * THUNK_LEN, thunk)],
        "look/aim update (VA 0x%08X): pick the mouse arm when the frame's real "
        "mouse delta is non-zero, else the gamepad arm (thunk at VA 0x%08X, "
        "g_inputSystems = 0x%08X)" % (off2va(look_off), cave_va, gis_va)))

    sites.append(Site("look", [(je_off, je_orig, b"\x90" * 6)],
                      "look/aim update: NOP `je gamepad_aim_path` (VA 0x%08X) -> "
                      "aiming ALWAYS uses the mouse arm; kills right-stick look "
                      "and aim assist" % off2va(je_off), default=False))

    # --- 7. PCXInputProducer::setVibration gate
    vib_pat = (rb"\x83\xEC\x0C\x80\x3D" + flagb +
               rb"\x00[\x74\xEB].\x33\xC0\x66\x89\x44\x24\x04\x33\xD2\xEB")
    vib_off, _ = find_one(data, vib_pat, "setVibration gate", tstart, tend)
    sites.append(Site("rumble", [(vib_off + 10, b"\x74", b"\xEB")],
                      "cdc::PCXInputProducer::setVibration: `je` -> `jmp` (VA 0x%08X) "
                      "-> rumble is not muted in keyboard/mouse mode"
                      % off2va(vib_off + 10)))

    return flag_va, sites


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(
        description="Allow keyboard/mouse and gamepad to be used at the same time in "
                    "Deus Ex: Human Revolution (Director's Cut).")
    ap.add_argument("exe", help="path to DXHRDC.exe (or DXHR.exe)")
    ap.add_argument("--revert", action="store_true", help="undo everything")
    ap.add_argument("--check", action="store_true", help="report status, write nothing")
    ap.add_argument("--force-mouse-look", action="store_true",
                    help="pin aiming to the mouse arm unconditionally instead of "
                         "choosing per frame. Disables right-stick look and aim "
                         "assist, and implies --no-looksrc.")
    ap.add_argument("--no-looksrc", action="store_true",
                    help="do not inject the look-source thunk")
    ap.add_argument("--mousethresh", action="store_true",
                    help="also drop the mouse activity threshold from 5 to 0")
    ap.add_argument("--padthresh", action="store_true",
                    help="also narrow the thumbstick idle window to +/-0x1FFF")
    ap.add_argument("--no-rumble", action="store_true",
                    help="leave the vibration gate alone")
    ap.add_argument("--no-backup", action="store_true", help="do not write a .kbmbak")
    args = ap.parse_args()

    with open(args.exe, "rb") as f:
        data = bytearray(f.read())

    try:
        flag_va, sites = locate_sites(data)
    except LookupError as e:
        print("ERROR: could not locate the input gates: %s" % e, file=sys.stderr)
        print("       (is this really a Deus Ex: HR / HR:DC executable?)", file=sys.stderr)
        return 2

    # Every site is always considered; one the caller did not select is driven back
    # to vanilla rather than left alone, so turning an option off actually undoes it.
    want = {s.name: s.default for s in sites}
    if args.force_mouse_look:
        want["look"], want["looksrc"] = True, False
    if args.no_looksrc:
        want["looksrc"] = False
    if args.mousethresh:
        want["mousethresh"] = True
    if args.padthresh:
        want["padthresh"] = True
    if args.no_rumble:
        want["rumble"] = False
    if args.revert:
        want = {k: False for k in want}

    print("g_usingMouseKeyboard = 0x%08X\n" % flag_va)

    todo, broken = [], False
    for s in sites:
        st = s.state(data)
        broken |= st == "UNKNOWN"
        target = "patched" if want[s.name] else "vanilla"
        if st != target:
            todo.append(s)
        print("%s [%-7s] %-11s file offset 0x%06X%s" % (
            "*" if st != target else " ", st, s.name, s.off,
            "  (+%d more)" % (len(s.parts) - 1) if len(s.parts) > 1 else ""))
        print("            %s" % s.desc)

    if broken:
        print("\nERROR: unexpected bytes at a patch site; refusing to touch the file.",
              file=sys.stderr)
        return 3

    if args.check:
        print("\n(* = differs from what the current options ask for)")
        return 0

    if not todo:
        print("\nNothing to do -- the file already matches these options.")
        return 0

    if not args.no_backup:
        bak = args.exe + ".kbmbak"
        if not os.path.exists(bak):
            shutil.copy2(args.exe, bak)
            print("\nBackup written: %s" % bak)

    applied = 0
    for s in todo:
        s.write(data, want[s.name])
        applied += want[s.name]

    with open(args.exe, "wb") as f:
        f.write(data)

    print("\nApplied %d site(s), reverted %d site(s)." % (applied, len(todo) - applied))
    print("New SHA-256: %s" % sha256(args.exe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
