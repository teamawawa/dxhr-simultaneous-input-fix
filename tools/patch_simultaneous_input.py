#!/usr/bin/env python3
"""
DXHR / DXHR:DC  --  "simultaneous keyboard+mouse and gamepad input" patch.

Vanilla behaviour
-----------------
The engine keeps a single global byte  g_usingMouseKeyboard  (0x00B23E54 in the
Director's Cut Steam/GOG build, 0x00B09E40 in the original release).  An
arbitration function (FUN_004B0360 in the DC) sets it to 1 when the
mouse/keyboard reports activity and to 0 when an XInput pad does.

Addresses below are the Director's Cut's.  Both builds are supported: struct
offsets are read from the exe, and the few places where the code itself differs
have a signature per build.  FINDINGS-non-directors-cut.md lists the differences.

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
  mousemotion  mouse motion no longer switches to keyboard/mouse mode, so the
            quick bar, prompts and menu cursor follow the keyboard and the pad;
            mouse buttons and the wheel still switch it

Optional, off by default:
  mousethresh  mouse activity threshold  5     -> 0  (replaces mousemotion)
  padthresh    pad thumbstick idle window 0x3FFF -> 0x1FFF
     Both only widen the coarse detectors feeding g_usingMouseKeyboard.  They do
     not fix looking.

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


IMAGE_REL_BASED_ABSOLUTE = 0    # padding entry; the loader skips it
IMAGE_REL_BASED_HIGHLOW = 3     # add the rebase delta to the dword at this RVA


def base_relocs(data):
    """Every base relocation entry as (rva, type, file offset of its 16-bit word).

    The exe sets DYNAMIC_BASE, so on Windows it is loaded at a randomised base and
    the loader adds the slide to every HIGHLOW dword listed here. Wine loads it at
    the preferred base and applies none of them, so a patch that writes over a live
    fixup works under Wine and is corrupted on Windows.
    """
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe_off + 24
    rva, size = struct.unpack_from("<II", data, opt + 96 + 5 * 8)
    base, secs = pe_sections(data)
    _, va2off, _, _ = make_maps(data)
    off = va2off(base + rva)
    if not rva or off is None:
        return []
    out, end = [], off + size
    while off + 8 <= end:
        page, block = struct.unpack_from("<II", data, off)
        if block < 8:
            break
        for w in range(off + 8, off + block, 2):
            word = struct.unpack_from("<H", data, w)[0]
            out.append((page + (word & 0xFFF), word >> 12, w))
        off += block
    return out


def find_one(data, pattern, what, start=0, end=None):
    """pattern is a regex over bytes; require exactly one match."""
    hits = [m for m in re.finditer(pattern, data[start:end], re.DOTALL)]
    if len(hits) != 1:
        raise LookupError("expected exactly 1 match for %s, found %d" % (what, len(hits)))
    return hits[0].start() + start, hits[0]


class Site:
    """One logical patch. `parts` is a list of (file_offset, vanilla, patched).

    `rivals` names sites that rewrite the same bytes differently. Bytes matching a
    rival's patched form count as vanilla for this site, and this site leaves
    them alone when reverting, since they are the rival's to revert.
    """

    def __init__(self, name, parts, desc, default=True, rivals=()):
        self.name, self.parts, self.desc, self.default = name, parts, desc, default
        self.rivals = list(rivals)          # Site objects, filled in after creation

    def _rival_owns(self, data):
        return any(r.state(data, _top=False) == "patched" for r in self.rivals)

    def state(self, data, _top=True):
        """patched / vanilla, "partial" when every part is one or the other but they
        disagree, UNKNOWN when any part matches neither.

        "partial" is a state real installs are in: v4 shipped `looksrc` without its
        relocation part, so an exe patched by v4 has the call and thunk but a live
        fixup. Patching completes it and reverting undoes it; only bytes we do not
        recognise are refused.
        """
        if _top and self._rival_owns(data):
            return "vanilla"
        seen = set()
        for off, orig, new in self.parts:
            cur = bytes(data[off:off + len(new)])
            seen.add("patched" if cur == new else "vanilla" if cur == orig else "UNKNOWN")
        if "UNKNOWN" in seen:
            return "UNKNOWN"
        if seen == {"patched"}:
            return "patched"
        if seen == {"vanilla"}:
            return "vanilla"
        return "partial"

    def write(self, data, patched):
        if not patched and self._rival_owns(data):
            return
        for off, orig, new in self.parts:
            blob = new if patched else orig
            data[off:off + len(blob)] = blob

    @property
    def off(self):
        return self.parts[0][0]


# --------------------------------------------------------------------------- #
# the injected look-source thunk
# --------------------------------------------------------------------------- #
def build_look_thunk(cave_va, g_inputsystems_va, dx_off=0x58, dy_off=0x5C):
    """deltaX/deltaY sit at +0x58/+0x5C in the Director's Cut and +0x54/+0x58 in the
    original, whose InputState has one fewer key; the caller passes the offsets
    read from InputState::reset in the exe being patched.

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
        mov  ecx, [eax + dx_off]  ; InputState::deltaX  (float bits)
        add  ecx, ecx             ; shift out the sign bit; ZF=1 iff +/-0.0
        jnz  .pop2
        mov  ecx, [eax + dy_off]  ; InputState::deltaY
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
            b"\x8B\x48" + bytes([dx_off]) +
            b"\x03\xC9"
            b"\x75\x05"
            b"\x8B\x48" + bytes([dy_off]) +
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
def detect_layout(data, tstart, tend):
    """Read the InputState layout out of InputState::reset, and name the build.

        push esi / push <keys> / mov esi,ecx / push 0 / push esi / call memset /
        fldz / fst [esi+<wheel>] / add esp,0xC / fst [esi+<dY>] / fstp [esi+<dX>]

    The Director's Cut has 0x55 key slots and the deltas at +0x58/+0x5C; the
    original has 0x54 and +0x54/+0x58, because the DC added one input. The two
    builds also differ in code the offsets cannot describe, keyed off the same
    fact: the mouse activity threshold (5 vs 30) and the shape of the look gate.
    """
    off, m = find_one(data, rb"\x56\x6A(.)\x8B\xF1\x6A\x00\x56\xE8....\xD9\xEE\xD9\x56(.)"
                            rb"\x83\xC4\x0C\xD9\x56(.)\xD9\x5E(.)\x5E\xC3",
                      "InputState::reset", tstart, tend)
    keys, wheel, dy, dx = (m.group(i)[0] for i in (1, 2, 3, 4))
    if not (dy == dx + 4 and wheel == dx + 8):
        raise LookupError("InputState::reset has an unexpected float layout")
    known = {0x55: ("Director's Cut", 0x05), 0x54: ("original", 0x1E)}
    if keys not in known:
        raise LookupError("unknown InputState layout (%d key slots)" % keys)
    name, mouse_threshold = known[keys]
    return {"name": name, "dx": dx, "dy": dy, "mouse_threshold": mouse_threshold}


def locate_sites(data):
    base, va2off, off2va, text = make_maps(data)
    tstart, tend = text[3], text[3] + text[4]
    relocs = base_relocs(data)
    layout = detect_layout(data, tstart, tend)
    sites = []

    # --- 1. the XInput "activity only" block inside PCXInputProducer::update
    #        cmp word [esi+B],0 / jne ; cmp byte [esi+B+2],0 / ja ; cmp byte [esi+B+3],0 / ja
    # B is XINPUT_STATE.wButtons: 0x94 in the Director's Cut, 0x90 in the original.
    act_pat = (rb"\x66\x83\xBE(.)\x00\x00\x00\x00\x75."
               rb"\x80\xBE(.)\x00\x00\x00\x00\x77."
               rb"\x80\xBE(.)\x00\x00\x00\x00\x77.")
    hits = [m for m in re.finditer(act_pat, bytes(data[tstart:tend]), re.DOTALL)
            if m.group(2)[0] == m.group(1)[0] + 2 and m.group(3)[0] == m.group(1)[0] + 3]
    if len(hits) != 1:
        raise LookupError("expected exactly 1 match for PCXInputProducer activity block, "
                          "found %d" % len(hits))
    act_off = hits[0].start() + tstart
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

    # --- 3. PCMouseKeyboard::update gate: the third of three guards
    #        cmp [ebx+init],0 / je ; cmp [ebx+cursorGrab],0 / je ; cmp [flag],0 / je
    kbm_pat = (rb"\x80\xBB.\x00\x00\x00\x00\x0F\x84...."
               rb"\x80\xBB.\x00\x00\x00\x00\x0F\x84...."
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

    # --- 4. mouse activity test (feeds g_usingMouseKeyboard only)
    #        add ecx,eax / cmp ecx,T / setle r8 / test dl,r8 / jne skip / mov [esi+L],1
    # Only the mouse branch of the raw-input handler runs these bytes; the keyboard
    # branch reaches the latch with its own `jmp` to the final mov. dl is "no button
    # or wheel event", r8 is "barely moved", and the latch is skipped when both hold.
    # The Director's Cut uses al and T=5, the original cl and T=30. Two sites
    # rewrite the cmp/setle pair, so they are rivals.
    mt_pat = (rb"\x03\xC8(?:\x83\xF9[\x00-\x7F]\x0F\x9E[\xC0\xC1]|[\xB0\xB1]\x01\x90{4})"
              rb"\x84([\xC2\xCA])\x75.\xC6\x86.\x00\x00\x00\x01")
    mt_off, mt_m = find_one(data, mt_pat, "mouse activity test", tstart, tend)
    reg = 1 if mt_m.group(1) == b"\xCA" else 0          # al = 0, cl = 1
    thr = layout["mouse_threshold"]
    mt_stock = bytes([0x83, 0xF9, thr, 0x0F, 0x9E, 0xC0 + reg])
    thresh = Site("mousethresh",
                  [(mt_off + 2, mt_stock, bytes([0x83, 0xF9, 0x00, 0x0F, 0x9E, 0xC0 + reg]))],
                  "mouse activity threshold (VA 0x%08X): |dX|+|dY| > %d -> != 0"
                  % (off2va(mt_off + 2), thr), default=False)
    # `mov r8, 1` makes "barely moved" always true, so the latch is set only by a
    # button or wheel event. Mouse motion then never flips the device flag, and the
    # quick bar, prompts and menu cursor follow the keyboard and the pad alone.
    motion = Site("mousemotion",
                  [(mt_off + 2, mt_stock, bytes([0xB0 + reg, 0x01, 0x90, 0x90, 0x90, 0x90]))],
                  "mouse activity test (VA 0x%08X): mouse motion no longer marks the "
                  "mouse/keyboard as active; buttons and wheel still do"
                  % off2va(mt_off + 2))
    thresh.rivals, motion.rivals = [motion], [thresh]
    sites += [thresh, motion]

    # --- 5. pad thumbstick idle window (feeds g_usingMouseKeyboard only)
    #        mov r1, -0x3FFF / cmp ax, r1w / jl / mov r2, +0x3FFF
    # The Director's Cut loads the window into edx/ecx, the original into ecx/edx.
    pt_off = act_off + 0x23
    cur = bytes(data[pt_off:pt_off + 15])
    if not (len(cur) == 15 and {cur[0], cur[10]} == {0xB9, 0xBA}):
        raise LookupError("pad activity threshold not where expected")

    def _window(half):
        return cur[:1] + struct.pack("<i", -half) + cur[5:11] + struct.pack("<I", half)

    sites.append(Site("padthresh", [(pt_off, _window(0x3FFF), _window(0x1FFF))],
                      "pad activity threshold (VA 0x%08X): thumbstick idle window "
                      "+/-0x3FFF -> +/-0x1FFF" % off2va(pt_off), default=False))

    # --- 6. the look/aim device gate
    # Director's Cut (FUN_007AC8C0): cmp [flag],0 / je pad_arm / cmp [esp+40h],0 /
    #   jne pad_arm, with the mouse arm inline; the second test is SmartGlass.
    # Original (FUN_0079D?): cmp [flag],0 / jne mouse_arm, with the mouse arm out of
    #   line and the pad arm falling through: fld [esp+X] / push ecx / fstp [esp] /
    #   push ebx / lea r,[esp+Y] / push r / mov ecx,esi / call aim_assist.
    # The thunk leaves ZF=0 exactly when the mouse moved, which takes the mouse arm
    # under both shapes: the DC's je falls through to it, the original's jne jumps.
    gate = rb"(?:\x80\x3D" + flagb + rb"\x00|\xE8....\x90\x90)"
    dc_pat = gate + rb"(?:\x0F\x84....|\x90{6})\x80\x7C\x24\x40\x00\x0F\x85...."
    orig_pat = (gate + rb"(?:\x0F\x85....|\x90\xE9....)"
                rb"\xD9\x44\x24.\x51\xD9\x1C\x24\x53\x8D[\x8C\x94]\x24....[\x51\x52]\x8B\xCE\xE8")
    shapes = [(m.start() + tstart, "dc") for m in
              re.finditer(dc_pat, bytes(data[tstart:tend]), re.DOTALL)]
    shapes += [(m.start() + tstart, "orig") for m in
               re.finditer(orig_pat, bytes(data[tstart:tend]), re.DOTALL)]
    if len(shapes) != 1:
        raise LookupError("expected exactly 1 look/aim device gate, found %d" % len(shapes))
    look_off, shape = shapes[0]
    cmp_orig = b"\x80\x3D" + struct.pack("<I", flag_va) + b"\x00"
    br_off = look_off + 7
    if shape == "dc":
        # optional `look` site: NOP the je so the mouse arm always runs
        sg_rel = struct.unpack_from("<i", data, look_off + 20)[0]
        pad_arm_va = off2va(look_off + 18) + 6 + sg_rel
        look_parts = [(br_off,
                       b"\x0F\x84" + struct.pack("<i", pad_arm_va - (off2va(br_off) + 6)),
                       b"\x90" * 6)]
        look_desc = "NOP `je gamepad_aim_path`"
    else:
        # optional `look` site: jne -> nop + jmp to the same target
        rel = data[br_off + 2:br_off + 6]
        look_parts = [(br_off, b"\x0F\x85" + rel, b"\x90\xE9" + rel)]
        look_desc = "`jne mouse_aim_path` -> `jmp`"

    # g_inputSystems: `xor eax,eax / mov [esi*4 + g_inputSystems], eax / inc esi / cmp esi,4`
    gis_off, gis_m = find_one(
        data, rb"\xEB\x02\x33\xC0\x89\x04\xB5(....)\x46\x83\xFE\x04\x7C.",
        "g_inputSystems array", tstart, tend)
    gis_va = struct.unpack("<I", gis_m.group(1))[0]

    cave_va, cave_off = find_cave(data, va2off, off2va, text, look_off)
    thunk = build_look_thunk(cave_va, gis_va, layout["dx"], layout["dy"])
    assert len(thunk) == THUNK_LEN
    call = b"\xE8" + struct.pack("<i", cave_va - (off2va(look_off) + 5)) + b"\x90\x90"

    # The cmp carries g_usingMouseKeyboard as an absolute operand at +2, so .reloc
    # has a HIGHLOW fixup there. Left live, Windows adds its ASLR slide to the
    # middle of our call's rel32 and the call lands in unmapped memory the first
    # time the look update runs. Turning the entry into ABSOLUTE padding makes the
    # loader skip it; reverting restores it.
    fix_rva = off2va(look_off) + 2 - base
    fix = [r for r in relocs if r[0] == fix_rva
           and r[1] in (IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_ABSOLUTE)]
    if len(fix) != 1:
        raise LookupError("expected 1 relocation for the look/aim cmp operand, found %d"
                          % len(fix))
    fix_word_off, low12 = fix[0][2], fix_rva & 0xFFF
    reloc_live = struct.pack("<H", (IMAGE_REL_BASED_HIGHLOW << 12) | low12)
    reloc_dead = struct.pack("<H", (IMAGE_REL_BASED_ABSOLUTE << 12) | low12)

    sites.append(Site("looksrc", [
        (look_off, cmp_orig, call),
        (cave_off, b"\xCC" * THUNK_LEN, thunk),
        (fix_word_off, reloc_live, reloc_dead)],
        "look/aim update (VA 0x%08X): pick the mouse arm when the frame's real "
        "mouse delta is non-zero, else the gamepad arm (thunk at VA 0x%08X, "
        "g_inputSystems = 0x%08X)" % (off2va(look_off), cave_va, gis_va)))

    sites.append(Site("look", look_parts,
                      "look/aim update: %s (VA 0x%08X) -> aiming ALWAYS uses the mouse "
                      "arm; kills right-stick look and aim assist"
                      % (look_desc, off2va(br_off)), default=False))

    # --- 7. PCXInputProducer::setVibration gate
    vib_pat = (rb"\x83\xEC\x0C\x80\x3D" + flagb +
               rb"\x00[\x74\xEB].\x33\xC0\x66\x89\x44\x24\x04\x33\xD2\xEB")
    vib_off, _ = find_one(data, vib_pat, "setVibration gate", tstart, tend)
    sites.append(Site("rumble", [(vib_off + 10, b"\x74", b"\xEB")],
                      "cdc::PCXInputProducer::setVibration: `je` -> `jmp` (VA 0x%08X) "
                      "-> rumble is not muted in keyboard/mouse mode"
                      % off2va(vib_off + 10)))

    check_relocations(sites, relocs, off2va, base)
    return flag_va, sites, layout


def check_relocations(sites, relocs, off2va, base):
    """Refuse any site whose code bytes overlap a fixup it does not also disable.

    Wine never applies relocations to this exe, so an overlap is invisible in
    testing there and only fails on Windows. That is how v4 shipped broken, so
    it is checked here rather than remembered.
    """
    rva_of_word = {word_off: rva for rva, _, word_off in relocs}
    disabled_by = {s.name: {rva_of_word[off] for off, _, _ in s.parts if off in rva_of_word}
                   for s in sites}
    disabled_any = set().union(*disabled_by.values())
    # Judge by the stock type: an entry some site disables is HIGHLOW in a clean exe
    # even if this file already has it patched to ABSOLUTE.
    live = [rva for rva, typ, _ in relocs
            if typ == IMAGE_REL_BASED_HIGHLOW or rva in disabled_any]
    for s in sites:
        for off, _, new in s.parts:
            if off in rva_of_word:
                continue                      # this part is the relocation edit itself
            lo = off2va(off) - base
            hi = lo + len(new)
            for rva in live:
                if rva < hi and rva + 4 > lo and rva not in disabled_by[s.name]:
                    raise LookupError(
                        "site %s writes over a live relocation at VA 0x%08X; it would "
                        "be corrupted when Windows rebases the image" % (s.name, base + rva))


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
    ap.add_argument("--no-mousemotion", action="store_true",
                    help="let mouse motion switch the game to keyboard/mouse mode, as "
                         "stock; the quick bar then shows whenever the mouse moves")
    ap.add_argument("--mousethresh", action="store_true",
                    help="drop the mouse activity threshold from 5 to 0. Rewrites the "
                         "same bytes as mousemotion, so it implies --no-mousemotion.")
    ap.add_argument("--padthresh", action="store_true",
                    help="also narrow the thumbstick idle window to +/-0x1FFF")
    ap.add_argument("--no-rumble", action="store_true",
                    help="leave the vibration gate alone")
    ap.add_argument("--no-backup", action="store_true", help="do not write a .kbmbak")
    args = ap.parse_args()

    with open(args.exe, "rb") as f:
        data = bytearray(f.read())

    try:
        flag_va, sites, layout = locate_sites(data)
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
    if args.no_mousemotion:
        want["mousemotion"] = False
    if args.mousethresh:
        want["mousethresh"], want["mousemotion"] = True, False
    if args.padthresh:
        want["padthresh"] = True
    if args.no_rumble:
        want["rumble"] = False
    if args.revert:
        want = {k: False for k in want}

    print("build: %s   g_usingMouseKeyboard = 0x%08X\n" % (layout["name"], flag_va))

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
