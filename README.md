# DXHR / DXHR:DC — simultaneous keyboard/mouse + gamepad input patch

**Deus Ex: Human Revolution — Director's Cut** and the original **Deus Ex: Human
Revolution** (PC, Steam builds) accept one input device at a time. Touch the mouse and the gamepad stops responding; use the
gamepad and the mouse stops. This patch removes that.

Both devices stay live, and aiming follows whichever one you are actually moving,
decided per frame. It was built for aiming with a Steam Controller touchpad
mapped to Mouse while the sticks and buttons handle everything else. Right-stick
look, stick acceleration and aim assist all still work. Confirmed working
in-game on both games.

| game | Steam app | version | exe |
|---|---|---|---|
| Deus Ex: Human Revolution — Director's Cut | 238010 | 2.0.0.0 | `DXHRDC.exe` |
| Deus Ex: Human Revolution | 28050 | 1.4.651.0 | `dxhr.exe` |

Both are the latest Steam builds. Tested on Linux with cachyos-proton and on
Windows 10 Enterprise LTSC 2021, with the Steam Controller (2026); the original
release only on Linux so far.

Claude was used heavily in reverse engineering and developing the patch,
though the decomp by rrika helped a bunch. The whole process didn't take very long:

> ✻ Cooked for 14m 35s<br>
> ✻ Churned for 8m 45s<br>
> ✻ Baked for 8m 01s<br>
> ✻ Brewed for 11m 50s<br>

(and then the mod was working but I spent quite a bit more to get the java patcher looking the way I want)

---

## Mod download & Installation

See here: https://www.nexusmods.com/deusexhumanrevolution/mods/73

If you're an end user, this is what you should use. This repo is for others
who want to understand this patch or include it within their modpacks.

If you don't want to use nexusmods (understandable), you can also download
directly from github [here](https://github.com/teamawawa/dxhr-simultaneous-input-fix/releases/latest),
same description is also visible there.

---

## Mechanism

Addresses in this section are the Director's Cut's. The original release has the
same input code with different struct offsets and addresses, and three spots
compiled differently; [FINDINGS-non-directors-cut.md](FINDINGS-non-directors-cut.md)
covers them and lists its sites.

The engine keeps one global byte, `g_usingMouseKeyboard` (`0x00B23E54`),
re-arbitrated every frame: mouse/keyboard activity sets it to 1, gamepad activity
sets it to 0. Two mechanisms read it.

**Both input producers skip their entire state-filling code** when the byte names
the other device. That is what kills the pad the instant you touch the mouse.
Removing those two gates covers buttons, movement and axes, which all land in the
same summed `InputState`.

**The look/aim update branches on the same byte**, and its two arms read
different values. The mouse arm applies the raw mouse delta; the gamepad arm runs
stick acceleration and aim assist. They compute different things and cannot both
run, so looking has to pick one source per frame.

The byte is unreliable for that choice. It comes from coarse latch-based activity
detectors, and in practice it does not track the mouse while a pad is also in
use: move with the left stick or hold a trigger and mouse aiming dies. So
`looksrc` ignores it and asks the direct question instead.

```
g_inputSystems[0]->currentState->{deltaX, deltaY} != 0  ?  mouse arm : gamepad arm
```

Only `cdc::PCMouseKeyboard` writes those two floats, so this is an unambiguous
"did the mouse move this frame". A 40-byte thunk goes into `.text` padding and is
called in place of the `cmp`. It returns with `ZF` set so the original `je` still
does the branching, and clobbers nothing but flags.

| name | site | VA | file offset | vanilla | patched |
|---|------|----|-------------|---------|---------|
| `kbm` | `cdc::PCMouseKeyboard::update` gate | `0x004B116F` | `0x0B056F` | `0F 84 23 10 00 00` (`je`) | `90 ×6` |
| `pad` | `cdc::PCXInputProducer::update` gate | `0x004B35B7` | `0x0B29B7` | `0F 85 1C 03 00 00` (`jne`) | `90 ×6` |
| `looksrc` | look/aim source select | `0x007AD162` | `0x3AC562` | `80 3D … 00` (`cmp`) | `E8 rel32` + `90 90` |
| `looksrc` | injected thunk | `0x00844234` | `0x443634` | `CC ×40` | 40-byte thunk |
| `looksrc` | `.reloc` entry for the replaced `cmp` | — | `0xB03DBE` | `64 31` (`HIGHLOW`) | `64 01` (`ABSOLUTE`) |
| `rumble` | `cdc::PCXInputProducer::setVibration` gate | `0x004B332A` | `0x0B272A` | `74 0B` (`je`) | `EB 0B` (`jmp`) |
| `mousemotion` | raw-input mouse activity test | `0x004B2EC4` | `0x0B22C4` | `83 F9 05 0F 9E C0` (`cmp ecx,5; setle al`) | `B0 01 90 90 90 90` (`mov al,1`) |

The thunk is position-independent: `call`/`pop` gets EIP, then an EIP-relative
displacement reaches `g_inputSystems`. It needs no new base relocation and works
with the ASLR the image asks for. Its code cave is verified unreferenced before
use, and `--revert` restores it to `0xCC`.

The `cmp` that the call replaces held an absolute address, and its relocation
entry has to be disabled too. Windows rebases the exe and would otherwise add the
ASLR slide to the middle of the call; Wine loads it at the preferred base and never
applies relocations, so only Windows crashes. The patcher refuses any site that
overlaps a live relocation, and `tools/rebase_check.py` simulates a Windows load
(FINDINGS.md §5).

`cdc::InputSystem::CombineInputs` already sums the states of all registered
producers, and the two producers write to disjoint slots of the shared
`InputState`, so nothing else has to change.

`mousemotion` changes what the device flag means for the UI. The flag still
drives button prompts, the quick bar (the item row with 1–0 shortcuts), the menu
cursor and aim-assist gating, but mouse motion no longer sets it: keys, mouse
buttons and the wheel switch to keyboard/mouse mode, and pad input switches back.
Aiming with a touchpad next to a pad then leaves the quick bar and prompts in
gamepad mode. In menus, a click switches to pointer mode. FINDINGS.md §2b covers
how the quick bar reads the flag.

### Optional sites

All three are off by default.

| name | change | effect |
|---|------|--------|
| `mousethresh` | mouse activity threshold `5` → `0` | widens the detector feeding `g_usingMouseKeyboard`; replaces `mousemotion` |
| `padthresh` | thumbstick idle window `±0x3FFF` → `±0x1FFF` | same, for the pad |
| `look` | NOP the look/aim `je` at `0x007AD169` | aiming always uses the mouse arm |

The threshold sites only affect the flag. `mousethresh` rewrites the same bytes
as `mousemotion`, so selecting it turns `mousemotion` off.
`--force-mouse-look` guarantees mouse aiming but disables right-stick look, stick
acceleration and aim assist. It is the fallback if `looksrc` misbehaves.

[FINDINGS.md](FINDINGS.md) has the full reverse-engineering write-up, and
[FINDINGS-non-directors-cut.md](FINDINGS-non-directors-cut.md) how the original
release differs.

## Manual patching with python script

```sh
python3 tools/patch_simultaneous_input.py "/path/to/DXHRDC.exe"     # Director's Cut
python3 tools/patch_simultaneous_input.py "/path/to/dxhr.exe"       # original release

python3 tools/patch_simultaneous_input.py --check  <exe>    # report status, write nothing
python3 tools/patch_simultaneous_input.py --revert <exe>    # undo everything

# The following are for alternate patches, not meant to be used
python3 tools/patch_simultaneous_input.py --force-mouse-look <exe>
python3 tools/patch_simultaneous_input.py --no-looksrc       <exe>
python3 tools/patch_simultaneous_input.py --mousethresh      <exe>
python3 tools/patch_simultaneous_input.py --padthresh        <exe>
python3 tools/patch_simultaneous_input.py --no-rumble        <exe>
python3 tools/patch_simultaneous_input.py --no-mousemotion   <exe>
```

An exe patched by an earlier version reads as partly patched, and patching it
again completes it in place, producing the same bytes as a fresh install. A v4
install crashes on Windows when loading a save, because v4 did not disable the
relocation entry; v4.1 fixed that, v4.2 adds `mousemotion`, and v4.3 adds the
original release.

The script identifies the game from the exe itself and prints which one it
found. Struct offsets are read out of `InputState::reset` rather than assumed,
so the injected thunk reads the right fields in either game.

To check that a patched exe survives being loaded the way Windows loads it:

```sh
python3 tools/rebase_check.py /path/to/stock/DXHRDC.exe /path/to/patched/DXHRDC.exe
```

---

## Thanks

Big thanks to [rrika/cdcEngineDXHR](https://github.com/rrika/cdcEngineDXHR).
