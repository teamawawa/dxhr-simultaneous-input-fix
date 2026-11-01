# Original release (non-Director's Cut)

Target: `dxhr.exe`, Deus Ex: Human Revolution, Steam app 28050, build 16850:
version 1.4.651.0, the latest on Steam. PE32, `ImageBase = 0x00400000`, linker
timestamp 2012-05-16. Same seven sections as the Director's Cut, no DRM wrapper,
ASLR enabled.

SHA-256 of the stock exe: `d72c75d022f31216cf63a94acaef7612b38fb59783578095dd8191f3b5518259`.
Its stored PE checksum matches the computed one, which confirms it is unmodified.

The input code is the same design as in the Director's Cut: the same classes,
the same device flag, the same per-producer gates, the same split look/aim
branch. [`FINDINGS.md`](FINDINGS.md) describes all of it, and nothing in
this build contradicts it. What differs is layout and compiler output, and in
three places the code shape. `tools/patch_simultaneous_input.py` handles both
builds; it reads the layout from the exe rather than assuming one.

## Structure layout

The Director's Cut added one input to the `EInput` enum, most likely
`Keyboard_TriggerCommentary` for the director's commentary. That makes
`InputState` one byte longer and pushes every later field back:

| | Director's Cut | original |
|---|---|---|
| `InputState` key slots | `0x55` | `0x54` |
| `InputState::deltaX` / `deltaY` / `deltaWheel` | `+0x58/+0x5C/+0x60` | `+0x54/+0x58/+0x5C` |
| `InputSystem` ring entry stride | `0x70` | `0x6C` |
| `InputSystem::currentState` | `+0x10` | `+0x10` |

Producer fields are 4 bytes lower in the original:

| field | Director's Cut | original |
|---|---|---|
| `PCXInputProducer` `XINPUT_STATE.wButtons` | `+0x94` | `+0x90` |
| `PCXInputProducer` triggers | `+0x96/+0x97` | `+0x92/+0x93` |
| `PCXInputProducer` activity latch | `+0xA0` | `+0x9C` |
| `InputProducer` `cursorGrab` | `+0x86` | `+0x82` |
| `PCMouseKeyboard` activity latch | `+0x91` | `+0x8D` |
| `PCMouseKeyboard` accumulated `deltaX/deltaY` | `+0xB0/+0xB4` | `+0xA8/+0xAC` |

The thunk's `deltaX`/`deltaY` offsets matter. Reusing the Director's Cut thunk
here would read `deltaY` and the wheel instead, so horizontal mouse motion alone
would never select the mouse arm, with nothing crashing to point at it. The
patcher reads the offsets from `InputState::reset`:

```
56 6A <keys> 8B F1 6A 00 56 E8 ....   push esi / push keys / mov esi,ecx / push 0 / push esi / call memset
D9 EE  D9 56 <wheel>  83 C4 0C        fldz / fst [esi+wheel] / add esp,0xC
D9 56 <dY>  D9 5E <dX>  5E C3         fst [esi+dY] / fstp [esi+dX] / pop esi / ret
```

## Code differences

**Look/aim gate is inverted.** The Director's Cut tests the flag with `je` to
the gamepad arm and keeps the mouse arm inline, then checks SmartGlass. The
original has no SmartGlass, places the mouse arm out of line, and lets the
gamepad arm fall through:

```asm
0079E003  cmp   byte ptr [0x00B09E40], 0
0079E00A  jne   0x0079EFB1          ; flag set -> mouse arm (out of line)
0079E010  fld   dword ptr [esp+0x6C] ; gamepad arm: push ecx / fstp [esp] / push ebx /
          ...                         ; lea ecx,[esp+0xE8] / push ecx / mov ecx,esi / call aim assist
0079EFB1  ...                       ; mouse arm: writes [esi+0x70/0x74], jmp 0x0079EC73
```

The thunk needs no change for this. It leaves `ZF=0` exactly when the mouse
moved, and the DC's `je` falls through to the mouse arm while the original's
`jne` jumps to it. Only the optional `look` site differs: here the `jne` becomes
`nop; jmp` to the same target.

**Mouse activity threshold is 30, in `cl`.** The Director's Cut lowered it to 5,
so the original needs six times more motion per frame before it treats the mouse
as in use:

```asm
004B28C1  add   ecx, eax
004B28C3  cmp   ecx, 0x1E        ; DC: cmp ecx, 5
004B28C6  setle cl               ; DC: setle al
004B28C9  test  dl, cl
004B28CB  jne   0x004B28D4
004B28CD  mov   byte ptr [esi+0x8D], 1
```

`mousemotion` writes `mov cl, 1` here. The keyboard branch still reaches the latch
through its own `jmp 0x004B28CD` at `0x004B29B9`, so these bytes stay mouse-only.

**Stick window registers are swapped.** `mov ecx, -0x3FFF / mov edx, +0x3FFF`
where the DC uses `edx`/`ecx`. Only the optional `padthresh` site touches it.

## Sites

| name | VA | file offset | stock | patched |
|---|---|---|---|---|
| `pad` | `0x004B2FB9` | `0x0B23B9` | `0F 85 1B 03 00 00` (`jne`) | `90 ×6` |
| `kbm` | `0x004B0C94` | `0x0B0094` | `0F 84 10 10 00 00` (`je`) | `90 ×6` |
| `looksrc` call | `0x0079E003` | `0x39D403` | `80 3D 40 9E B0 00 00` (`cmp`) | `E8 rel32` + `90 90` |
| `looksrc` thunk | `0x00809EE1` | `0x4092E1` | `CC ×40` | 40-byte thunk, reading `+0x54/+0x58` |
| `looksrc` `.reloc` entry | fixup at `0x0079E005` | in `.reloc` | `HIGHLOW` | `ABSOLUTE` |
| `rumble` | `0x004B2DDA` | `0x0B21DA` | `74 0B` (`je`) | `EB 0B` (`jmp`) |
| `mousemotion` | `0x004B28C3` | `0x0B1CC3` | `83 F9 1E 0F 9E C1` | `B1 01 90 90 90 90` |

Other addresses:

| | Director's Cut | original |
|---|---|---|
| `g_usingMouseKeyboard` | `0x00B23E54` | `0x00B09E40` |
| `g_inputSystems` | `0x00E50980` | `0x00E344F0` |
| arbiter (`Input_UpdateActiveDevice`) | `0x004B0360` | `0x004B0060` |
| `PCXInputProducer::update` | `0x004B3490` | `0x004B2F50` |
| `PCMouseKeyboard::update` | `0x004B10B0` | `0x004B0BD0` |
| `PCXInputProducer::setVibration` | `0x004B3320` | `0x004B2DD0` |
| aim-assist gate (`FUN_007AAF70` equivalent) | `0x007AAFCD` | `0x0079BE5D` |
| references to `g_usingMouseKeyboard` | 47 | 44 |

## Verification

* Every site's patched bytes were read back out of a patched copy and
  disassembled. The thunk resolves `0x00809EE7 + 0x62A609 = 0x00E344F0`.
* `tools/rebase_check.py` passes for the default set and for `--force-mouse-look`,
  so no patched byte overlaps a live relocation.
* Applying and reverting every option returns the exact stock exe.
* The Director's Cut output of the same tool is byte-identical to before the port
  for every option and combination tested, including the release default
  `a54ba5bb…`.

* Tested in-game on Linux with the default set (`047c745c…`): works.
* The Java patchers produce the same bytes as the Python tool on this build, from
  a stock exe and from one carrying the optional `mousethresh` site, and revert
  to stock.
