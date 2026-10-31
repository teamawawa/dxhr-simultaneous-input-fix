# Reverse-engineering notes

Target: `DXHRDC.exe`, Deus Ex: Human Revolution — Director's Cut, Steam build.
PE32, `ImageBase = 0x00400000`, 7 sections. `.text` is VA `0x00401000`, raw offset
`0x400`, so **file offset = VA − 0x400C00**.

SHA-256 of the exe as analysed, already DXHR-Patcher-patched:
`70c24671c9136743cac611958ae0c8e37e95fdc8f97b68daea962f33bf2b7cd0`

Reference material:

* [`rrika/cdcEngineDXHR`](https://github.com/rrika/cdcEngineDXHR), a partial
  decompilation of the engine, cloned into `cdcEngineDXHR/`. Its `input/`
  directory gives the `InputProducer` / `InputSystem` class shapes and the
  `EInput` enum. Its `InputSystem::CombineInputs` and `PCMouseKeyboard::update`
  are simplified rewrites rather than faithful ones, and the device arbitration
  described below does not appear there at all.
* The exe's MSVC RTTI, which carries real class names. `objtree.txt` in the
  decomp repo is a dump of that hierarchy.

---

## 1. Input classes

RTTI type descriptors were located by searching for the mangled names, then
walking `TypeDescriptor → CompleteObjectLocator → vftable` (`tools/rtti.py`,
`tools/vftable.py`):

| class | type descriptor | vftable |
|---|---|---|
| `cdc::InputProducer` | `0x00B239A4` | `0x00A90ADC` |
| `cdc::RandomInputProducer` | `0x00B239C4` | `0x00A90B34` |
| `cdc::InputSystem` | `0x00B23E00` | `0x00A90C08` |
| `cdc::PCMouseKeyboard` | `0x00B23FFC` | `0x00A9173C` |
| `cdc::PCXInputProducer` | `0x00B24020` | `0x00A9181C` |

Mapping the vftable slots onto `cdcEngineDXHR/input/Input.h`'s `InputProducer`
layout (`method_0`, `setCursorGrab`, `method_8`, `method_C`, `method_10`,
`update`, `method_18`, …):

| slot | offset | `InputProducer` | `PCMouseKeyboard` | `PCXInputProducer` |
|---|---|---|---|---|
| 0 | `0x00` | `0x006B1B30` | `0x004B3220` | `0x006B1B30` |
| 1 | `0x04` | `0x004AC3D0` `setCursorGrab` | `0x004B2840` | `0x004AC3D0` |
| 4 | `0x10` | `0x009A2B10` | `0x009A2B10` | `0x004B33B0` poll/connect |
| **5** | `0x14` | `0x004AC3F0` **`update`** | **`0x004B10B0`** | **`0x004B3490`** |
| 6 | `0x18` | `0x004AC420` | `0x004B0CB0` | `0x004AC420` |
| 10 | `0x28` | `0x004AD230` | `0x004AD230` | `0x004AD230` reset state |
| 11 | `0x2C` | `0x004B3320` | — | `0x004B3320` `setVibration` (§3c) |

The XInput entry points are resolved dynamically into `.data`:

| address | contents |
|---|---|
| `0x00E514C4` | `XInputGetState` |
| `0x00E514C8` | `XInputSetState` |
| `0x00E514CC` | "XInput disabled" byte, set by `sub_004B3980` |
| `0x00E514B4` | array of `PCXInputProducer*` |
| `0x00E514D4` | number of entries in that array |
| `0x00E51498` | the `PCMouseKeyboard*` |

---

## 2. `g_usingMouseKeyboard`

```
0x00B23E4C  float  g_mouseXSensitivity      = 0.00135f
0x00B23E50  float  g_mouseYSensitivity      = 0.00135f
0x00B23E54  byte   g_usingMouseKeyboard     = 1
0x00B23E55  byte   g_prevUsingMouseKeyboard = 1
```

The engine re-decides every frame which single device is the input device.
`FUN_004B0360`, call it `Input_UpdateActiveDevice`, is the arbiter:

```c
void Input_UpdateActiveDevice(void) {
    g_prevUsingMouseKeyboard = g_usingMouseKeyboard;

    if (PCMouseKeyboard_ConsumeActivity(g_mouseKeyboard))   // sub_004B0BA0
        g_usingMouseKeyboard = 1;
    else {
        for (i = 0; i < g_numPads; i++)
            if (PCXInputProducer_ConsumeActivity(g_pads[i])) {   // sub_004B3960
                g_usingMouseKeyboard = 0;
                break;
            }
        if (g_smartGlass && SmartGlass_HadActivity())
            g_usingMouseKeyboard = 0;
    }

    if (g_usingMouseKeyboard != g_prevUsingMouseKeyboard) {
        debugPrint(g_usingMouseKeyboard ? "keyboard" : "Xinput");  // 0xA90CAC / 0xA90CA4
        UI_OnActiveInputDeviceChanged();                           // FUN_0081A130
        if (g_usingMouseKeyboard)
            for (i = 0; i < g_numPads; i++)
                g_pads[i]->vt[0x28]();   // wipe the pad's InputState
    }
    FUN_004B3400();
}
```

The mouse branch is checked first and short-circuits, so as long as the mouse
keeps producing motion, which a Steam Controller touchpad mapped to mouse does
continuously, `g_usingMouseKeyboard` stays at 1 and the pad never gets a look-in.

Both "consume activity" helpers are latch-readers. The latches themselves sit
behind thresholds (§2a):

```asm
sub_004B0BA0   ; PCMouseKeyboard: byte [this+0x91], set from the WM_INPUT handler
    cmp  byte ptr [ecx+0x91], 0
    je   .no
    mov  byte ptr [ecx+0x91], 0
    mov  al, 1
    ret

sub_004B3960   ; PCXInputProducer: byte [this+0xA0], set by the block at 0x004B38D9
    cmp  byte ptr [ecx+0xA0], 0
    je   .no
    mov  byte ptr [ecx+0xA0], 0
    mov  al, 1
    ret
```

The arbiter only sets a flag. The lockout itself is in the producers (§3).

### 2a. Activity thresholds

Neither latch is set by "the device produced anything". Both sit behind a
threshold, and below it the device counts as idle.

Mouse, in the `WM_INPUT` / `RIM_TYPEMOUSE` handler at `0x004B2E92`:

```asm
004B2E92  mov   ecx, [esp+0x30]         ; RAWMOUSE.lLastX
004B2E96  add   [esi+0xB0], ecx         ; accumulate deltaX
004B2E9C  mov   ecx, [esp+0x34]         ; RAWMOUSE.lLastY
004B2EA0  mov   eax, [esi+0xB0]
004B2EA6  add   [esi+0xB4], ecx         ; accumulate deltaY
004B2EAC  mov   ecx, [esi+0xB4]
          ; eax = |deltaX|, ecx = |deltaY|
004B2EC2  add   ecx, eax                ; Manhattan distance this frame
004B2EC4  cmp   ecx, 5                  ; <<< site: mousethresh
004B2EC7  setle al                      ; al = "barely moved"
004B2ECA  test  dl, al                  ; dl = "no button or wheel event either"
004B2ECC  jne   0x4B2ED5                ; -> not activity
004B2ECE  mov   byte ptr [esi+0x91], 1  ; latch: the mouse was used this frame
```

`this+0xB0/0xB4` are zeroed at the end of every `PCMouseKeyboard::update`, so
this is a per-frame budget. At 60 fps you must generate more than 300 raw counts
per second before the engine believes you are using the mouse, and slow precise
aiming on a touchpad never clears it.

Pad, inside the activity block at `0x004B38D9`:

```asm
004B38FC  mov   edx, 0xFFFFC001         ; -0x3FFF   <<< site: padthresh
004B3901  cmp   ax, dx
004B3904  jl    .active
004B3906  mov   ecx, 0x3FFF             ; +0x3FFF   <<< site: padthresh
004B390B  cmp   ax, cx
004B390E  jg    .active
          ; ...repeated for all four thumbstick axes...
```

`0x3FFF` is half of full deflection, so anything gentler counts as idle for
arbitration purposes. The window is loaded into `edx` and `ecx` once and reused
for all four axes, so it is exactly two immediates.

`mousethresh` lowers the mouse threshold to 0, where `setle` means "moved by
exactly zero". `padthresh` narrows the stick window to `±0x1FFF`, roughly the
standard XInput right-stick deadzone of `8689`: small enough that ordinary
deflection registers, large enough that a noisy resting stick does not.

Both sites are off by default. They make the flag more responsive but do not fix
looking (§3d), and leaving them alone keeps button prompts and aim-assist gating
at their shipped behaviour.

---

## 3. Flag consumers

`ghidra_scripts/DumpFlagRefs.java` finds 47 references. Three are writes:
`FUN_004B0360` ×3, plus `FUN_006B1A50`, which forces 0 from a padshock script.

Most of the reads are Scaleform UI code deciding which button glyphs to draw:
`FUN_0072D1F0`, `FUN_007305B0`, `FUN_00735B90`, `FUN_00736050`, `FUN_00736750`,
`FUN_007384F0`, `FUN_00739500`, `FUN_00739900`, `FUN_00809920`, `FUN_0080A180`,
`FUN_0080A490`, `FUN_0080A6D0`, `FUN_008126E0`, `FUN_00812330`, `FUN_00812F00`,
`FUN_007AAF70`, `FUN_007BB900`, `FUN_007FD0D0`, `FUN_007FE2A0`, and
`FUN_0081A130` for mouse-cursor show/hide.

Four reads gate input: §3a, §3b, §3c and §3d. Three of the four are patched by
default. §3d is left intact and handled by the thunk in §5.

### 3a. `cdc::PCMouseKeyboard::update` @ `0x004B10B0`

```asm
004B114E  cmp   byte ptr [ebx+0x90], 0
004B1155  je    0x4B2198              ; not initialised -> skip
004B115B  cmp   byte ptr [ebx+0x86], 0
004B1162  je    0x4B2198              ; cursor not grabbed -> skip
004B1168  cmp   byte ptr [0x00B23E54], 0
004B116F  je    0x4B2198              ; <<< site: kbm. pad is active -> skip
004B1175  fild  dword ptr [ebx+0xB0]  ; deltaX
004B117B  fmul  dword ptr [0x00B23E4C]; * g_mouseXSensitivity
    ...                                ; -> state.deltaX (this+0x5C) and keys[82]
```

`0x4B2198` is the shared epilogue: pop the pending FPU value, copy
`vkeys → vkeysPrev`, zero `deltaX/deltaY/deltaWheel` (`this+0xB0/0xB4/0xB8`),
`return true`. The full path converges on the same epilogue at `0x4B219A`.

With a pad active the mouse/keyboard producer contributes nothing and discards
its accumulated deltas.

### 3b. `cdc::PCXInputProducer::update` @ `0x004B3490`

```asm
004B3490  push  ecx
004B3492  mov   esi, ecx
          call  this->vt[8]                  ; enabled?
          je    .return_false
004B349F  mov   ecx, [esi+0x88]              ; dwUserIndex
004B34A5  lea   eax, [esi+0x90]              ; XINPUT_STATE
004B34AD  call  dword ptr [0x00E514C4]       ; XInputGetState
          test  eax, eax
          jne   .disconnected
    ...
004B3582  cmp   byte ptr [0x00E514CC], 0     ; XInput globally disabled?
004B3589  jne   0x4B394A                     ; -> return true, no state
004B3596  call  0x004AC3F0                   ; InputProducer::update (enabled && grabbed?)
          je    .return_false
004B35A3  cmp   byte ptr [esi+0x86], 0       ; cursorGrab
004B35AA  je    .return_false
004B35B0  cmp   byte ptr [0x00B23E54], 0
004B35B7  jne   0x4B38D9                     ; <<< site: pad. kbm active -> activity check only
004B35BD  fldz                               ; ---- fill path ----
          ...                                ; buttons -> state.keys[0..3]
004B3860  ...                                ; thumbsticks -> state.keys[0x10..0x13]
004B38D6  mov   byte ptr [esi+0x17], al
                                             ; ---- falls through ----
004B38D9  cmp   word ptr [esi+0x94], 0       ; ---- activity detector ----
          jne   .active
          cmp   byte ptr [esi+0x96], 0       ; left trigger
          ja    .active
          cmp   byte ptr [esi+0x97], 0       ; right trigger
          ja    .active
          ; each thumbstick axis vs. +/-0x3FFF
          ...
004B3943  .active: mov byte ptr [esi+0xA0], 1
004B394A  mov   al, 1
004B394E  ret   4
```

The state-filling path falls straight through into the activity detector, and the
`jne` at `0x004B35B7` only skips the filling. NOPing it makes the pad always fill
its state while the activity latch keeps working, so on-screen button prompts
still switch to gamepad glyphs when you use the pad.

### 3c. `cdc::PCXInputProducer::setVibration` @ `0x004B3320`

```asm
004B3320  sub   esp, 0xC
004B3323  cmp   byte ptr [0x00B23E54], 0
004B332A  je    0x4B3337                     ; <<< site: rumble
004B332C  xor   eax, eax                     ; kbm active -> both motors = 0
004B332E  mov   word ptr [esp+4], ax
004B3333  xor   edx, edx
004B3335  jmp   0x4B3395
004B3337  fld   dword ptr [ecx+0x7C]         ; left motor  (float 0..1)
          ...
004B336C  fmul  dword ptr [ecx+0x80]         ; right motor
004B3395  mov   ecx, [ecx+0x88]              ; dwUserIndex
          call  dword ptr [0x00E514C8]       ; XInputSetState
```

Rumble is muted the same way. Turning the `je` into an unconditional `jmp` always
takes the "compute real motor speeds" path.

### 3d. Look/aim update `FUN_007AC8C0` @ `0x007AD162`

```asm
          ; ... look deltas computed into [esp+0x38] / [esp+0x80..0x8C] from
          ; two LogicInput evaluations (FUN_004AEAE0) ...
007AD162  cmp   byte ptr [0x00B23E54], 0     ; <<< site: looksrc replaces this cmp
007AD169  je    0x7AD20D            ; <<< site: look. pad active -> gamepad aim path
007AD16F  cmp   byte ptr [esp+0x40], 0
007AD174  jne   0x7AD20D            ; SmartGlass active -> gamepad aim path
007AD17A  ...                       ; ---- mouse arm: raw delta, no assist ----
007AD1FE  fstp  dword ptr [esi+0x70]
007AD205  fstp  dword ptr [esi+0x74]
007AD208  jmp   0x7ADEAB            ; done
007AD20D  ...                       ; ---- gamepad arm ----
007AD220  call  0x007AAF70          ; aim-assist target acquisition
          ...                       ; stick acceleration curves (FUN_007AA360,
          ;                            FUN_00461820), magnetism, then [esi+0x70/0x74]
```

The two arms do not read the same values. The mouse arm consumes the raw
per-frame mouse delta; the gamepad arm consumes separately-scaled stick values
and runs them through aim assist. This is a second, independent device switch
rather than a redundant guard on top of §3a and §3b, and it only becomes visible
once the producer gates are removed. Before that the byte was pinned to 1
whenever the mouse moved and the pad produced nothing, so the mouse arm was
always the correct choice.

The exclusivity here is a genuine either/or: the two arms compute different
things and cannot both run. The choice has to be made accurately rather than
forced.

`g_usingMouseKeyboard` is unreliable for it. With a pad in use, either the left
stick for movement or a held trigger, mouse aiming dies even with the right stick
completely idle, and even with both thresholds in §2a lowered. Something holds
the flag at 0 whenever the pad is active that the threshold change does not
reach. One unconfirmed candidate: the arbiter (`FUN_004AC680` → `FUN_004B0360`)
has three call sites, so it may run more than once per tick. Only the first call
would see the mouse latch, which it consumes and clears, while the pad latches
stay pending because the mouse branch short-circuits past the pad loop. A second
call in the same tick would then find a stale pad latch and flip the flag back
to 0.

The branch does not need to know which device the player is using. It needs to
know whether there is a mouse delta to apply this frame, which is directly
observable:

```c
InputState *st = g_inputSystems[0]->currentState;   // +0x10
bool useMouseArm = st->deltaX != 0.0f || st->deltaY != 0.0f;  // +0x58, +0x5C
```

Only `cdc::PCMouseKeyboard` writes those two floats; the pad producer writes
`keys[0..0x13]` and nothing else. §5 covers the thunk that implements this.

The alternative is the `look` site, which NOPs the `je` and pins the update to
the mouse arm. That works, at the cost of making the gamepad arm dead code and
losing right-stick look, stick acceleration and aim assist with it. It is
available as `--force-mouse-look`.

Two nearby gates were checked and do not gate looking: `FUN_007BB900` @
`0x007BB946`, an aim-assist stickiness timer, and `FUN_007FD0D0` @ `0x007FD0D0`,
UI focus. Neither needs patching.

---

## 4. Input combining

`cdc::InputSystem::CombineInputs` iterates the registered producers and sums
their `InputState`s, saturating each of the 85 key bytes to ±127 and adding the
three float deltas. See `cdcEngineDXHR/input/Input.cpp`. There is no "pick one
producer" logic there; the exclusivity lives entirely in the producers.

The two producers write to disjoint slots of `InputState`, at offsets relative to
the producer's `state` at `this+4`:

| producer | writes | `EInput` meaning |
|---|---|---|
| `PCXInputProducer` | `state.keys[0x00..0x03]`, `keys[0x10..0x13]` | pad buttons, left+right thumbsticks (`Input_16..19`) |
| `PCMouseKeyboard` | `keys[0x20]`, `keys[0x21]` | `Input_MovementAD`, `Input_MovementWS` |
| | `keys[0x24..0x3F]` | `Input_Action` … `Input_TriggerCommentary` |
| | `keys[0x52..0x54]` + floats `+0x5C/0x60/0x64` | `Input_MouseX/Y/Wheel` |

Gamepad look uses the right thumbstick (`Input_18/19`) and mouse look uses
`Input_MouseX/Y`. They travel through separate slots and are read by separate
code paths, so both can drive the camera in the same frame.

None of the branch patches introduces a code path the binary does not already
execute. Each makes the binary always take the branch it already takes in one of
the two vanilla modes, so the x87 stack discipline is unchanged and both branches
converge on the same epilogue.

### Residual behaviour after patching

* `g_usingMouseKeyboard` still flips exactly as before, so button prompts, cursor
  visibility and the aim-assist gate in `FUN_007AAF70` keep following the
  last-used device. The flag is left alone rather than pinned.
* On each `pad → kbm` transition the arbiter still calls `vt[0x28]` on every pad
  producer, which wipes its state for one frame. The pad refills it on the next
  `update()`.
* Looking still switches source per frame, per §3d. The switch is driven by the
  frame's actual mouse delta rather than by the device flag.
* With `--force-mouse-look` the gamepad aim path stops running, taking
  right-stick look, stick acceleration and aim assist with it. Movement, buttons
  and everything else on the pad are unaffected either way, since they do not go
  through `FUN_007AC8C0`.
* A mouse with sensor jitter reports a non-zero delta most frames and so holds
  the mouse arm. A Steam Controller touchpad emits nothing while untouched, so
  this does not arise there.
* A controller with a non-centred resting stick now applies that drift instead of
  having it ignored while you are on mouse/keyboard. DXHR applies deadzones from
  `logicinput_database`, which should absorb it, but this is the most likely
  source of trouble. See TESTING.md.

---

## 5. The injected look-source thunk

The only patch that adds code rather than removing a branch.

**Call site.** The 7-byte `cmp byte [g_usingMouseKeyboard], 0` at `0x007AD162` is
replaced by `call rel32` plus two `nop`s. The `je gamepad_aim_path` at
`0x007AD169` is left untouched, so the thunk only has to return with `ZF` set
correctly.

**Where it lives.** 44 bytes of `0xCC` inter-function padding at `0x00844234`
(file `0x443634`), between the end of one function and the 16-byte-aligned start
of the next at `0x00844260`. The patcher verifies that no `rel32` branch and no
absolute pointer anywhere in the image targets that range before claiming it, and
`--revert` fills it back with `0xCC`.

**The thunk**, 40 bytes:

```asm
        push eax
        call .L1
.L1:    pop  eax                  ; eax = VA(.L1)
        mov  eax, [eax + D]       ; D = g_inputSystems - VA(.L1), a build constant
        test eax, eax
        jz   .out                 ; ZF=1 -> caller's `je` takes the gamepad arm
        mov  eax, [eax + 0x10]    ; InputSystem::currentState
        test eax, eax
        jz   .out
        push ecx
        mov  ecx, [eax + 0x58]    ; InputState::deltaX, as raw float bits
        add  ecx, ecx             ; shift out the sign bit; ZF=1 iff +/-0.0
        jnz  .pop2
        mov  ecx, [eax + 0x5C]    ; InputState::deltaY
        add  ecx, ecx
.pop2:  pop  ecx
.out:   pop  eax
        ret
```

Four properties make this safe to drop into the middle of a live function:

* **Registers.** Only `eax` and `ecx` are touched, both saved and restored. `ecx`
  is dead at the call site anyway: the gamepad arm's `push ecx` at `0x007AD211`
  is the "reserve 4 bytes for an `fstp`" idiom rather than an argument. `ebx` and
  `esi` are live there and are never touched.
* **Flags.** `pop` and `ret` do not affect flags, so the last flag-setting
  instruction on each path is what the caller's `je` sees. `add ecx, ecx` doubles
  as the zero test, and `add` on `-0.0` (`0x80000000`) yields `0`, so negative
  zero counts as no motion.
* **Relocation of the thunk.** The image sets
  `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`, so it can be rebased, and any absolute
  address baked into new code would need a `.reloc` entry. The `call`/`pop` gets
  EIP at runtime and the displacement to `g_inputSystems` is a difference between
  two addresses in the same image, which is invariant under rebasing, so the
  thunk needs no entry of its own.
* **Fallback.** If `g_inputSystems[0]` or its `currentState` is null during early
  start-up, both `test`s leave `ZF=1` and the caller takes the gamepad arm, which
  is the vanilla behaviour for `g_usingMouseKeyboard == 0`.

**Relocation of the call site.** The `cmp` being replaced carries
`g_usingMouseKeyboard` as an absolute operand, so `.reloc` has a `HIGHLOW` fixup
for VA `0x007AD164`. That dword now sits across the middle of the `call`'s rel32
and the first `nop`. Windows loads the exe at a randomised base and adds the
slide to that dword, which sends the call into unmapped memory the first time the
look update runs: the game reaches the main menu and crashes on loading a save.
Wine loads the exe at its preferred base and applies no relocations, so the bug
cannot be reproduced under Proton.

`looksrc` therefore has a third part: the relocation entry's type goes from
`HIGHLOW` (3) to `ABSOLUTE` (0), which the loader treats as padding and skips. It
is a single byte at file offset `0xB03DBF`, and `--revert` restores it. Both
patchers also refuse any site whose code bytes overlap a live fixup that the same
site does not disable, and `tools/rebase_check.py` applies every live fixup with
several slides and requires patched bytes to come through unchanged.

| VA (of fixup) | entry word, file offset | stock | patched |
|---|---|---|---|
| `0x007AD164` | `0xB03DBE` | `64 31` (`HIGHLOW`, offset `0x164`) | `64 01` (`ABSOLUTE`) |

`g_inputSystems` (`0x00E50980`) is recovered from the initialiser loop in
`FUN_004AC590` rather than hardcoded:

```asm
004AC604  xor  eax, eax
004AC606  mov  [esi*4 + 0x00E50980], eax
004AC60D  inc  esi
004AC60E  cmp  esi, 4
```

Index 0 is the right one. `FUN_004AC590` registers both producers on
`g_inputSystems[0]` (`mov ecx, [0x00E50980]` before each `AddProducer` call at
`0x004AC656` and `0x004AC669`), so that is where the combined mouse delta lands.

---

## Appendix A — what the DXHR Patcher changes

`patcher/DXHR-Patcher_1.5.jar` ships its own sources. `ExecuteChanges.java` is a
flat list of raw-file-offset byte pokes per game version. For `DC_STEAM`:

| feature | file offset(s) | off → on |
|---|---|---|
| Skip Cutscenes | `0x3DAB98` | `0x10` → `0x24` |
| Bypass Hacking | `0x3F0278`, `0x3F0CD3` | `0x20`→`0x14`, `0x24`→`0x18` |
| Stop Telemetry | `0x0EB096` | `0x73` (`jae`) → `0xEB` (`jmp`) |
| High Core Count Fix | `0x0D3165`..`+4` | `E8 46 F0 FF FF` (`call`) → 5× `0x90` |
| FOV Increase | `0x667043`, `0x3DE612`, `0x3DE61A` | `100`→`110`, `100`→`110`, `6`→`8` |
| Energy Cell Regen | `0x25E128` | `0x75` (`jne`) → `0xEB` (`jmp`) |
| Skip Intro Videos | `0x2323E5`..`+1` | `74 09` (`je`) → `90 90` |
| Fix Linux Exit | `0x3F2D69`..`+6` | `6A 06 E8 60 E0 E3 FF` → 7× `0x90` |
| UI Scale | `0x332D2A` (13 B), `0x32E4F7` (25 B) | clamp/`>>1` variants |

Every one of these uses the same trick as this patch: neutralise a branch or a
call by overwriting it with `0x90`/`0xEB`. None are anywhere near the input code,
so the two patches compose cleanly. The patcher's `compatable_modhook/` subfolder
is an unrelated `DFEngine.dll` modhook for loading loose files.

Applied to the exe analysed here: *Fix Linux Exit*, *Skip Intro Videos*, *Stop
Telemetry*, *UI: Full Scaling — Standard Size*. Not applied: FOV Increase, Bypass
Hacking, Skip Cutscenes, High Core Count Fix, Energy Cell Regen.
