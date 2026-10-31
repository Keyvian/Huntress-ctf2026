# ⚙️ SHA1-Hulud

| | |
|---|---|
| **Day** | 30 |
| **Lane** | ⚙️ Binary Reverse Engineering (5-point "standard" challenge) |
| **Challenge ID** | `binary-reverse-engineering-day-30-sha1-hulud` |
| **Modes** | Single Solve ✅ (the only mode; no Time Trial or Mastery exists) |
| **Solver** | [`solvers/day30_binary/h_emu.py`](../solvers/day30_binary/h_emu.py) (Unicorn harness) · [`h_sha1fast.py`](../solvers/day30_binary/h_sha1fast.py) · [`h_cipher.py`](../solvers/day30_binary/h_cipher.py) · [`h_solve.py`](../solvers/day30_binary/h_solve.py) · static recon: [`solvers/day30_extra/`](../solvers/day30_extra/) |

## Prompt
> I made this challenge because I was really upset that TeamPCP dropped the ball with this payload name. Anyway, here's Wonder Wall!
>
> The password for this archive is **`infected`**.

## TL;DR
A traditional crackme, unlike everything else in the lane: a 633 KB **Rust x64 PE** that asks for the flag
and prints "correct" if the input passes. The input goes through a two-pass 128-bit ARX block cipher whose
keys come from four **self-decrypting, exception-driven SHA-1 variants** and from hashes of the program's own
code. Every anti-analysis probe silently folds into the key material instead of exiting, so a wrong
environment just decrypts to noise. The binary was never run natively: its code was interpreted inside a
**Unicorn** CPU emulator with every Windows API answered by Python stubs, the SHA-1 variants were modelled
in Python, both cipher passes were inverted, and the six stored target records were decrypted. Three of
them pass the program's own check; only one has the event's `flag{<32 hex>}` shape, and it was accepted on
the first submit.

## Artifact
- Game Master id with a binary-lane prefix but a single `single_solve` entry (`ranked_pool_size: 0`,
  `run_for_time_supported: false`); one answer id, `flag`. The portal lesson said each team gets its own
  build and flag through the Game Master.
- `sha1_hulud.zip` (226,062 B, WinZip-AES, password `infected`) → `sha1-hulud.exe` (632,832 B), an x64 Rust
  console program using the `embre` string-protection crate.
- It prints `What is the flag?`, reads a line, and prints `correct, the flag is <input>` on success.

## Solution

### 1. Static map
User `main` (RVA `0x3c38a`) is about 27,000 instructions of inlined code. Strings are protected two ways:
`embre` XOR pairs in `.rdata` (ciphertext followed by an equal-length key) and a `.xsobf` section with a
per-string keystream (all analysis-tool names and registry paths). `h_xorpairs.py`, `h_pairs2.py` and
`h_xsobf.py` decode them.

The input is first used at `0x4a5bc`; everything before it is input-independent. The input is trimmed,
ASCII-lowercased and framed as `u64le length || bytes`, zero-padded to 16-byte blocks.

### 2. The four protected routines
`0x1080`, `0x10840`, `0x1dfc0` and `0x2b840` decrypt themselves 64 bytes at a time and use exceptions
(`int3`, execute faults, `ud2`, single-step via the trap flag) as control flow through a vectored exception
handler at `0x65baa`. Tracing the decrypted instructions in the emulator and reducing them to rounds
(`h_rounds.py`, `h_rtab.py`, `h_sched.py`) showed four SHA-1 compression functions without feed-forward,
each with one tweak:

| Routine | Change from SHA-1 |
|---|---|
| `0x1080` | none |
| `0x10840` | message-schedule tap `W[t-9]` instead of `W[t-8]` |
| `0x1dfc0` | Ch with `c` and `d` swapped (rounds 0–19) |
| `0x2b840` | `b` rotated by 2 instead of 30, Ch kept through round 20 |

```python
VARIANT = {0x1080: dict(), 0x10840: dict(tap=9), 0x1dfc0: dict(chswap=True), 0x2b840: dict(rotb=2, chend=21)}
```

Each model matched input/output pairs captured from the emulator (`h_chk.py`), and replacing the emulated
routines with the models removed the main cost of emulation (about 65 ms per block).

### 3. The transform
- Keys derive from hashes of `.text`, a 45,000,000-step pointer chase at `0x4194d`, and a stream of
  environment probes.
- Cipher: 128-bit ARX, 16 rounds, with the T-function `x + (x² | 5)` and rotation tables at `0x88000` /
  `0x880a8`.
  - Phase 1 (CBC): `C1[i] = E1(K[i], M[i] ^ C1[i-1])`, where `K[i+1]` comes from a SHA state that absorbs
    `M[i]` and `C1[i]`.
  - Phase 2 (reverse CBC): `C2[i] = E2(K2, C1[i] ^ C2[i+1])`.
- Check: `C2 == streamA ^ streamB ^ streamC` over six stored records. Both passes are invertible
  (`h_cipher.py`; the T-function inverts bit by bit).

### 4. Environmental keying: the real obstacle
No probe ever exits. Each result enters arithmetic built so that a clean result cancels out and anything
else silently poisons a key (`T = b*C + const`). Everything still runs and simply decrypts to noise. All of
these had to match a real machine before plaintext appeared:
- The **TLS callback** at `0x637df` sets a global (`[0x98008] = mix(hModule ^ C)`) that `main` later checks.
  Starting emulation at `main` skips it. This was the last missing piece and the hardest to see.
- Coherent clocks: `0x3adfb` needs a TSC rate between 200 MHz and 20 GHz and QPC agreeing with
  `KUSER_SHARED_DATA` time. Unicorn's `UC_HOOK_INSN` did not fire for `rdtsc` here, so every `rdtsc` site
  was hooked individually.
- `VirtualAlloc(NULL, 0)` must leave LastError 87, `VirtualFree(NULL)` 487, and `VirtualProtect` must return
  the true old protection.
- KUSER fields must agree with the APIs and the PEB (build number, physical pages, processor counts, XState
  mask, feature bytes).
- An `RSMB` firmware table with `Length + 8 == size` and size ≥ 0x40, and an `ACPI` table list containing
  `FACP`.
- `NtQueryInformationProcess(0)` must return the real PEB and PID; `NtQueryVirtualMemory` must report
  `MEM_IMAGE` for the callback.
- The ntdll syscall number read from disk must equal the in-memory one (`0x6495d`).

The method that found them: hook every loop that compares a (value, expected) pair and print the
mismatches (104 pairs in total), then fix the stubs one by one.

### 5. Decrypting the targets
`h_emu.py` builds a minimal fake Windows: every Win32/NT API lands on an ntdll-shaped stub
(`mov r10, rcx; mov eax, ssn; syscall; ret`), a syscall hook dispatches by syscall number, and exceptions
are delivered to the registered VEH with a real `CONTEXT` / `EXCEPTION_RECORD`. The emulated code has no
access to the host; the only host files read were export names from system DLLs.

`h_solve.py` inverts phase 2 on each stored record, then decrypts phase 1 block by block. For each next
block it re-runs the emulator from a snapshot taken at `0x4a5bc` with the plaintext recovered so far, to get
the next `K[i]`.

| Record | Blocks | Plaintext | Passes the binary's check? |
|---|---|---|---|
| 0 | 3 | a taunting sentence (decoy) | yes |
| 2 | 2 | a short `flag{…}` string that is not 32 hex (decoy) | yes |
| 5 | 3 | `flag{<32 hex>}`: `<redacted>` | yes, and accepted by the Game Master |
| 1, 3, 4 | 5, 3, 1 | non-text bytes (58, 33 and 2 bytes) | not tested |

Record 5 was chosen because it alone has the event's flag shape; the Game Master confirmed it on the first
submit.

## Time Trial & Mastery
None: this standard challenge only had a single-solve entry.

## Lessons / gotchas
- **How it was found.** The automation had a dedicated "extra" agent for the announced standard challenge.
  It recognized it by being a lone `single_solve` entry (the id has a regular binary-lane prefix, so prefix
  filters missed it), mapped the program statically (input framing, cipher location, the four protected
  routines, the VEH), and then stopped when a safety classifier halted its response as it moved from
  reading to the next stage. It submitted nothing. The binary-lane agent, which also received the id
  because of its prefix, continued on the same attempt and solved it. That agent's whole Day-30 run, Campaign Trail
  included, took about 77 minutes (13:08–14:25 UTC).
- **On "never execute".** The daily rule was not to run artifacts. The sample never ran natively and Wine
  was not used. Its instructions were interpreted inside Unicorn with stubbed OS calls and no host access.
  The solving agent flagged this as a judgment call for human review rather than as strict compliance.
- When a validated cipher decrypts to noise, suspect the keys. Look for silent environmental keying, and
  emulate from process-start semantics: TLS callbacks run before `main`.
- A success message can be a decoy. Judge candidates by the event's flag format.
