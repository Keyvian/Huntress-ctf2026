# ⚙️ D-Day

| | |
|---|---|
| **Day** | 11 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-11-d-collection-planner` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day11_binary/b11.py`](../solvers/day11_binary/b11.py) · [`d11start.py`](../solvers/day11_binary/d11start.py) · [`peek11.py`](../solvers/day11_binary/peek11.py) |

## Prompt
> D templates generate code the way a printing press generates pages — fast, and everywhere. Trace the runtime's template expansions back to the collection config they built.

## TL;DR
Day-10 contract plus a 10-question `d11` unit: a D-language ELF whose config is a Base64 `SENG…` literal in
`.rodata`. The field shape is identical to the Nim unit (`d09`), so the whole change was widening the
`d09` handler to `("d09", "d11")`. The only operational issue was the three parallel agents sharing one
Game Master token, which hit `rate_limited` on the first calls; the solver gained exponential backoff.

## Artifact
WinZip-AES ZIP (password `infected`); mastery has 3 sets (default delivery = set 1, `delivery=1,2` = sets 2
and 3). The `d11` binary is an ldc/gdc-style ELF with D-mangled symbols such as
`_D4v00012decodeConfigFZAya` and `_D4v0008campaignFZAya`, and a `__minfo` section (D module info). Every
`d11` variant seen (000, 001, 007) was an ELF. Some `d02`/`d04`/`d10` variants in mastery set 2 were PE
`.exe` files, which the existing code handled.

## Solution
`d11` fields (graded CORRECT):

| Field | Value |
|---|---|
| `artifact_sha256_1` | SHA-256 of the binary |
| `format` / `architecture` / `machine` | `elf` / `x86-64` / `62` |
| `config_{campaign,domain,mutex,url}` | from the Base64 HCFG (`BR11-000`, `node-000.day11.example.invalid`, …) |
| `config_crc32_hex` | `0x%08x` of CRC32 over the decoded JSON |
| `hcfg_offset` | file offset of the start of the `SENG…` string, e.g. `368272` |

The decode is the [Day-9](../day09/binary-nimble.md) `b64_hcfg()` scan. `.rodata` also holds a plaintext
template fragment `,"campaign":"` and the words `decoy`, `sandbox` and `analysis`; none of them matter, the
only HCFG is the `SENG` literal.

Single solve again banked the new unit first (`accepted`, 100 remaining), then `d01`–`d10` → CORRECT.

## Time Trial & Mastery
One process each (`b11.py <ch> --save <dir> --submit --split-on-fail`):

| Mode | Questions | Time used / window |
|---|---|---|
| time_trial | 110 | 3.0 s / 30 s, one shot |
| mastery | 330 (3 × 110) | 5.2 s / 30 s, one shot |

`unique_attempts_remaining` was already 0 on the first timed starts, but both passed on the first attempt,
so the drain-and-practice route from [Day 8](../day08/binary-swift-justice.md) was not needed.

`gm_call()` wraps every Game Master call and backs off on `rate_limited` and on empty responses, because
the warmup/metadata/mobile, script and binary agents all start at 09:00 with the same token.

## Lessons / gotchas
- When a new unit has the same question shape as an old one, extend the handler tuple instead of writing
  new code.
- Prompts about "template expansions" were flavor: no question asked about D templates.
- Parallel agents sharing a token need backoff on the very first requests.
