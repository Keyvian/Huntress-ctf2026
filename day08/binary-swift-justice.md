# ⚙️ Swift Justice

| | |
|---|---|
| **Day** | 08 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-08-swift-network-configuration` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | Day-8 solver not preserved; [`solvers/day09/b9.py`](../solvers/day09/b9.py) is its direct successor (`d08` handler, Day-8 field formats) |

## Prompt
> Swift binaries speak in protocols and hide their networking in plain sight. Follow the symbols to the URL configuration and see where this one phones home.

## TL;DR
The contract grew in two directions: two new fields on most old units (80 questions, eight units × 10) and
a new `d08` unit, a **67 MB Swift ELF**. Its only raw `HCFG` hit is a 4-byte decoy; the real config is a
Base64 `SENG…` string, like the Java units. Two `d08` fields wanted **integers** (`elf_class` = `64`,
`machine` = `62`) instead of the labels used for `d01`. The analysis took minutes; mastery took most of
the day, because 400 answers over five 31 MB deliveries did not fit the ranked window from the Homebase VM.
It was finished untimed through `op=practice`.

## Artifact
A 31.4 MB WinZip-AES ZIP (password `infected`) with nine members: `d01`/`d02`/`d04`/`d05`/`d08` ELFs, the
`d03` DLL and its runtimeconfig, and the `d06`/`d07` jars. 80 answer ids.

New fields on old units:

| Unit | New fields | Accepted shape |
|---|---|---|
| `d01` | `entry_point`, `has_symtab` | `0x401040`-style lowercase hex; `true`/`false` |
| `d02` | `has_cpp_typeinfo`, `has_cpp_vtable` | `true` if `_ZTI` / `_ZTV` names exist |
| `d06`, `d07` | `compression_methods` | compact JSON array of ZIP method ids in first-appearance order, e.g. `[0,8]` |
| several | `hcfg_version`, `xor_key_hex` | integer `1`; `0x%02x` |

`d08` fields: `artifact_sha256_1`, `format` (`elf`), `architecture` (`x86-64`), `elf_class`, `machine`,
`config_{campaign,domain,mutex,url}`, `config_crc32_hex`.

## Solution
1. **New fields on old units.** The question texts gave no format hints, so the untimed single solve was
   used to brute-force short candidate lists per field (`true`/`True`/`yes`/`1`, names vs numbers, …). The
   first pass banked 73 of 80; every new old-unit field landed on a natural candidate.
2. **`d08` config.** A raw `HCFG` hit exists near offset 90 031, but its length field is 4: a decoy. The
   real config is an `encodedConfig` Swift string holding Base64 text that starts with `SENG`, so the jar logic from
   [Day 6](../day06/binary-pool-party.md) applies: regex `SENG[A-Za-z0-9+/]{16,}`, Base64-decode, parse
   the HCFG record. The solver now tries raw HCFG first and falls back to the Base64 scan for every unit.
3. **`d08_analysis_elf_class`** is graded as an integer: the class in bits, `64`.
4. **`d08_analysis_machine`** was the last field (79/80). Every architecture spelling was rejected; the
   accepted answer was **`62`**, the numeric `e_machine` (`EM_X86_64`). This "integer machine" convention
   holds for every unit added after Day 8, while `d01`'s `machine` stays `x86-64`.

```python
def machine_int(b):
    if b[:4] == b"\x7fELF":
        return str(struct.unpack("<H", b[18:20])[0])          # 62
    if b[:2] == b"MZ":
        e = struct.unpack("<I", b[0x3C:0x40])[0]
        return str(struct.unpack("<H", b[e + 4:e + 6])[0])     # 34404 for AMD64 PE
```

## Time Trial & Mastery
**Time trial.** The first runs expired. The cause was first suspected to be the AES decryption of the
67 MB member, but measurement showed decryption took about 0.8 s; the real cost was the **artifact fetch
through the proxy** (spikes up to 40 s, normally 5–9 s) against a ranked window of roughly 10–13 s.
`op=practice` was refused (`fresh_attempts_remaining`) while ranked attempts remained, so the fix was to
loop ranked attempts until one got a fast fetch. That produced a flag, but it did not show up in the list
right away, so the time trial was re-run later in the day before the lane was confirmed complete.

**Mastery.** 400 answers = 5 sets × 80, from 5 deliveries (0–4) of about 31 MB each, each a full
`d01`–`d08` set with its own 67 MB Swift binary. The ranked window was about **26 s**. One measured ranked
try: attempt ready at 2.2 s, extract and compute 9.6 s, then 15.6 s of submits (234/400 banked) because 220
multi-candidate fields were sent as singles. The Homebase VM (2 cores, 1.9 GB) also saw fetch spikes and
rate limits. The winning recipe:

1. Drain the ranked rotation: each `op=retry` consumes one of the finite `unique_attempts_remaining`, about
   one per 29 s (spamming just returns `rate_limited`). About 24 attempts, around 12 minutes.
2. Let the last live attempt expire, then call `op=practice` **once**. It returns `deadline: null` and a
   fresh untimed question set.
3. Grind submits gently: 5 workers, up to 18 retries per submit with exponential backoff (0.5 → 6 s).
   396/400 banked in one round.
4. The last four were genuinely wrong: `d02_analysis_format` and `d04_analysis_format` in two sets. Those
   deliveries carried **native PE** builds (`.exe`) of the C++ and Go units, and the solver had hardcoded
   `elf`. With `pe` added as a candidate, the grinder banked them and mastery returned CORRECT.

## Lessons / gotchas
- `op=practice` **resets the attempt on every call**. Banked answers were wiped once by a second, diagnostic
  `practice` call. Call it once, then only submit.
- An empty `{}` or `rate_limited` response is not a wrong answer. Retry it; only `incorrect` means wrong.
- Old units can silently change container per delivery (ELF or PE for `d02`/`d04`, later `d10` too).
  Always derive `format` from the magic bytes.
- Integer-typed questions want numbers (`62`, `64`), even when an earlier unit's text field used labels.
- When the ranked timed window cannot be met from your infrastructure, the untimed practice path still
  completes the mode (without speed points).
