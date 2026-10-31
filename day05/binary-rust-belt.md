# ⚙️ Rust Belt

| | |
|---|---|
| **Day** | 05 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-05-rust-runtime-shapes` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | Day-5 solver not preserved; the same logic lives in the consolidated [`solvers/day09/b9.py`](../solvers/day09/b9.py) (`d04`/`d05` handler) |

## Prompt
> Rust leaves its own fingerprints: mangled symbols with a distinct accent, panic strings that confess, trait objects hiding in plain sight. Learn the accent.

## TL;DR
Day-4 bundle plus a new `d05` Rust ELF: 40 questions over five units (`d01`–`d05`, eight each). The Rust
binary hides its config in an HCFG record like the others, but it also carries **decoy HCFG blocks**, so
"the first `HCFG` hit" is no longer safe: decode every block and keep the one that yields a complete JSON
config. The timed modes introduced the parallel-submit pattern the lane used for the rest of the first week.

## Artifact
A 1.9 MB WinZip-AES ZIP (password `infected`) with six files: `d01`/`d02` C ELFs, the `d03` .NET DLL plus
its `runtimeconfig.json`, the `d04` Go ELF and the new `d05` Rust ELF (both large x86-64 ELFs). 40 answer ids; `d05` has the same field shape as `d04` (SHA-256, `architecture`, `format`
and the HCFG config fields).

## Solution
The [Day-4 solver](../day04/binary-go-fish.md) was reused almost verbatim; the changes were all in HCFG
handling.

1. Scan the whole file for every `HCFG` occurrence, not just the first.
2. For each one, read key (+5) and LE16 length (+6), XOR-decode from +12, and parse the **leading** JSON
   object with `json.JSONDecoder().raw_decode`. The length field can cut or overrun the object, so
   `raw_decode` is safer than `json.loads` on the whole slice.
3. The Rust binary had three HCFG blocks. Keep the block whose JSON is a dict with `campaign`, `domain`
   and `mutex`, preferring the one with the most keys:

```python
def best(blocks):
    return max(blocks, key=lambda d: (all(k in d["cfg"] for k in ("campaign", "domain", "mutex")),
                                      len(d["cfg"])))
```

4. `config_crc32_hex` = `0x%08x` of the CRC32 of the decoded JSON bytes (the slice that `raw_decode`
   consumed).
5. `architecture` = `x86-64`, `format` = `elf`, as for the Go unit.

In single solve (untimed), each field got a short candidate list and the solver banked them one field at a
time. All 40 banked.

## Time Trial & Mastery
Time trial had **40 questions and a window of about 7 seconds**, and banking did not carry over between
attempts. The winning layout was to decode the live artifact and submit **in parallel** with a
`ThreadPoolExecutor`: every candidate of every field as its own single-answer submit (59 jobs), so the right
candidate banks and the wrong ones are harmless. That finished in about 2.4 s.

Mastery had 80 answers over two sets (`set1.`/`set2.`, from deliveries 0 and 1, fetched in parallel). It
used a hybrid layout: large JSON-valued answers as singles, the few multi-candidate fields brute-forced in
parallel, and the deterministic short fields in chunks of 12, with 20 workers. One diagnostic run left
`set2.d05_analysis_config_crc32_hex` unbanked even though the same formula had banked for set 1, which
looked like a dropped submit under load. The final hybrid run was CORRECT in about 2.6 s.

## Lessons / gotchas
- Expect decoy HCFG blocks from now on. Decode them all and pick the one with a complete config.
- Parse the JSON with `raw_decode`; trust the object, not the length field.
- In a short timed window, parallel single-answer submits are a cheap way to cover enum-like fields.
  Banking makes wrong guesses free, and only the right one counts.
- Watch the rate limiter: very high concurrency causes cascades of `rate_limited` that look like failures.
