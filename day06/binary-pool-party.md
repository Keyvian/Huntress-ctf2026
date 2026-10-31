# ⚙️ Pool Party

| | |
|---|---|
| **Day** | 06 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-06-java-bytecode-loader` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | Day-6 solver not preserved; the `d06` logic lives in [`solvers/day09/b9.py`](../solvers/day09/b9.py) (jar handler, `b64_hcfg`) |

## Prompt
> Every Java class file carries its own phone book: the constant pool. Names, methods, invocations — it's all in there. Dive in and take attendance.

## TL;DR
Day-5 bundle plus `d06`, a small Java `.jar`. Its config is not a raw HCFG record in the file: it is a
**Base64 string constant** in a class's constant pool, and the Base64 decodes to an HCFG record. Since
`base64("HCFG…")` always starts with `SENG`, a regex over the class bytes finds it instantly. The day also
added an integer `hcfg_version` field (header byte 4).

## Artifact
WinZip-AES ZIP (password `infected`), units `d01`–`d05` as before plus `d06--variant-000.jar`. 48 answer
ids (six units × eight). The jar's main class `Day06Variant000.class` has a `CONFIG` string field and the
methods `<init>`, `decodeConfig`, `campaign`, `evaluate` and `main`; `CONFIG` holds the Base64 text.

`d06` fields: `artifact_sha256_1`, `format`, `config_{campaign,domain,mutex,url}`, `config_crc32_hex`,
`hcfg_version`. Day 8 later adds `xor_key_hex` and `compression_methods` to this unit.

## Solution
1. Open the jar as a normal ZIP (it is not encrypted) and read the `.class` members.
2. Either walk the constant pool (tag 1 = `CONSTANT_Utf8`) and test each string, or simply regex the class
   bytes for the Base64 of `HCFG`:

```python
for m in re.finditer(rb"SENG[A-Za-z0-9+/]{16,}={0,2}", class_bytes):
    s = m.group(0)
    blob = base64.b64decode(s + b"=" * (-len(s) % 4))
    blocks = hcfg_blocks(blob)   # same parser as the native units
```

3. Decode the HCFG record exactly as for the native units (key at +5, LE16 length at +6, XOR'd JSON at
   +12) and pick the complete config with `best()` (see [Day 5](../day05/binary-rust-belt.md)).
4. `hcfg_version` = header byte 4 as a base-10 integer (`1`). It was graded as an integer field.
5. `format` = `jar`.

The `d05` Rust binary still carried a decoy HCFG block, which the `best()` selection already handled. The
`d03_analysis_format` question had also changed kind (it was now a `pattern` question rather than free
`exact_text`); `pe_cli` still matched.

## Time Trial & Mastery
Time trial: 48 questions in a window of about 7 s. A first hybrid attempt submitted only the first
candidate for each field and stalled at 30 remaining, because the format/architecture candidates of the
Go-vs-Rust units were ambiguous. Switching back to "every candidate as a parallel single submit" solved it.

Mastery: 96 questions over two sets in a similarly short window. Fields with several candidates were
brute-forced as parallel singles and single-candidate fields were chunked, with 14 workers. An earlier try
with 120 workers triggered a rate-limit cascade and failed.

## Lessons / gotchas
- Base64-wrapped HCFG records are recognisable by the `SENG` prefix. That one regex is reused for the
  Kotlin, Swift, Nim, D and Crystal units later.
- Treat `hcfg_version` as an integer answer (`1`), not `0x01`.
- More workers is not faster once the rate limiter kicks in. 14–30 workers was the useful range.
- Day 17 later adds `methods` (the main class's method names in order, as compact JSON) and
  `access_flags` (the class `access_flags` as an integer, `49` = `0x31`) for this unit.
