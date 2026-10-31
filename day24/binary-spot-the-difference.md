# ⚙️ Spot the Difference

| | |
|---|---|
| **Day** | 24 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-24-patch-diffing` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day24_binary/b24.py`](../solvers/day24_binary/b24.py) · [`inspect24.py`](../solvers/day24_binary/inspect24.py) |

## Prompt
> Two builds, one fix. Diff the vulnerable function against its corrected twin and pinpoint exactly what changed — then prove the old one was really broken.

## TL;DR
Day-23 contract (276 questions) plus a 12-question `d24` unit: **two Scala jars**, a vulnerable build and a
corrected build. The questions ask only for hashes, formats and the HCFG config (stored as a Base64 string
constant), with one twist: the shared `config_*` answers are valid only if **both jars decode to the same
config bytes**. The question spelled out the lookup rule (constant-pool UTF-8 constants of at least 80
Base64 characters, first CRC32-valid record), and the solver implemented it with a small constant-pool
walker. The actual patch was looked at with `javap` but is not graded.

## Artifact
WinZip-AES ZIP (password `infected`). New members in ZIP order: `d24--sample-vulnerable.jar` (4,054 B) and
`d24--sample-corrected.jar` (4,422 B). Manifest: `Created-By: Huntress deterministic Scala factory`,
`Main-Class: Day24Vulnerable000` / `Day24Corrected000`. Each jar has a `<Main>.class` forwarder and a
`<Main>$.class` Scala module object with `encodedConfig`, `decodeConfig`, `score` and `main`.

Fields: `d24_artifact_sha256_{1,2}`, `d24_analysis_{corrected,vulnerable}_format` (enum:
`elf`/`pe`/`pe_cli`/`jar`/`wasm`/`neko_bytecode`), `d24_analysis_config_{campaign,domain,mutex,url}` ("decode
BOTH d24-- role members and require their config objects to be byte-for-byte equal before using the common
value") and `d24_analysis_corrected_config_{campaign,domain,mutex,url}` (corrected jar alone). No CRC,
version, XOR-key or machine fields.

## Solution
1. Hash the members in ZIP order (vulnerable is member 1). Assign roles by basename suffix
   (`vulnerable.jar`, `corrected.jar`). Both formats are `jar`.
2. For every `.class` in each jar, walk the constant pool and collect the `CONSTANT_Utf8` entries:

```python
def class_cp_utf8(cb):
    p = 8; cpc = struct.unpack(">H", cb[p:p + 2])[0]; p += 2
    out, i = [], 1
    while i < cpc:
        t = cb[p]; p += 1
        if t == 1:   l = struct.unpack(">H", cb[p:p + 2])[0]; p += 2; out.append(cb[p:p + l]); p += l
        elif t in (3, 4): p += 4
        elif t in (5, 6): p += 8; i += 1          # long/double take two slots
        elif t in (7, 8, 16, 19, 20): p += 2
        elif t in (9, 10, 11, 12, 17, 18): p += 4
        elif t == 15: p += 3
        i += 1
    return out
```

3. Keep constants that are at least 80 characters of the Base64 alphabet, decode them, and accept the
   **first CRC32-valid HCFG record** (same 12-byte header as always). It is the `encodedConfig` literal of
   the `<Main>$` class: 508–552 characters, payload 368–400 bytes, a different key per variant.
4. Compare the two decoded payloads byte for byte. They were equal in all ten variants seen, so
   `config_*` and `corrected_config_*` have the same values. A mismatch would be flagged in the
   diagnostics with the vulnerable record as fallback; that path never ran.

The older `SENG` regex would also have found the constant, but the constant-pool walk is what the question
specifies.

**The diff, for the record** (`javap`, variant 000): the vulnerable `score(s)` is
`if (augmentString(s).nonEmpty) s.charAt(0) else -1`, which throws a `NullPointerException` on a null input;
the corrected one is `Option(s).filter(nonEmpty).map(_.charAt(0)).getOrElse(-1)`, with three
`$anonfun$score$N` lambdas added. No question asks about it.

## Time Trial & Mastery
`deadline: None` again; no rate limiting.

| Mode | Questions | Time used |
|---|---|---|
| single_solve | 288 | untimed, one submit |
| time_trial | 288 | 5.9 s end to end (gather 4.7 s) |
| mastery | 2304 (**8 sets** × 288) | 27.4 s end to end (gather 24.1 s, eight parallel deliveries) |

Downloading the deliveries now dominated the run time (eight deliveries of about 36 MB).

## Lessons / gotchas
- When the question specifies a lookup rule (minimum length, alphabet, "first CRC32-valid"), implement
  that rule literally even if a simpler regex happens to work.
- "Byte-for-byte equal" means comparing the decoded payloads, not the parsed JSON objects.
- Patch-diffing prompts do not mean patch-diffing questions; check the contract first.
