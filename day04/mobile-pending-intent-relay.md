# 📱 Pending Intent Relay

| | |
|---|---|
| **Day** | 04 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-04-pending-intent-relay` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/codex_day4_mobile/d4m_solve.py`](../solvers/codex_day4_mobile/d4m_solve.py) (+ [`d4m_inspect.py`](../solvers/codex_day4_mobile/d4m_inspect.py)) |

## Prompt
> Recover and redirect a mutable PendingIntent while preserving every earlier component check.

## TL;DR
Same APK and puzzle mechanic as Days 1–3, with one new codec, **`xor`**. The puzzle has an extra `key`
field. Base64-decode `data`, XOR every byte with `key` (one byte, e.g. 29), and the result is `ANS-<16 HEX>`. A
forked sub-agent solved all three modes in about 70 s, each in a single attempt.

## Artifact
- An APK with `assets/huntress_puzzle.json` = `{"schema":…,"day":4,"codec":"xor","data":"<base64>","key":<int>}`.
- `d4m_inspect.py` dumps the start response, the questions (`id`, `artifact`, `answer_format`) and the puzzle JSON.
  That inspect-first step was standard on new days.

## Solution
**Theme.** A `PendingIntent` lets another app fire an Intent *as you*. If it is created `FLAG_MUTABLE` around an
implicit or empty base Intent, whoever receives it can fill in the component and extras with
`Intent.fillIn()` and redirect it to the victim's private components with the victim's permissions. Android 12+
requires an explicit mutability flag for that reason, and the safe default is `FLAG_IMMUTABLE` with an explicit
component.

**Extraction.** The answer is still the puzzle value:

```python
if c == "xor":
    raw = base64.b64decode(d + "=" * (-len(d) % 4))
    return bytes(b ^ int(k) for b in raw).decode()     # -> "ANS-<16 HEX>"
```

The decoder keeps every earlier branch (`plain`, `reverse`, `base64`/`base64url`, `hex`, `rot13`, `gzip`), because
later mastery sets mix codecs from earlier days.

## Time Trial & Mastery
- `solve(mode)` runs `start` → fetch → decode → submit and retries the whole loop with `retry` when a submit is not
  `CORRECT`. Every mode passed on the first attempt. There were no rate-limit or timer problems.
- Mastery ids are `set1.answer`…; set K is fetched with `delivery=K-1`, falling back to the default artifact.

## Lessons / gotchas
- `xor` keys showed up again later as a plain int (Day 11's key 81, Day 18's key 20). From Day 11 on, the decoder
  accepts an int, a list, hex or a string as a repeating key.
- The PendingIntent story is flavor. The `127.0.0.1` backend in the dex is still a decoy.
