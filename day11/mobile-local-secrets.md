# 📱 Local Secrets

| | |
|---|---|
| **Day** | 11 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-11-local-secrets` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day11_quick/mob11.py`](../solvers/day11_quick/mob11.py) |

## Prompt
> Separate active credentials from decoys across generated local stores.

## TL;DR
The APK layout is unchanged. The puzzle used the **`xor`** codec, which first appeared on
[Day 4](../day04/mobile-pending-intent-relay.md): `{"codec":"xor","data":"<base64>","key":81}`. Base64-decode,
XOR each byte with 81 (`0x51`), and you get `ANS-<16 HEX>`. The dex's "locally stored synthetic credential"
(`client_secret=SECRET-…`) is the decoy the prompt warns about.

## Artifact
- Same members as Day 10. The dex story mentions `shared_preferences`, a `client_secret=SECRET-…` value and the
  `127.0.0.1:19090` backend.
- Mastery: 3 sets, one APK per set, fetched through the delivery fallback.

## Solution
**Theme.** Apps leave credentials in `SharedPreferences`, SQLite, files or hard-coded constants. Some of them are
live and some are stale or decoy. On a rooted device or from a backup (see Day 5) all of them are readable, so the
work is deciding which one the backend actually accepts. Here the "active credential" is whatever the puzzle
decodes to.

**Extraction.** `mob11.py` is `mob10.py` plus a forgiving XOR:

```python
def _key_bytes(key):                     # int, list, "81", "0x51", "a1b2…", or text
    if isinstance(key, int): return bytes([key & 0xff])
    ...
def xor_dec(data, key):
    kb = _key_bytes(key)
    for raw in _bytes(data):             # try hex, base64, base64url, raw
        s = bytes(c ^ kb[i % len(kb)] for i, c in enumerate(raw)).decode("latin1")
        if ANS.fullmatch(s.strip()):
            return s
```

The key repeats if it is longer than one byte. The solver also aborts if any answer doesn't match the ANS pattern,
so a partly wrong set is never submitted.

## Time Trial & Mastery
- All three modes passed on the first submit. Day 11 was the first time the three parallel agents
  (quick/script/binary), which share one GM token, hit `rate_limited` on their opening `op=list`/`status` calls.
  `gmx.GMX` added exponential backoff (1.5 s ×1.6, capped at 10 s). No timed mode was affected.

## Lessons / gotchas
- The dex secret (`SECRET-…`) looks like an answer but isn't one. Only the `ANS-` pattern counts.
- A tolerant key parser paid off later: Day 18 used `xor` again with key 20, and Day 23's single used key 81 again.
