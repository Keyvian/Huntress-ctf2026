# 👶 Rotten Base

| | |
|---|---|
| **Day** | 29 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-29` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day29_quick/warm29.py`](../solvers/day29_quick/warm29.py) (imports `warm28`) · [`warm_audit26.py`](../solvers/day29_quick/warm_audit26.py) |

## Prompt
> Sixty-four invited thirteen over. Things got scrambled.

## TL;DR
Base64 text put through **ROT13** afterwards. ROT13 changes letters only, so digits, `+`, `/` and `=` survive. To decode,
ROT13 the text back, then Base64-decode: `b64decode(rot13(s))`. The existing layer search already found that two-step
path for Single and Time Trial. Following the Day-28 lesson, the Mastery row decoder was written and tested on one blob
**before** the full run.

## Artifact
- Single Solve and Time Trial: one "rotten" Base64 string.
- Mastery: 143 sets, **29 rows**. Row 29 is ROT13'd Base64, e.g. `oP03At==` → `bC03Ng==` → `l-76`.

## Solution
```python
def rot13b64(t):
    h = re.sub(r"\s+", "", t)
    if len(h) < 2 or not re.fullmatch(r"[A-Za-z0-9+/_\-]+=*", h): return None
    r = codecs.decode(h, "rot13").replace("-", "+").replace("_", "/")
    r += "=" * (-len(r.rstrip("=")) % 4) if "=" not in r else ""
    s = base64.b64decode(r, validate=True).decode("utf-8")          # any failure -> None
    return s if s and all(c.isprintable() or c in "\r\n\t" for c in s) else None

warm26.STRONG_LABELS.add("r13b64")
```
Same pattern as [Day 28](../day28/warmups-back-in-sixteen.md): import the previous day, put the new decoder in front of
`layers()`, add a strong row label, and monkeypatch both into `warm24`.

## Time Trial & Mastery
All modes were regular untimed attempts. Single and Time Trial (256 unique attempts) were CORRECT. Mastery: one blob was
tested first (0.6 s), then all 143 locally. Checks before the one submit: `warm_audit26.py` (0 inexact lines, all slug
words real, "odd structure" only flagging the 29 rows) and an independent check that every slug ends with the row-29
decode (0 mismatches). CORRECT, 143/143.

## Lessons / gotchas
- A chained codec ("then") needs its own strict row decoder. A breadth-first search over single layers finds it on a long
  blob but is too slow and too ambiguous on a 6–8 character fragment.
- Validate Base64 strictly (`validate=True`, exact padding). With loose decoding, the ROT13'd text would also "decode"
  to garbage as plain Base64.
