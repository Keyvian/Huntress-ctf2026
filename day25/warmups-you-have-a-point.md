# 👶 You Have a Point

| | |
|---|---|
| **Day** | 25 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-25` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day25_quick/warm25.py`](../solvers/day25_quick/warm25.py) (imports `warm24`) |

## Prompt
> Every character has a point. A code point, anyway.

## TL;DR
Unicode code-point notation: `U+004E U+0069 U+0063 …`, one token per character, separated by whitespace. `chr(int(x, 16))`
on each token, then join. Every variant (Single, Time Trial, all 123 Mastery blobs) used plain `U+XXXX` with a single
layer.

## Artifact
- Single Solve and Time Trial: `blob.txt`, `U+XXXX` tokens.
- Mastery: 123 sets (`blob-01.txt`…`blob-123.txt`, default ZIP), 25 mixed-codec rows; row 25 holds code points.

## Solution
`cp_candidates()` accepts any **one** spelling for the whole blob or row (every token must match the same form):

| label | form |
|---|---|
| `cpU` | `U+004E`, `u+4e` |
| `cpbs` | `N`, `\U0001F600` |
| `cpx` | `\x4E` |
| `cphtmlx` / `cphtml` | `&#x4E;` / `&#78;` |
| `cp0x` | `0x4E` |
| `cpdec` | bare decimals (kept last; the older `dec` codec owns those rows) |

It also handles glued forms without separators (`U+004EU+0069…`). Surrogates and values ≥ 0x110000 are rejected.

```python
for lab, rx in CP_FORMS:
    vals = [int(rx.match(x).group(1), 10 if lab in ("cpdec", "cphtml") else 16) for x in toks]  # all must match
    s = "".join(chr(v) for v in vals)
```
This was the first solver built **without copying source**. `warm25.py` imports `warm24` (now `__main__`-guarded) and
monkeypatches `warm24.layers`, `warm24.line_decode_l` and `warm24.solve_blob`. Because `main()`, `learn_positions()` and
the template search look these up through module globals, the new codec applies everywhere. An explicit
`U+`/`\u`/`&#` blob is unambiguous, so the other candidates are skipped.

## Time Trial & Mastery
The Day-25 listing advertised ranked budgets for optional `run_for_time` play (warmups: 30 s Time Trial, 140 s
Mastery). Plain `start` still gave regular untimed attempts, and those scored. Single, Time Trial (256 unique
attempts) and Mastery (123/123, 2.5 s compute) were all CORRECT on the first submit.

## Lessons / gotchas
- Monkeypatching an imported, guarded module is the clean way to grow a decoder over many days. Each day adds one small
  file, and earlier days' behavior doesn't change.
- Let codecs that overlap step aside: bare decimal "code points" and the Day-5 decimal-bytes codec read the same text,
  so the older label keeps its rank.
