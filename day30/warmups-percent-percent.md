# 👶 Percent Percent

| | |
|---|---|
| **Day** | 30 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-30` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day30_quick/warm30.py`](../solvers/day30_quick/warm30.py) (imports `warm29`) · check [`warm_check30.py`](../solvers/day30_quick/warm_check30.py) |

## Prompt
> That address bar problem? It happened twice.

## TL;DR
**Double** percent-encoding (the [Day 7](../day07/warmups-percent-chance.md) codec, twice). Every byte became `%XX`, then
the `%` signs were encoded again: `%25%36%33` → `%63` → `c`. Decode with `unquote(unquote(t))`. This was the first day
whose Single Solve the layer search **missed**: the one-pass `url` candidate left `%XX` text, and the run aborted with 0
answers (nothing was submitted).

## Artifact
- Single Solve and Time Trial: one `%25%XX%XX…` string.
- Mastery: 148 sets, **30 rows**; row 30 is double-percent-encoded.

## Solution
```python
def durl(t):
    h = re.sub(r"\s+", "", t)
    if "%25" not in h or not re.fullmatch(r"(?:[^%]|%[0-9A-Fa-f]{2})+", h): return None
    s = unquote(unquote(h, errors="strict"), errors="strict")
    if not s or re.search(r"%[0-9A-Fa-f]{2}", s) or not all(c.isprintable() or c in "\r\n\t" for c in s):
        return None
    return s
```
When `durl` matches, `warm30.py` returns **only** that candidate, both as a layer and as a row label (`durl`, added to
`STRONG_LABELS`). A once-decoded row is still `%XX` text and can never be the answer, so the plain `url` candidate is
dropped.

## Time Trial & Mastery
All modes were regular untimed attempts. After the fix, Single and Time Trial (256 unique attempts) were CORRECT.
`warm_check30.py` checked the Mastery bundle before the one submit: 148/148 exact template, row 30 and row 29 strict
decodes matching each slug's tail, no duplicate slugs, every word that appears only once a real word. CORRECT, 148/148.

## Lessons / gotchas
- A partial decode that looks plausible (`%63%65…` looks "decoded" next to `%25%36%33`) is a trap for any search that
  accepts the first change. Add a check that the output is fully decoded (no `%XX` left).
- Our solver's refusal to submit with missing answers (in place since Day 10) turned a decoding failure into a no-op
  rather than an `incorrect`.
