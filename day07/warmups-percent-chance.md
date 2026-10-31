# 👶 Percent Chance

| | |
|---|---|
| **Day** | 07 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-07` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | Not preserved. All three modes were solved by the scheduled release-morning run; its scripts and notes were not kept. |

## Prompt
> My address bar is having a moment.

## TL;DR
URL percent-encoding: every byte is written as `%XX` (`%4e%69%63%65` = `Nice`), and `urllib.parse.unquote()` reverses
it. The interactive session that picked up Day 7 found all three warmup modes already marked solved, so this writeup
reconstructs the technique from the prompt and from how the codec showed up in later Mastery bundles. No first-hand
solve log survives.

## Artifact
- Single Solve and Time Trial: one `blob.txt`. The day's own artifact was not saved. From the prompt and the later
  bundles, it was the usual sentence in `%XX` form.
- Mastery: 33 sets (catalog `ranked_set_count`). By the pattern seen every other day (Day N's Mastery blob has N rows,
  row k in Day k's codec), each blob had 7 `NN\t` rows with row 07 in percent-encoding. A real row 07 from the Day-9
  bundle: `07	%6d%65%20%4d%61%73%74%65%72%3a%20%64` → `me Master: d`.

## Solution
```python
import urllib.parse
text = urllib.parse.unquote(blob)          # %XX -> byte -> UTF-8
slug = re.search(r"Game Master: ([a-z]+-[a-z]+-[a-z]+-\d{2})", text).group(1)
```
For Mastery rows, the later solvers detect the codec strictly before decoding, so a row is treated as URL-encoded only
when it is nothing but `%XX` triplets:
```python
if re.fullmatch(r"(%[0-9A-Fa-f]{2})+", f): add("url", urllib.parse.unquote(f))
```
(from [`day10_quick/warm10.py`](../solvers/day10_quick/warm10.py)).

## Time Trial & Mastery
No notes from the solving run survive. The final catalog lists ranked budgets of 20 s (Time Trial) and 50 s (Mastery,
33 sets). The interactive session that afternoon confirmed all three modes `solved=True` through the Game Master list.

## Lessons / gotchas
- The codec came back on [Day 30](../day30/warmups-percent-percent.md) ("It happened twice"). A single `unquote` there
  leaves `%XX` text behind, so a one-pass URL decoder must not be accepted when its output still contains `%XX`.
- Keep solver scripts and a short note even for days that look trivial. This day is the one gap in our record.
