# 👶 Monkey Business

| | |
|---|---|
| **Day** | 27 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-27` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day27_quick/warm26.py`](../solvers/day27_quick/warm26.py) (Day-26 solver, unchanged) · [`unzipall.py`](../solvers/day27_quick/unzipall.py) · [`warm_audit26.py`](../solvers/day27_quick/warm_audit26.py) |

## Prompt
> Ook. Ook? Ook! Someone seems chatty.

## TL;DR
**Ook!**, the orangutan dialect of Brainfuck. Each pair of `Ook.`/`Ook?`/`Ook!` tokens is one Brainfuck command. The blob is
a 34 KB Ook! program whose output is the sentence. Day 26's `warm26.py` already translated Ook! to Brainfuck, so there
was **no code change**. The day's work was the pre-submit audit.

## Artifact
- Single Solve and Time Trial: one Ook! program (≈34 KB of `Ook. Ook? Ook!` triplets).
- Mastery: 133 sets, now **27 rows** per blob. The 26 Day-26 codecs plus **row 27, an Ook! program printing the slug
  tail**, as the Day-26 note had predicted.

## Solution
```python
OOK_MAP = {"..": "+", "!!": "-", ".?": ">", "?.": "<", "!.": ".", ".!": ",", "!?": "[", "?!": "]"}
toks  = re.findall(r"Ook[.?!]", text, re.I)
pairs = [toks[i][3] + toks[i + 1][3] for i in range(0, len(toks), 2)]
out   = bf_run("".join(OOK_MAP[p] for p in pairs))     # Day-26 interpreter (8-bit cells, step cap)
```
Short Ook (bare `.?!` pairs without the word) goes through the same map. Ook! counts as a strict-syntax label (`ook`), so
in Mastery it outranks the letter-cipher candidates on row 27.

## Time Trial & Mastery
All modes were regular untimed attempts. Single Solve and Time Trial (256 unique attempts) were CORRECT. Before the one
Mastery submit we ran:
1. `unzipall.py` to extract the 133 blobs,
2. `warm26.py local <blobs>` to decode offline,
3. `warm_audit26.py local.txt blobs`: 0 inexact template lines, and all slug words appearing only once were real words,
4. a check that the offline slugs matched a dry run's (`diff`, SAME).
Then one submit: CORRECT, 133/133. The whole check took under 10 s.

## Lessons / gotchas
- The bundle grows by one row a day, in a predictable order, so the next day's row count and position can be predicted
  and verified (`len(rows) == day`, BF row index).
- The audit-then-submit routine is cheap and turns a possible `incorrect` into a local fix before submitting.
