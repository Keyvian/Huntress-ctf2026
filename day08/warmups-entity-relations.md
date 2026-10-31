# 👶 Entity Relations

| | |
|---|---|
| **Day** | 08 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-08` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | Homebase-only `~/d8/w8.py` (= Day 6's `w6.py` plus an `html.unescape` candidate); not copied into this repo. |

## Prompt
> The browser understands. Do you?

## TL;DR
HTML numeric character references: `&#78;&#105;&#99;&#101;…` = `Nice…`. `html.unescape()` decodes them. The scheduled
morning run solved Single Solve. The afternoon session added `html.unescape` to the Day-6 per-row solver for the timed
modes. The Mastery bundle was back to **one ZIP** of blobs.

## Artifact
- Single Solve: `blob.txt`, 620 bytes, one `&#NN;` entity per character.
- Time Trial: the same form. It started with `deadline: None`, so it was untimed in practice.
- Mastery: 38 sets. The default artifact is one ZIP (20,293 bytes) of `blob-01.txt`…`blob-38.txt`. `delivery≥1` returns
  `{"error":"invalid_delivery"}`. Each blob is the mixed-codec `NN\t` list, starting `01\tTmljZSB3b3JrIGRl…`, with row 08
  in HTML entities.

## Solution
`w8.py` was built by patching `w6.py` with `sed`: import `html`, and add one candidate to the per-row generator.

```python
out = [p] if re.search(r"[A-Za-z]", p) else []
try:
    h = html.unescape(p)
    if h != p: out.append(h)
except: pass
```
The rest is the Day-6 pipeline: score candidates per row, concatenate, regex the slug after `Master:`.

## Time Trial & Mastery
- Time Trial: CORRECT in 3.1 s.
- Mastery: the first run returned `invalid_answers`. `w6.py` fetched one delivery per set (the Days 4–6 layout), and
  37 of 38 fetches came back `invalid_delivery`. Inspecting the default artifact showed the 38-member ZIP. We read
  `blob-%02d.txt` for each `setN.message` from that one ZIP, decoded all 38 and got CORRECT on one submit.

## Lessons / gotchas
- The delivery layout changes without notice: one ZIP (Days 1–3), one delivery per set (Days 4–6), one ZIP again from
  Day 8. Read `questions[].artifact` and look at the default artifact before fetching per delivery.
- `invalid_answers` means at least one answer was empty or missing. It does not mean a wrong slug. Check that every
  `answer_id` has a value before submitting.
