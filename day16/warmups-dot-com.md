# 👶 Dot Com

| | |
|---|---|
| **Day** | 16 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-16` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day16_quick/warm16.py`](../solvers/day16_quick/warm16.py) (+ [`st16.py`](../solvers/day16_quick/st16.py) attempt saver) |

## Prompt
> Sixteen little symbols are calling. Dot dot dot.

## TL;DR
Two layers. The blob is **Morse code** (one symbol per space-separated group), and the decoded symbols are only the 16
hex digits, so the Morse text is a **hex string** of the ASCII sentence. Decode Morse, then unhexlify. `warm16.py` adds
an ITU Morse table as a whole-blob layer and as Morse→hex/Base32/decimal row codecs.

## Artifact
- Single Solve and Time Trial: `blob.txt`, Morse with single spaces between characters.
- Mastery: 78 sets of mixed-codec `NN\t` blobs, 16 rows each. **Row 16 (the slug tail) is a Morse→hex fragment.** The other
  15 rows are the usual codecs (Base64, ROT13, hex, binary, …).

## Solution
```python
s = s.translate(str.maketrans("·•_–—−|", "..----/"))      # normalize dot/dash look-alikes
words = re.split(r"\s*/\s*|\s{3,}", line.strip())          # word gaps: "/", "|" or 3+ spaces
text  = " ".join("".join(MORSE.get(t, "?") for t in w.split()) for w in words)
# row codec: Morse that decodes to pure hex digits -> bytes
if re.fullmatch(r"([0-9A-Fa-f]{2})+", re.sub(r"\s+", "", text)):
    add("morsehex", binascii.unhexlify(re.sub(r"\s+", "", text)))
```
Morse has no case, so the final-line check became case-insensitive (`TEMPLATE` compiled with `re.I`). Whole-blob decoding
is Morse → hex string → next layer `unhexlify` → sentence.

## Time Trial & Mastery
**New Game Master behavior (2026-10-16):** the guidance now said *"Time Trial and Mastery are regular scored challenges
by default … Set `run_for_time:true` on start or retry to request a fresh timed Hall of Fame attempt."* A plain `start`
on `/time_trial` or `/mastery` returned `deadline: None`, with 256 unique attempts for warmups. `st16.py` saves
`start.json` plus the artifact so attempts can be decoded offline. Time Trial (untimed) was CORRECT. Mastery was CORRECT
for all 78 sets in ~2 s, once the `morsehex` row codec existed.

## Lessons / gotchas
- Check whether a day's new codec is itself a wrapper. Here Morse was the outer layer and hex the inner one, so a
  Morse-only decoder outputs hex digits that never match the template.
- From here on, regular untimed play counted for the score, so speed mostly mattered for the optional Hall of Fame.
  The exception was [Day 18](../day18/warmups-off-the-rails.md), whose warmup timed modes came back with real timers.
