# 👶 Eighty-Five Alive

| | |
|---|---|
| **Day** | 23 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-23` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day23_quick/warm23x.py`](../solvers/day23_quick/warm23x.py) (= `warm21.py` + [`a85_snippet.py`](../solvers/day23_quick/a85_snippet.py)) |

## Prompt
> The alphabet got bigger. Adobe might recognize the neighbors.

## TL;DR
**Adobe Ascii85**: base 85, so the alphabet is bigger than Base64's, and the `<~ … ~>` framing comes from Adobe
PostScript/PDF. Decode with `base64.a85decode(s, adobe=True)`.

## Artifact
- Single Solve and Time Trial: `blob.txt`, one `<~…~>`-framed Ascii85 block.
- Mastery: 113 sets (`blob-01.txt`…`blob-113.txt`, all in the default ZIP). Row 23 is an Adobe Ascii85 fragment.
  A real row 23 from the Day-26 bundle: `<~@psG#~>` → `cast`.

## Solution
`a85_candidates()` tries four base-85 dialects and returns `(label, bytes)` pairs:

| label | dialect | check |
|---|---|---|
| `a85` | Adobe Ascii85 | text starts `<~` and ends `~>`, `a85decode(adobe=True)` |
| `a85b` | bare Ascii85 | characters `!`..`u` (+ `z`, `y`) |
| `b85` | RFC 1924 / Python `b85` | digits, letters and the RFC 1924 punctuation set |
| `z85` | ZeroMQ Z85 | custom alphabet, 5 chars → 4 bytes big-endian |

`layers()` and `line_decode_l()` are wrapped, so the outputs also go through `inflate()` and `u16()`. An Adobe-framed blob
is treated as unambiguous: the wrapper returns only the base-85 decodes and skips the ROT/Atbash/Base64 candidates. For
an Adobe-framed row, its decode is ranked first.

## Time Trial & Mastery
All modes were regular untimed attempts. Single was CORRECT, then Time Trial was CORRECT (256 unique attempts). Mastery
was CORRECT for all 113 sets, with 3.2 s of compute.

## Lessons / gotchas
- The solver is named `warm23x.py` because `warm23.py` could no longer be created in that folder. Rename, copy and
  touch all failed with EPERM, a Windows handle left behind by an editor rename. If a solver file disappears after an
  edit, use a new name.
- `warm21.py` called `main()` at module level with no `__main__` guard, so importing it would start and submit a
  challenge. `warm23x.py` was therefore built by concatenating source (Day-21 code minus its last line, plus the
  snippet), not by importing. From Day 24 on, every solver has a guard and later days chain by import.
- The framing (`<~ ~>`) is the strongest signal available. Treat it as decisive, or a ROT47 of the row can out-score the
  real decode. That is exactly what happened on [Day 26](../day26/warmups-food-for-thought.md).
