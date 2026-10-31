# 👶 Escape Room

| | |
|---|---|
| **Day** | 09 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-09` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day09/w9.py`](../solvers/day09/w9.py) (single blob) · [`solvers/day09/w9m.py`](../solvers/day09/w9m.py) (mixed-codec Mastery) |

## Prompt
> These characters would very much like to escape.

## TL;DR
JSON/JavaScript Unicode escapes: the blob is a quoted JSON string literal, `"Nice…"`, and `json.loads`
turns it back into the sentence. Day 9 was the first day solved end to end by the unattended morning agent working
from WSL. The Mastery blob grew to 9 rows, one codec per release day so far.

## Artifact
- Single Solve: solved minutes earlier by a first pass of the same scheduled run. Its blob was not logged.
- Time Trial: `blob.txt`, 650 bytes, starting `"Nice …`. `deadline: null` (untimed).
- Mastery: 43 sets, one ZIP of `blob-01.txt`…`blob-43.txt`, each with 9 rows. A real blob:
  ```
  01	TmljZSB3b3JrIGRl                     b64   -> "Nice work de"
  02	pbqvat guvf j                        rot13 -> "coding this w"
  03	61726d75702120546f20736f6c           hex   -> "armup! To sol"
  04	01110110 01100101 00101100 …         bin   -> "ve, submit t"
  05	104 105 115 32 101 120 97 99 116 …   dec   -> "his exact ans"
  06	167 145 162 040 164 157 040 …        oct   -> "wer to the Ga"
  07	%6d%65%20%4d%61%73%74%65%72%3a%20%64 url   -> "me Master: d"
  08	&#97;&#115;&#104;&#105;&#110;&#103;… html  -> "ashing-garden"
  09	"-wat…"          json  -> "-waterfall-18"
  ```

## Solution
`w9.py` repeatedly applies "un-escape" steps until nothing changes: JSON string literal → `json.loads`, `\uXXXX`/`\xXX`
→ `unicode_escape`, `&#…;` → `html.unescape`, `%XX` → `unquote`, then hex and Base64. It then takes the slug from the
final line. `w9m.py` decodes each `NN\t` row with structural detectors first (json, `\u`, url, html, 8-bit binary,
decimal or octal tokens, `0x`/`\x` tokens, hex, Base64, Base32), then ROT13 and plain text. It picks the best row by a
printable-letter score, with a small bonus for the structural codecs.

```python
best = max(cands(f), key=lambda kv: score(kv[1])
           + (0.3 if kv[0] not in ("rot13", "plain", "b64", "b32") else 0)
           + (0.15 if kv[0] == "b64" else 0))
```
A blob passes only if its decoded final line contains `submit this exact answer to the Game Master`. The script submits
only when 0 blobs fail.

## Time Trial & Mastery
Both were regular untimed attempts (`deadline: null`). Time Trial: decoded offline from the saved artifact, then
submitted, CORRECT. Mastery: all 43 blobs decoded offline (`BAD 0 of 43`), then one live submit, CORRECT.

## Lessons / gotchas
- Detect structurally before scoring. A row that is a quoted string full of `\u` is unambiguous. Statistics are only
  needed for the letter ciphers (ROT13 etc.).
- Decode offline from the saved artifact (`--dir`), check that 0 blobs fail, then submit. That pattern held for the rest
  of the event.
