# 📱 Intent Injection

| | |
|---|---|
| **Day** | 03 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-03-intent-injection` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_d3mob.py`](../solvers/solve_d3mob.py) |

## Prompt
> Trace attacker-controlled extras through an internal navigation boundary.

## TL;DR
The container is the same as Days 1–2. `assets/huntress_puzzle.json` is
`{schema, day:3, codec:"base64", data}`, and Base64-decoding `data` gives `ANS-<16 HEX>`. The manifest, the binary
AXML and the dex tell the intent-injection story, but none of them are needed.

## Artifact
- A tiny APK (plain ZIP) with `AndroidManifest.xml`, `classes.dex` and `assets/huntress_puzzle.json`.
- One answer id `answer` in Single Solve and Time Trial. Mastery has `set1.answer` … `set3.answer`.

## Solution
**Theme.** In intent injection, an exported "router" Activity takes a nested `Intent` (or a component name, URI or
flags) out of attacker-supplied extras and calls `startActivity()` with it. The router runs with the app's own
identity, so the attacker reaches *internal*, non-exported screens. The usual fixes are to never forward
caller-supplied Intents, or to rebuild them with explicit, allow-listed components.

**Extraction:**

```python
def puzzle_from_apk(b):
    z = zipfile.ZipFile(io.BytesIO(b))
    j = json.loads(z.read("assets/huntress_puzzle.json"))
    return dec(j["codec"], j["data"]).strip()       # Day 3: base64 -> "ANS-…"

# dec("base64", d) = base64.b64decode(d + "=" * (-len(d) % 4)).decode()
```

`solve_d3mob.py` adds padding repair and, for an unknown codec, a final "try Base64, else plain" fallback.

## Time Trial & Mastery
- All three modes were solved with one start → fetch → decode → submit process per attempt.
- Mastery: 3 sets. The solver reads each question's `set` number, fetches API `delivery=set-1`, and falls back to the
  default artifact if that delivery returns an error blob.

## Lessons / gotchas
- The codec changes every day, but the container doesn't. Check `codec` before reading any code.
- Padding: some generators drop the `=`. Always pad before calling `b64decode`.
