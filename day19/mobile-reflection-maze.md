# 📱 Reflection Maze

| | |
|---|---|
| **Day** | 19 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-19-reflection-maze` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day19_quick/mob19.py`](../solvers/day19_quick/mob19.py) (byte-identical to `mob17.py`) |

## Prompt
> Reconstruct reflective dispatch across generated equivalent call graphs.

## TL;DR
The puzzle was `{"codec":"reflection","data":"ANS-…"}`, and **`data` was already the plain answer**. The dex has a
`ReflectionMaze` class with `CODEC="reflection"`, `CONTROL="reflective_dispatch"` and a `describe()` method, and it
doesn't transform anything. `mob17.py` handled this without code changes: it checks the ANS pattern *before* looking
up the codec, so an unknown codec name with an already-valid value is returned as-is.

## Artifact
- `classes.dex`: `MainActivity`, the `ChallengeActivity` WebView stub (backend and `client_secret` decoys) and the
  `ReflectionMaze` constants.
- Mastery: 5 sets via `delivery=1..4`, with codecs `base64`, `split` (`order [2,0,1]`), `xor`, `xor`, `reflection`.

## Solution
**Theme.** Reflective dispatch (`Class.forName(name).getDeclaredMethod("m" + k, …).invoke(…)`) hides the call graph
from static tools. Generators can emit many "equivalent" graphs that compute the same thing through different
names. Reconstructing it means resolving the strings that build class and method names.

**Extraction:**

```python
s = p["data"]
for _ in range(6):
    if ANS.fullmatch(s.strip()):     # already an answer -> done, whatever the codec says
        return s.strip(), p
    s = dec(p.get("codec"), s, p)    # "reflection" would raise ValueError, but is never reached
```

**jadx tip** (recorded that day): the Kali `jadx` wrapper changes directory before it runs, so relative input/output
paths break. Always pass absolute paths.

## Time Trial & Mastery
- Every timed mode in the quick lanes was a regular untimed attempt (`deadline: None`).
- All three modes were `CORRECT` on the first submit.

## Lessons / gotchas
- Check the result pattern before dispatching on the codec name. Unknown labels with plain data then cost nothing.
- The theme came back for real on [Day 25](../day25/mobile-integrity-signals.md). A v2 mastery set dispatched through
  `Class.forName(...).getDeclaredMethod(...).invoke(...)`, and the Dalvik interpreter had to model
  `java.lang.reflect`.
