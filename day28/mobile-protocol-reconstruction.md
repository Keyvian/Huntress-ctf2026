# 📱 Protocol Reconstruction

| | |
|---|---|
| **Day** | 28 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-28-protocol-reconstruction` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day28_quick/mob28.py`](../solvers/day28_quick/mob28.py) (+ [`dalvik.py`](../solvers/day28_quick/dalvik.py)) |

## Prompt
> Reconstruct the app-to-backend protocol and preserve nonce and ordering semantics.

## TL;DR
Single Solve introduced a new v1 codec, **`packet`**. `data` is the hex of a binary frame,
`"HA" | u8 length | payload | u8 checksum`, where the checksum is the XOR of every byte before it and the payload is
the `ANS-` code. Time Trial was a v2 `analysis` build with a frame-packing loop. Mastery had **12 sets, all v2**,
including one `.apks` split bundle. The interpreter needed no change. The agent added the packet parser and checked
the Time Trial against a hand port.

## Artifact
- Single Solve `protocol_reconstruction.apk`: `{"schema":"huntress.mobile.puzzle.v1","day":28,"codec":"packet","data":"484114414e532d36…4311"}`.
  The dex also builds the usual `127.0.0.1:19090/…/evidence?case_id=…&client_secret=…&proof=` WebView URL.
- Time Trial: v2 `analysis`.
- Mastery: **12 sets**. Deliveries are labeled `protocol_reconstruction_mastery_01.apk` … `_12.apk`, and
  `_11` is an **`.apks`** bundle. Themes: d01, d04, d07, d08, d11, d14, d17, d18, d22, d24, d26 (split bundle),
  d28.

## Solution
**Theme.** Rebuilding an app's wire protocol means recovering framing (magic, length, checksum), field order and
replay protection (nonces, sequence numbers) well enough to produce messages the server accepts. Reordering
frames or reusing a nonce gets the message rejected.

**Single Solve: the `packet` codec.** Decoding the example: `48 41` = `"HA"`, `14` = 20-byte length, 20 payload bytes
`414e532d…` = `ANS-…`, and a final `11` = XOR of all 23 preceding bytes. `mob28.py` parses strictly and refuses
anything that doesn't fit:

```python
def frames(b):
    out, i = [], 0
    while i < len(b):
        if len(b) - i < 4: raise ValueError("trailing bytes")
        magic, n = b[i:i + 2], b[i + 2]
        end = i + 3 + n
        if end + 1 > len(b): raise ValueError("length overruns")
        x = 0
        for c in b[i:end]: x ^= c                      # checksum covers magic + length + payload
        out.append((magic, b[i + 3:end], x == b[end]))
        i = end + 1
    return out
```

If a variant ever ships several frames, they are ordered by an explicit sequence or nonce prefix when one exists,
otherwise kept in wire order. It never did. The codec is installed by monkeypatching `mob19.dec`, so the whole
`mob19` → `mob26` chain picks it up without edits.

**Time Trial: v2 with a framing loop.** The chain was `FrameKit.mixPacket…` → `Util.sessionSession…`, a loop over
`ProtocolReconstruction.frame(21, tbl[i], step)` = `(a << 16) | (b << 8) | c` with a data-dependent index walk, →
`FrameKit.mixNonce…` → `Mix.f1` → `Util.finSession…` ^ const. `dalvik.py` computed it without changes. A hand
re-implementation of the jadx output with 64-bit wrap-around gave the same value, and the submit was `CORRECT`.

## Time Trial & Mastery
- All timed modes were regular untimed attempts. Time Trial `uar` 32.
- Mastery: 12/12 computed in 6.5 s and submitted once: `CORRECT`. Before submitting, each set's package name
  (`com.huntress.mobile.dNN.v…` in the question text) was checked against the package inside its delivered APK,
  12/12. In set 11 the trace showed `Assets.readSplit` reading the feature split
  ([Day 26](../day26/mobile-split-decision.md) model).

## Lessons / gotchas
- The single can introduce a new v1 codec while Time Trial and Mastery are v2 puzzles the interpreter already
  handles. Write the new codec as a strict parser with diagnostics.
- Always verify the set ↔ delivery mapping. Every question text names its package, so the check is cheap.
