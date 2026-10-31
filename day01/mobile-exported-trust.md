# 📱 Exported Trust

| | |
|---|---|
| **Day** | 01 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-01-exported-trust` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/sm.py`](../solvers/sm.py) (positional mapping, final) · [`solvers/solve_mobile_exported.py`](../solvers/solve_mobile_exported.py) (first attempt, case-string mapping) |

## Prompt
> Identify an exported deep-link Activity that attaches an embedded client credential, invoke it with the correct case reference, and return the backend evidence code.

## TL;DR
The artifact is a tiny (~12 KB) APK. The exported Activity, deep link and "client credential" are all
present, but the answer never comes from talking to a backend. It is stored in the APK at
`assets/huntress_puzzle.json` as `{schema, day, codec, data}`. On Day 1 `codec` is `plain`, so the answer is
`data` as-is: `ANS-` followed by 16 uppercase hex digits. Every later mobile day reuses this container. Only the codec, and
later the structure, changes.

## Artifact
- Question (answer id `answer`, one per set): it names a case reference `MOB-01-…` and asks for the backend answer
  code for that case. Later days show the full wording: *"For case MOB-NN-… in package com.huntress.mobile.dNN.v…:
  <prompt>. Submit only the exact backend answer code returned for this case."* Format `pattern`: "ANS- followed by
  exactly 16 uppercase hexadecimal characters; no spaces or explanatory text", normalization `exact`.
- The APK is a plain ZIP with these members:

| Member | Content |
|---|---|
| `AndroidManifest.xml` | the exported Activity and its deep-link intent filter (the story) |
| `classes.dex` | the Activity code, the `MOB-01-…` case reference and the backend URL |
| `assets/huntress_puzzle.json` | `{"schema":…,"day":1,"codec":"plain","data":"ANS-…"}`, which holds the answer |

- Mastery has 3 sets (`set1.answer` … `set3.answer`), with one APK per set.

## Solution
The story describes a real Android bug class. An `android:exported="true"` Activity can be started by any app on
the device. If it also attaches a secret to the request it makes, any caller can borrow that secret. In this APK the
dex builds `http://127.0.0.1:19090/mobile/attempt/<id>/evidence?case_id=…&client_secret=SECRET-…&proof=…`. That
embedded `client_secret` is the "credential" the prompt refers to.

In practice the loopback backend can't be reached from the player's side, and the GM proxy doesn't forward that path.
The answer the backend would return is already in the APK:

```python
z = zipfile.ZipFile(io.BytesIO(apk_bytes))
p = json.loads(z.read("assets/huntress_puzzle.json"))
answer = decode(p["codec"], p["data"])        # Day 1: codec == "plain" -> data verbatim
assert re.fullmatch(r"ANS-[0-9A-F]{16}", answer)
```

The decoder handled `plain`, `reverse`, `base64`, `base64url`, `hex`, `rot13` and `gzip` from the start, so the
following days only needed small changes.

## Time Trial & Mastery
- Every mode followed the same steps in one process: `start` (or `retry` when `start` returned no `answer_ids`), download, decode, submit.
- Mastery was locked (`prerequisite_required`) until the same challenge's Time Trial was solved.
- **Delivery off-by-one:** mastery question labels read `delivery 1/2/3`, but the API `delivery` parameter is
  0-based. Set K comes from `delivery=K-1`, and `delivery=3` returns `{"error":"invalid_delivery"}`.
- The first solver (`solve_mobile_exported.py`) matched questions to APKs by the `MOB-01-…` case string found in the
  dex. That was unreliable because `start`/`retry` regenerate the case references and values. The final solver
  (`sm.py`) maps set K to delivery K-1 inside a single process.

## Lessons / gotchas
- The `127.0.0.1:19090` backend and its `client_secret` are a decoy that stays in every mobile APK until Day 31.
  Never try to reach it.
- Map mastery sets to deliveries by position (0-based), not by case strings.
- Always validate against `ANS-[0-9A-F]{16}` before submitting. Every mobile answer for the whole event has that
  shape.
