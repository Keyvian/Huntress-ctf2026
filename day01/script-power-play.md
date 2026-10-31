# 📜 Power Play

| | |
|---|---|
| **Day** | 01 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-01-native-signals` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/solve_powerplay.py`](../solvers/solve_powerplay.py) |

## Prompt
> Three PowerShell specimens are on the table, and none of them will ever run. That's fine, because you only need to read them. Classify each script's intent, map its primary ATT&CK technique, and pull out the exact indicators sitting in plain sight.

## TL;DR
Three inert PowerShell scripts each carry a `[Convert]::FromBase64String('…')` literal that decodes to a small
JSON object of indicators. Decode it, read the fields by position (the keys are single letters `a`–`h`), and
answer one scenario label, one ATT&CK ID and three indicators per script. This day seeded the whole lane: the
same three `.ps1` files and their 15 questions are carried, unchanged in shape, into every later day.

## Artifact
A WinZip-AES ZIP (password `infected`; Python's `zipfile` cannot decrypt it, `pyzipper` can) with three
specimens:

| File | Scenario | Questions |
|---|---|---|
| `resource-sample.ps1` | resource hijacking (cryptominer-style) | scenario, attack, url, wallet, mutex |
| `collection-sample.ps1` | data collection (browser stores) | scenario, attack, url, file, user-agent |
| `impact-sample.ps1` | ransomware-style impact | scenario, attack, extension, note, url |

15 answer IDs in total (`resource-scenario`, `collection-user-agent`, …). `scenario` is an enum
(`resource_hijacking`, `synthetic_collection`, `synthetic_impact`); `attack` uses the `mitre_attack_id` format
(`T####` or `T####.###`); everything else is `exact_text`.

## Solution
1. Open the ZIP with `pyzipper` and the password `infected`.
2. In each `.ps1`, grab the Base64 literal with `FromBase64String\('([^']+)'\)` and decode it to JSON.
3. Map the single-letter keys per scenario. The layout differs by scenario, so detect the scenario first.
   The Day-1 solver does this from content (a `wallet_…` value → resource; a dotted extension plus a `.txt`
   note → impact; a list value → collection) and falls back to the filename:

| Scenario | `url` | second | third |
|---|---|---|---|
| resource | `b` | wallet = `c` (`wallet_<hex>`) | mutex = `h` (`Global\…`) |
| collection | `b` | file = `c[0]` (`c` is a list; the question asks for the *first* filename) | user-agent = `f` |
| impact | `d` | extension = `b` (e.g. `.locked-<5 hex>`) | note = `c` (`RECOVERY-<hex>.txt`) |

4. ATT&CK mapping (fixed per scenario):
   - `resource_hijacking` → **T1496** (Resource Hijacking)
   - `synthetic_impact` → **T1486** (Data Encrypted for Impact)
   - `synthetic_collection` → **T1555.003** (Credentials from Web Browsers). The script steals browser
     `Login Data`/cookies, so it is credential access rather than an archiving technique. (On Day 5 the grader
     also accepted `T1005`, and from Day 12 the question wording names "browser credential store" explicitly.)

```python
m = re.search(r"FromBase64String\('([^']+)'\)", txt)
d = json.loads(base64.b64decode(m.group(1)))
if kind == "resource":   v = {"url": d["b"], "wallet": d["c"], "mutex": d["h"]}
elif kind == "collection": v = {"url": d["b"], "file": d["c"][0], "user-agent": d["f"]}
else:                    v = {"extension": d["b"], "note": d["c"], "url": d["d"]}
```

The ATT&CK IDs were the only uncertain part. The untimed Single Solve gives partial feedback: a subset submit
whose answers are all correct returns `accepted` plus a `remaining` count and banks them, while any wrong
answer makes the whole batch `incorrect`. Submitting the confident indicators first and then one candidate
technique at a time isolated the right IDs.

## Time Trial & Mastery
- The timed modes deliver a fresh variant of the same three scripts. The solver does start → download →
  decode → submit in one process using the hard-coded mapping learned in Single Solve.
- Mastery bundles two sets (`set1.*`, `set2.*`). The solver fetches the default artifact first (a nested ZIP
  yields one group per inner ZIP, in name order) and probes `delivery=N` only until every set is covered.
  Groups are de-duplicated by content, because deliveries can repeat a set.
- Later variants of the same `.ps1` files (seen from Day 3 on) add a `-bxor <key>` loop and/or
  `[Array]::Reverse` before the JSON parse; the later solvers apply both when present.

## Lessons / gotchas
- Use the partial-feedback banking on the untimed mode to learn undocumented mappings, then one-shot the
  timed modes.
- The collection `file` answer is the first element of a list, not the whole list.
- The single-letter key layout depends on the scenario. On Day 23 the timed modes renamed these files to
  hash names, and reading the wrong layout became a real trap (see
  [Day 23](../day23/script-press-start-to-decode.md)).
- Next day: [Host With the Most](../day02/script-host-with-the-most.md) adds JScript on top of these three files.
