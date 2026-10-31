# 🔎 No Artifact Left Behind

| | |
|---|---|
| **Day** | 31 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-31-no-artifact-left-behind` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day31_quick/m31.py`](../solvers/day31_quick/m31.py) + case-graph analyser [`graph31.py`](../solvers/day31_quick/graph31.py) |

## Prompt
> Everything is evidence now. Reconstruct the complete execution-and-delivery chain, defend every edge with primary metadata, and identify the tempting conclusion the corpus does not support.

## TL;DR
The final field is `graph.execution_chain_artifact_ids` for `case-001.zip`: a JSON array of artifact ids, in order,
from the one member nothing references down to a terminal member. Each member is an anonymous, extensionless file
typed by its magic bytes. Each format hides its "next" pointer somewhere different: a PowerShell launch line, a JSON
`next` key, an e-mail attachment, a nested ZIP's `run.txt`, a SQLite row, a PNG text chunk. Most of the case is a
closed cycle with no entry. That cycle is the decoy, the "tempting conclusion".

## Artifact
- `case-001.zip` → `artifacts/<id>` (ids like `word-<hex>`), 11–32 members per case, no manifest.
- Answer id `d31-case-001-graph-execution-chain-artifact-ids`. A new synthesis question,
  `metadata-day-31-synthesis-sha256-order`, was already handled by the existing synthesis code.
- Time Trial: **36 questions**. Mastery: **15 sets × 36 = 540**. This is the full lane contract: every family from
  Day 1 to Day 31.

## Solution
**1. Type each member by bytes.** PNG signature, `SQLite format 3`, `PK\x03\x04`, `From:` / `Message-ID:` header
(e-mail), a leading `{` (JSON), a leading `#` or `$ErrorActionPreference` (PowerShell).

**2. Extract edges only from the field that drives execution in that format.** Ids mentioned anywhere else (comments,
subjects, readmes, notes) are reported as `STRAY` and never followed.

| Format | Edge source | Terminal form |
|---|---|---|
| PowerShell | non-comment launch line: `Invoke-Item` / `Start-Process` / `&` + `.\<id>` | `# … terminal` comment + `Write-Output '<word-hex>'` (that value is not a member) |
| JSON | `"next": "<id>"` | `{"done": true, "ref": …}` |
| E-mail | base64 `route.txt` attachment: `open:` / `next:` / `forwarded to:` / `continue with:` | message with no attachment |
| Nested ZIP | `run.txt` → `execute <id>` | `summary.txt` instead of `run.txt` |
| SQLite | `launch_queue.target` | a `summary` table instead of `launch_queue` |
| PNG | `tEXt` `Comment` = `next=<id>` | `done <hex>` |

Single and time trial showed only the PNG and PowerShell terminals. The other four first appeared in mastery.

**3. Walk the graph.** Find the member with in-degree 0 and follow single out-edges until a member with a terminal
marker (simplified from `graph31.chains()`):

```python
roots = [n for n in g if indeg[n] == 0]
for r in roots:
    path, cur = [r], r
    while g[cur]:
        if len(g[cur]) > 1: raise ValueError("branch")      # never seen
        nxt = g[cur][0]
        if nxt in path: break                               # loop -> not the chain
        path.append(nxt); cur = nxt
    if term[cur]: chain = path
answer = json.dumps(chain, separators=(",", ":"))
```

**Structure check.** All 17 cases seen had exactly one unreferenced member (the root), one path from it to a terminal,
and every other member on a closed cycle with no entry. There was no fork and no merge anywhere. The decoy cycle was
usually the larger part: 18 of the 22 members on the single. `graph31.field()` raises unless the graph is exactly "one
chain plus cycles", so an unexpected shape stops the submit instead of producing a guess.

## Time Trial & Mastery
- Regular untimed attempts. Single and Time Trial (36/36) were CORRECT with the first version of `graph31.py`.
- Mastery: that first version **refused 8 of 15 sets** by design, because their chains ended in the four terminal forms
  it had not seen yet (e-mail without attachment, `summary.txt`, `summary` table, JSON `done`). These were added as
  terminal markers.
- **Mismatched quotes.** Some launch lines read `Start-Process '.\x"` or `&  ".\x'`. PowerShell would not parse them.
  They occur both on the real chain (9 times across mastery) and off it (15 times). Single and time trial had none on
  the chain, so their CORRECT verdicts proved nothing about this case. The agent probed it with a **one-answer subset
  submit** of set 8, whose chain crosses two such lines: `accepted`, `remaining: 539`. Following them is correct, and
  the same probe confirmed the set ↔ `evidence-NN.zip` mapping.
- Full mastery submit after the set-8 probe: CORRECT 540/540. That was the last metadata mode of the event.

## Lessons / gotchas
- Only follow references that the format would act on. Mentions in comments, subjects or notes are the "tempting
  conclusion" material.
- Make the solver refuse shapes it does not understand. Eight refusals cost minutes, while one guessed chain would
  have failed a 540-answer submit.
- Syntactic noise on an edge (broken quoting) is not a reason to drop the edge. Test the hypothesis with one banked
  answer before betting the set on it.
- The whole lane converges here: identity by bytes ([Day 1](../day01/metadata-you-must-be-this-hash-to-ride.md)),
  typing by magic ([Day 2](../day02/metadata-looks-can-be-deceiving.md)), and structure-aware parsing of every format
  added since. See the [lane overview](../lanes/metadata.md).
