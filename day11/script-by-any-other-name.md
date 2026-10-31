# 📜 By Any Other Name

| | |
|---|---|
| **Day** | 11 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-11-native-api-semantics` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day11_script/s9.py`](../solvers/day11_script/s9.py) + [`sdec.py`](../solvers/day11_script/sdec.py) (unchanged) · [`timed.py`](../solvers/day11_script/timed.py) · [`fetch.py`](../solvers/day11_script/fetch.py) |

## Prompt
> These scripts reach for native APIs by name, but a name isn't a behavior. Map each reference to the receipt-backed action it models, and flag the call whose claimed purpose the evidence doesn't support.

## TL;DR
**811 questions** = the Day-10 contract (753, unchanged) + 58 new: four **TypeScript** polyglots and two
advanced Bash fixtures. No native-API semantics question existed. The Day-10 solver computed 811/811
unchanged, and the whole lane took about 4 minutes.

## Artifact
WinZip-AES ZIP (`infected`), a 94-file `evidence.zip`. New files:

| File | Questions | Notes |
|---|---|---|
| `polyglot-typescript-{benign-utility,downloader,launcher,staged-chain}.ts` | 4 × 11 | `// HUNTRESS_ANALYSIS_V1:<ENC>-…` + `const descriptor_<hex>: string = "…"` |
| `nameref-dispatch.sh` | 7 | feature `nameref_dispatch`, primitive `declare_nameref` |
| `dynamic-file-descriptor.sh` | 7 | feature `dynamic_file_descriptor`, primitive `allocated_file_descriptor` |

The Bash materials are `decimal_csv` (`Codec='decimal_csv|'`).

## Solution
1. `fetch.py <ch> <dir>` (start + artifact download with rate-limit backoff), then
   `qdiff.py <day10 start.json> <day11 start.json>` → 0 gone, 0 changed, 58 new.
2. Run the Day-10 solver unchanged:
   - The TypeScript files carry the standard analysis header, so the polyglot branch answers all 11 questions
     from the decoded descriptor ([Day 8](../day08/script-lost-in-translation.md)). As always, role and
     attack are the recorded values (benign-utility → `none`).
   - The Bash fixtures decode with the generic Material/Codec brute-forcer: `advanced_syntax`, `T1059.004`,
     and feature/primitive/campaign/stage count/steps from the plan.
3. Single Solve: `s9.py <ch> --dir <dir> --submit --by-file --files 10` → 10 batches, all `accepted`, the
   last one CORRECT.

Everything was decoded statically; nothing was executed.

## Time Trial & Mastery
- `timed.py <ch>/time_trial <dir>`: 811 answers, 9-second window, one-shot in 2.6 s.
- `timed.py <ch>/mastery <dir>`: 1,622 answers (2 sets), 11-second window, one-shot in 2.4 s. The default
  artifact bundled both sets.
- Gotcha: the three automated agents (one per lane group, running in parallel since Day 10) share one GM
  token. This day the first `start` call hit `rate_limited`, so `fetch.py` gained exponential backoff.

## Lessons / gotchas
- Three days in a row (Day 9 → 11), the lane grew by one polyglot language and two Bash fixtures. The
  "diff, then reuse" path is now a routine.
- Shared-token rate limits hit the first requests of a parallel run. Retry with backoff before treating a
  response as an error.
- Previous: [Day 10](../day10/script-bind-over-matter.md) · Next: [Day 12](../day12/script-autoit-takes-two.md).
