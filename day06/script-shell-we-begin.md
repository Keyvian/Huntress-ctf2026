# 📜 Shell We Begin

| | |
|---|---|
| **Day** | 06 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-06-bash-behavior-graphs` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | The Day-6 solver (`d6bash_solve.py`, Homebase VM) was not preserved; its Bash decoding lives on in [`solvers/day09/sdec.py`](../solvers/day09/sdec.py) |

## Prompt
> Six Bash behavior graphs, none of which will ever run. Read them like a native: map the adapters, count the stages, tag the ATT&CK techniques, and pull the exact indicators hiding in the final bytes.

## TL;DR
The Day-5 set (357 questions) plus six Bash "behavior graph" scripts with 7 questions each, **399 questions**.
Each `.sh` carries a `Material_<id>`/`Codec_<id>` pair and a self-contained decode routine that prints a
`v=1|…` plan. The plan answers adapter, campaign, indicator, stage count and the ordered steps. Role comes
from the filename, and ATT&CK uses the Unix-shell execution technique `T1059.004`.

## Artifact
WinZip-AES ZIP (`infected`): the 44 earlier specimens ([Day 5](../day05/script-hatch-careful.md)) plus
`host-context.sh`, `memory-stage.sh`, `embedded-write.sh`, `remote-write.sh`, `local-dispatch.sh`,
`staged-chain.sh`.

Bash questions (7 per file):

| Suffix | Format |
|---|---|
| `role` | enum |
| `attack` | ATT&CK ID or `none` |
| `adapter`, `campaign`, indicator (`host-id` / `url` / `file-path`) | exact text |
| `stage-count` | base-10 integer |
| `steps` | ordered tokens joined by `>` with no spaces |

## Solution
Specimen shape (abridged; from a later variant of the same family):

```bash
readonly Material_2ec0bff3='dj0xfHN0ZXBz…''…'      # base64 chunks, sometimes split into adjacent quotes
readonly Codec_2ec0bff3='base64_chunks|identity|'  # <representation>|<transform>|<param>
Load_2ec0bff3()    { … base64 --decode | od -An -v -tu1 … }   # bytes -> integer array
Decode_2ec0bff3()  { … inverse transform … }
Recover_2ec0bff3() { …; printf '%s\n' "$plan"; }
Inspect_2ec0bff3() { Recover_2ec0bff3; }
```

On this day the codecs were `base64_chunks` with transforms such as `reverse_then_xor`. Python's strict
Base64 decoder choked on some chunked materials that Bash's `base64 --decode` accepts. So the Day-6 solver
took the shortcut of running each fixture in its built-in inspect mode (`HUNTRESS_INSPECT_ONLY=1`), which
only calls `Recover_` and prints the plan line:

```
v=1|steps=decode_configuration,return_configuration|adapter=readonly_configuration|stage_count=1|
campaign_id=campaign-<10 hex>|host_id=host-<10 hex>
```
(This is the `host-context.sh` plan from a later variant.)

From [Day 9](../day09/script-all-the-world-s-a-stager.md) on, the solver did this statically: join the
adjacent quoted chunks, decode leniently, and brute-force the inverse transform until the bytes look like a
plan.

Answer mapping:
- `role` from the filename: host-context → `benign_utility`, memory-stage → `stager`, embedded-write →
  `dropper`, remote-write → `downloader`, local-dispatch → `launcher`, staged-chain → `staged_chain`.
- `attack`: benign `none`; stager and downloader `T1105`; dropper `T1140`; launcher and staged_chain
  **`T1059.004`** (Unix Shell).
- `adapter`, `campaign` (`campaign_id`), indicator: plan fields.
- `stage-count`: plan `stage_count`, submitted as a string.
- `steps`: plan `steps` with commas replaced by `>` (e.g. `acquire_remote>write_file`).

## Time Trial & Mastery
- This was the first day solved by a background watcher that waited for the 09:00 ET release and then
  started solving. Day 6 was complete about 20 minutes after release.
- The timed modes reused the Day-5 strategy: parallel chunks of about 40 deterministic answers plus
  parallel single-answer submits of every Batch expansion/control candidate, with about 30 workers for
  Time Trial.
- Mastery was 798 answers in 2 sets under about 7 seconds. It needed **lower** concurrency than Time Trial,
  because a large worker pool triggered rate-limit cascades that ate the deadline. It finished in about 7.1 s.

## Lessons / gotchas
- `steps` is an `ordered_tokens` answer: keep the plan order and use bare `>` separators.
- Integers must still be sent as JSON strings. The GM rejects numeric answer values with `invalid_answers`
  (this was formalized on [Day 7](../day07/script-node-by-node.md)).
- Different Base64 decoders disagree on sloppy padding and chunking, so decode leniently.
- Previous: [Day 5](../day05/script-hatch-careful.md) · Next: [Day 7](../day07/script-node-by-node.md).
