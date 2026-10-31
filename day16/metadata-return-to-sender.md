# 🔎 Return to Sender

| | |
|---|---|
| **Day** | 16 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-16-return-to-sender` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day16_quick/m16.py`](../solvers/day16_quick/m16.py) (wraps [`m15.py`](../solvers/day15_quick/m15.py)) |

## Prompt
> A mailbox export contains replies, forwards, duplicates, and reconstructed messages. Use stable message identities to rebuild which mail actually belongs together.

## TL;DR
The new field is `email.message_id` for `message-001.eml`: the RFC 5322 `Message-ID` header **verbatim, angle
brackets included** (`<artifact-assembly-line@example.test>`). It was CORRECT on the first single-solve try. The
timed modes are the [Day 15](../day15/metadata-a-word-to-the-wise.md) contract plus this one question.

## Artifact
- `message-001.eml`: `multipart/mixed`, a base64 attachment `evidence-note.txt`, and a custom
  `X-Huntress-Correlation` header.
- Answer id `d16-email-001-email-message-id`.
- Time Trial: **21 questions** (the Day-15 contract + email). Mastery: **5 sets × 21 = 105**, all in the default ZIP.
- The threading story (replies, forwards, duplicates) never became a question. Every mode asked only
  `email.message_id` on top of the cumulative contract.

## Solution
```python
msg = email.message_from_bytes(b, policy=email.policy.compat32)
answer = msg["Message-ID"].strip()        # keep the <...> exactly as stored
```
Keep the angle brackets: they are part of the `msg-id` grammar (`"<" id-left "@" id-right ">"`) and the grader
expects them.

`m16.py` wraps `m15` by monkey-patching `m15.field_value`, so every older family keeps working. It adds `email.<snake>`:

- Any header by name: `in_reply_to`, `references`, `subject`, `from`, `to`, `date`, `x_huntress_correlation`, …
- Derived fields: `attachment_filenames`, `attachment_count`, `attachment_{sha256,md5,size_bytes}` (first attachment,
  decoded), `body_text`, `correlation_token`, `boundary`.
- For `json`-kind answers whose raw value is not JSON (e.g. `References`), the value is split on whitespace into a
  compact array.

Those were built for the threading questions the prompt hinted at. None was asked.

## Time Trial & Mastery
- The GM guidance (changed on Day 13) says: "Time Trial and Mastery are regular scored challenges by default. A
  correct untimed solve still earns the flag and CourseStack points. Set `run_for_time:true` on start or retry to
  request a fresh timed Hall of Fame attempt." On Days 13–14 the metadata timed modes still had deadlines. From Day 15
  they did not: this day a plain `start` returned `deadline: None`, `run_for_time: False` and
  `unique_attempts_remaining: 32`, and the listing gained `ranked_deadline_ms`, `ranked_solve_budget_ms`,
  `ranked_pool_size` and `regular_pool_size`.
- The one-process race was therefore no longer needed for the regular score. Time Trial CORRECT 21/21, Mastery CORRECT
  105/105.

## Lessons / gotchas
- Header values are evidence. Copy them byte-exact, delimiters included, and do not normalize.
- The pattern from now on: one honest new field per day on a new file type, with a forensic-story prompt that does not
  turn into extra questions. Build the parser broad anyway, so a later twist costs one alias.
