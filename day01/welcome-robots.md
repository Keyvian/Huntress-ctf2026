# Welcome Robots

| | |
|---|---|
| **Day** | 01 (orientation) |
| **Lane** | Welcome |
| **Challenge ID** | `welcome-robots` |
| **Modes** | Single Solve ✅ |
| **Solver** | none needed (two Game Master calls) |

## Prompt
> Ask your AI teammate to identify the Welcome Robots challenge and provide the answer for the CTF platform.

## TL;DR
An orientation freebie that checks the Game Master loop works end to end. The `start` response hands over the flag
itself in an `issued_flag` field, and the only answer id is `flag`. Submitting that value back is the whole challenge.

## Artifact
No artifact. `start` returns `answer_ids: ["flag"]` and an `issued_flag` value (a 32-hex string, not reproduced here).

## Solution
```
POST {"op": "start",  "challenge": "welcome-robots"}                       -> issued_flag, answer_ids ["flag"]
POST {"op": "submit", "challenge": "welcome-robots", "answers": {"flag": "<issued_flag>"}}   -> CORRECT
```
Answers are always JSON strings keyed by the exact `answer_id`. This held for every challenge in the event.

## Time Trial & Mastery
Single mode only.

## Lessons / gotchas
- Send `op: "start"` explicitly. A bare `{"challenge": …}` can return just the contract (questions with null
  `answer_ids`) without starting an attempt, and then `artifact`/`submit` answer `start_required`.
- `welcome-robots` and `read-the-rules` show up in day listings as their own `welcome` lane. Our day-ID helper skipped
  them explicitly so the daily automation never tried to treat them as a lane.
