# 👶 Safe Travels

| | |
|---|---|
| **Day** | 11 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-11` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day11_quick/warm11.py`](../solvers/day11_quick/warm11.py) (+ [`gmx.py`](../solvers/day11_quick/gmx.py) rate-limit backoff) |

## Prompt
> Our usual base went on a URL-friendly vacation.

## TL;DR
base64url (RFC 4648 §5): Base64 with `-` and `_` instead of `+` and `/`, and padding dropped. Decode with
`base64.urlsafe_b64decode` after re-padding to a multiple of 4. `warm11.py` is `warm10.py` plus base64url in both the
whole-blob layers and the per-row decoder.

## Artifact
- Single Solve: `blob.txt`, one unpadded base64url line (`TmljZSB3b3JrIGRl…`).
- Time Trial: same form, with a real deadline (~10 s from start).
- Mastery: 53 sets, `blob-01.txt`…`blob-53.txt` in one ZIP, deadline ~8 s from start. The day's note calls the blobs
  "plain base64url" and does not record their row layout. Day 13's learned row order (row 11 = base64url) suggests they
  were the usual 11-row mixed form. Either way `warm11.py` decoded all of them.

## Solution
```python
def pad(s, n):
    s = s.rstrip("=")
    return s + "=" * (-len(s) % n)

if re.fullmatch(r"[A-Za-z0-9_\-]+=*", c):
    out.append(base64.urlsafe_b64decode(pad(c, 4)))
```
The rest is the [Day 10](../day10/warmups-thirty-two-below.md) machinery: syntax-detected row codecs, then a template
search on `Nice work … Game Master: <slug>`.

## Time Trial & Mastery
Time Trial: CORRECT, compute 0.7 s. Mastery: all 53 decoded and CORRECT on the first submit, well inside its short
timer.

## Lessons / gotchas
- New today: three solving agents in parallel shared one Game Master token, so the first `list`/`status` calls returned
  `rate_limited`. `gmx.GMX` retries posts, status calls and artifact fetches with exponential backoff (1.5 s × 1.6, capped
  at 10 s). The first warmup run took ~25 s because of these retries. After that, every call went through the first time.
- Keep the backoff on artifact fetches too. A `rate_limited` JSON body must never be decoded as if it were a blob.
