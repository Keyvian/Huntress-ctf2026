# 📜 FROM Whence It Came

| | |
|---|---|
| **Day** | 27 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-27-docker-build-attribution` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day27_script/s23.py`](../solvers/day27_script/s23.py) (verbatim copy of Day 26) · [`qdiff.py`](../solvers/day27_script/qdiff.py) · [`wdiff.py`](../solvers/day27_script/wdiff.py) |

## Prompt
> A Dockerfile and several earlier specimens share strings, but sharing strings doesn't mean sharing parents. Attribute each specimen using build-stage, semantic, and static-handoff evidence, and expose the resemblance that's only skin-deep.

## TL;DR
Four **Dockerfile** polyglots, Single Solve = Day-26 single + 44 (1,659). The surprise was that **Time Trial
used the same question IDs as Single Solve** (1,659) instead of the separate hash-named timed contract. It
was a different variant, though: 423 of the 1,659 answers differed. Mastery: 11 sets × 1,659 = 18,249. Zero
solver changes.

## Artifact
`polyglot-dockerfile-{benign-utility,downloader,launcher,staged-chain}.dockerfile`, 11 questions each, 175
files in all.

```dockerfile
# HUNTRESS_ANALYSIS_V1:<HEADER>-<payload>
FROM scratch AS analysis_<hex>
ARG HUNTRESS_DESCRIPTOR="<same payload>"
LABEL huntress.analysis.descriptor=$HUNTRESS_DESCRIPTOR
```

Headers: `FRAG`, `HEX`, `B64`, `HB64`. The payload, like every polyglot since Day 8, also records a
`verdict` field that no question asks for:
`v=3|language=dockerfile|role=…|verdict=…|attack=…|adapter=…|host_profile=standalone|…|campaign_id=DOCKERFILE-<8hex>|url=https://dockerfile-<10hex>.example.invalid/stage|file_path=/tmp/huntress-dockerfile/.<16hex>.stage`.

## Solution
1. `op=status` on the base ID before starting → `status0.json` (1,659 questions);
   `qdiff <day26 single> status0.json` → 0 gone, 0 changed, 44 new.
2. `fetch.py` + `extract.py` → `s23.py --dir` → 1,659/1,659, no diagnostics.
3. Attack is the **recorded** field, and it was accepted as recorded even where the steps disagree: the
   downloader says `T1105` with steps `decode_configuration>return_configuration`; launcher and staged-chain
   say `T1059`; benign says `none`.
4. Nothing in the contract asks for build-stage attribution or "skin-deep" resemblance.
5. Single Solve: `--submit --by-file --only dockerfile` (4 × `accepted`), then `--submit --exclude dockerfile`
   → CORRECT.

## Time Trial & Mastery
- **Time Trial switched contracts.** `qdiff <today's single> <today's tt>` → 0/0/0: identical IDs. Up to Day 26
  the timed contract was a separate hash-named set (Day 26: 1,677 questions), so a `wdiff` against Day 26's
  Time Trial would report 1,551 "new shapes" because of the switch alone. The artifact was a different
  variant, so it was still computed from fresh bytes. `s23.py` handled it unchanged. Untimed
  (`deadline: None`), bank-then-rest → CORRECT.
- **Mastery** = 11 sets × 1,659 (`set<N>.<single id>`). `s23.py <ch>/mastery --save <dir>`: start took
  2.5 s, all 11 sets were loaded by 5.7 s, and 18,249 answers were computed by 7.1 s. Cached
  `--submit --by-file --only dockerfile --files 11` (4 groups of 121), then the remaining 17,765 → CORRECT.
  No rate limiting.

## Lessons / gotchas
- Check the timed contract against **today's** single contract first (`qdiff`). Use `wdiff` against the
  previous day's timed contract only if the IDs differ. The format flipped back the very next day
  ([Day 28](../day28/script-out-of-order.md)).
- Never reuse answers across modes or days, even with identical IDs. The bytes differ per variant.
- Previous: [Day 26](../day26/script-mixed-signals.md) · Next: [Day 28](../day28/script-out-of-order.md).
