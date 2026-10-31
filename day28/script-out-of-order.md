# 📜 Out of Order

| | |
|---|---|
| **Day** | 28 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-28-terraform-cloud-timeline` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day28_script/s23.py`](../solvers/day28_script/s23.py) (verbatim copy of Day 27) · [`qdiff.py`](../solvers/day28_script/qdiff.py) · [`wdiff.py`](../solvers/day28_script/wdiff.py) |

## Prompt
> Terraform HCL describes cloud resources, expressions, and dependencies that change over time. Assemble the timeline from resources, prior scripts, and relationship evidence — without planning or applying anything — and find the change that happened out of order.

## TL;DR
Four **Terraform HCL** polyglots. Single Solve = Day-27 single + 44 (1,703). Time Trial went **back** to
the separate hash-named contract (1,781), and Mastery followed it (12 sets × 1,781 = 21,372). Zero solver
changes, with no diagnostics in any mode. About 6 minutes.

## Artifact
`polyglot-terraform_hcl-{benign-utility,downloader,launcher,staged-chain}.tf`, 11 questions each in Single
Solve. The timed IDs look like `polyglot-terraform_hcl-<6hex>-*`, 13 per file.

```hcl
# HUNTRESS_ANALYSIS_V1:<HEADER>-<payload>
terraform { required_version = ">= 1.0" }
locals { huntress_descriptor_<hex> = "<same payload>" }
output "inert_analysis_<hex>" { value = local.huntress_descriptor_<hex> }
```

Headers: `FRAG`, `HEX`, `B64`, `HB64`. Payload:
`v=3|language=terraform_hcl|role=…|verdict=…|attack=…|…|campaign_id=TERRAFORM_HCL-<8hex>|url=https://terraform_hcl-<10hex>.example.invalid/stage|file_path=/tmp/huntress-terraform_hcl/.<16hex>.stage`.

## Solution
1. `op=status` before start → `scr_status0.json` (1,703 questions).
2. `fetch.py` + `extract.py` → `qdiff <day27 single> <day28 single>` → 44 new → `s23.py --dir` → 1,703/1,703.
3. All answers are recorded descriptor fields ([Day 8](../day08/script-lost-in-translation.md)); the recorded
   `attack` was accepted (downloader `T1105`, launcher/staged-chain `T1059`, benign `none`, and on Time Trial
   `persistence_descriptor` → `T1053`). No question asks about a timeline or an out-of-order change.
4. Single Solve: `--submit --by-file --only terraform` (4 × `accepted`), then `--submit --exclude terraform` → CORRECT.

## Time Trial & Mastery
- **Contract check**: `qdiff` of Time Trial against today's single → 0 common IDs, so the hash-named contract
  was back. `wdiff <day26 tt start.json> <day28 tt start.json>` (the last hash-named one) → 26 new shapes:
  Dockerfile × 13 (absent from Day 27's single-shaped Time Trial) and Terraform × 13, including `url-host`,
  `path-leaf` and `campaign-token`. 0 gone, 0 reworded.
- Time Trial: untimed (`deadline: None`, 32 unique attempts). Bank the 4 Terraform groups (13 each), then
  submit the remaining 1,729 → CORRECT.
- Mastery: `s23.py <ch>/mastery --save <dir>` → 12 sets by 6.4 s, 21,372 answers computed by 8.0 s. Cached
  `--submit --by-file --only terraform --files 12` (4 groups of 156), then the remaining 20,748 → CORRECT.

## Lessons / gotchas
- The timed contract can flip between "same IDs as single" ([Day 27](../day27/script-from-whence-it-came.md))
  and the hash-named shape. Run `qdiff` against today's single first. If nothing is shared, `wdiff` against the
  last hash-named timed contract.
- Mastery follows whichever shape Time Trial uses, and the set count keeps growing (11 → 12).
- Previous: [Day 27](../day27/script-from-whence-it-came.md) · Next: [Day 29](../day29/script-make-it-make-sense.md).
