# 📜 Ashes to Assets

| | |
|---|---|
| **Day** | 25 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-25-phoenix-stage-chain` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day25_script/s23.py`](../solvers/day25_script/s23.py) (verbatim copy of Day 24) · [`lyr.py`](../solvers/day25_script/lyr.py) · [`qdiff.py`](../solvers/day25_script/qdiff.py) / [`wdiff.py`](../solvers/day25_script/wdiff.py) |

## Prompt
> Configuration starts out in Elixir source and has changed shape by the time an inert Phoenix-hosted stage picks it up. Follow every transformation, reconcile each one with earlier campaign artifacts, and find the setting that didn't survive the rebirth.

## TL;DR
An **Elixir** polyglot family plus a Phoenix host, and nothing else. Single Solve = Day-24 single + 55
(1,571); timed = Day-24 timed + 65 (1,625). Mastery grew to **9 sets** (14,625 answers). Zero solver code
changes, with no diagnostics on the first compute. This is exactly what the Day-24 note predicted. About 5
minutes for the lane.

## Artifact
- Single Solve: `polyglot-elixir-{benign-utility,downloader,launcher,staged-chain}.exs` and
  `host-elixir-phoenix-elixir.exs` (11 questions each), 167 files in all.
- Time Trial / Mastery: the same five as hash-named `.exs` files, 13 questions each
  ([Day 23 timed contract](../day23/script-press-start-to-decode.md)).

```elixir
# HUNTRESS_ANALYSIS_V1:<HEADER>-<payload>
descriptor_<hex> = "<same payload>"
_plan_<hex> = %{descriptor: descriptor_<hex>}

defmodule Huntress.InertController<HEX> do            # host file only
  def show(_conn, _params), do: {:ok, "inert-analysis-fixture"}
end
```

Single Solve headers: `HEX`, `HB64`. Timed headers: `LYR-<chain>` (`hex_hex_frag`, `hex_rev_hex`,
`hex_hex_b32`, `b64_b64_b32`, `hex_b32_rev`), decoded right-to-left by the unchanged `lyr.py`.

## Solution
1. `fetch.py` + `extract.py` → `qdiff.py <day24 single> <day25 single>` → 55 new, all Elixir, 0 gone/changed.
2. `s23.py --dir` → 1,571/1,571. The decoded payload is the usual
   `v=3|language=elixir|role=…|attack=…|adapter=…|host_profile=…|obfuscation_profile=…|stage_profile=…|next_language=…|stage_count=…|steps=…|campaign_id=ELIXIR-<8hex>|url=https://elixir-<10hex>.example.invalid/stage|file_path=/tmp/huntress-elixir/.<16hex>.stage`.
3. The host question ("script host or webshell source container") answers `host_profile=elixir_phoenix`;
   the polyglots answer `standalone`. `path-leaf` keeps the leading dot.
4. The timed descriptors again record role/attack pairs that do not follow from the steps (e.g. `uploader` +
   `T1041` with steps ending in `dispatch_language`) and invented stage-profile names (`cobalt_braid`,
   `ruby_lattice`, `onyx_pivot`, `slate_ladder`). Answer the recorded values.
5. "Rebirth", "survive", "reconcile" and "transformation" appear only in the prompt. No question asks for a
   config diff or a "lost setting".
6. Single Solve: `--submit --by-file --only elixir` (5 × 11 `accepted`), then `--submit --exclude elixir` → CORRECT.

## Time Trial & Mastery
- Time Trial: untimed regular attempt (`deadline: None`, 32 unique attempts left).
  `wdiff <day24 tt> <day25 tt>` → only the 13 Elixir shapes new. Bank the Elixir groups (13 each), then
  submit the remaining 1,560 → CORRECT.
- Mastery: `s23.py <ch>/mastery --save <dir>`. Start took 1.9 s, all 9 sets were loaded from the default ZIP
  (`evidence-0N.zip` members) by 4.1 s, and 14,625 answers were computed by 5.0 s. Cached
  `--submit --by-file --only elixir --files 9` (5 groups of 117 `accepted`), then the remaining 14,040 in one
  submit → CORRECT.

## Lessons / gotchas
- Mastery set count keeps growing (7 → 8 → 9). `--files <setcount>` keeps the "bank new groups first" step
  at one request per new file.
- Previous: [Day 24](../day24/script-web-of-lies.md) · Next: [Day 26](../day26/script-mixed-signals.md).
