# ⚙️ Campaign Trail

| | |
|---|---|
| **Day** | 30 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-30-multi-binary-campaign` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day30_binary/b30.py`](../solvers/day30_binary/b30.py) (`hgrf_scan_back`, `d30_fields`) · [`qdiff.py`](../solvers/day30_binary/qdiff.py) · [`confirm.py`](../solvers/day30_binary/confirm.py) |

## Prompt
> One binary is a clue; a campaign is a story. Reconstruct the loader, library, and config graph across the whole set and map the operation end to end.

## TL;DR
Day-29 contract (406 questions) plus 14 `d30_*` questions. The unit is three **Neko bytecode** modules
(`loader`, `library`, `config`), and the config record uses a new magic, **`HGRF`**, with the usual 12-byte
HCFG header layout. The one trap: the questions refer to `graph.config.campaign`, but the decoded JSON has
no `graph` key, because "graph" is the decoded object itself. Reading the computed answers before submitting
caught it, and all three modes passed on the first submit. The same day also had the 5-point standard
challenge [SHA1-Hulud](binary-sha1-hulud.md), solved by the same agent.

## Artifact
WinZip-AES ZIP (password `infected`). New members in ZIP order: `d30--sample-loader.n`,
`d30--sample-library.n` and `d30--sample-config.n`, all Neko bytecode (`NEKO` magic), about 20.9 KB each.

Fields: `d30_artifact_sha256_{1,2,3}`, `d30_analysis_{loader,library,config_capsule}_format`
(`neko_bytecode`, from the format enum first seen on [Day 20](../day20/binary-resourceful.md)),
`d30_analysis_config_{campaign,domain,mutex,url}` (from the loader's graph) and
`d30_analysis_config_capsule_graph_config_{campaign,domain,mutex,url}` (from `config.n`'s graph). Note that
the role key is `config_capsule` even though the file name ends `config.n`.

## Solution
- Contract diff: 406 → 420, 0 gone, 0 changed, 14 new; the time-trial contract was identical.
- **`HGRF` records**: same layout as HCFG (version +4, XOR key +5, u16le length +6, CRC32 +8, payload +12).
  Scan backward from the end of each member and take the unique CRC32-valid record (sample: offset ~20173,
  key `0xf1`). `b30.py` adds `hgrf_scan_back()` for this.
- **The `graph.config.x` path**: the decoded JSON is the graph. The values are at `obj["config"]["campaign"]`,
  not `obj["graph"]["config"]["campaign"]`. A first draft that used `.get("graph")` silently produced `none`
  for every config field; the mistake showed up when the computed answers were printed for review, before
  any submit.
- The three graphs (loader, library, config capsule) were identical once their `this_role` key was
  removed, in all 16 variants seen (single, time trial and 14 mastery sets). The solver checks this and
  flags a mismatch in its diagnostics.

```python
p = b.rfind(b"HGRF")                                   # backward scan, validate every candidate
while p != -1:
    ver, key = b[p + 4], b[p + 5]
    size = struct.unpack("<H", b[p + 6:p + 8])[0]
    hdr_crc = struct.unpack("<I", b[p + 8:p + 12])[0]
    plain = bytes(c ^ key for c in b[p + 12:p + 12 + size])
    if zlib.crc32(plain) & 0xffffffff == hdr_crc:
        good.append(dict(off=p, key=key, cfg=json.loads(plain)))
    p = b.rfind(b"HGRF", 0, p)
...
c = recs["loader"]["cfg"].get("config", {})           # the decoded object IS the graph
A["d30_analysis_config_campaign"] = str(c.get("campaign", "none"))
```

## Time Trial & Mastery
| Mode | Questions | Time used |
|---|---|---|
| single_solve | 420 | untimed, one submit |
| time_trial | 420 | 4.3 s (`deadline: None`, 171 unique attempts) |
| mastery | 5880 (**14 sets** × 420) | 26 s |

## Lessons / gotchas
- A path in a question (`graph.config.campaign`) can name a concept rather than a JSON key. Print the
  computed answers before the first submit; `none` everywhere is a red flag.
- New magic, same header: once the HCFG parser takes the magic as a parameter, `HGRF` (and Day 31's
  `HGAU`) cost one line each.
- "Reconstruct the loader, library and config graph" stayed flavor; no graph question existed.
