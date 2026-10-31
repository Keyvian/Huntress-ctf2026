# ⚙️ Shared Custody

| | |
|---|---|
| **Day** | 21 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-21-shared-library-boundaries` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | `b21.py` was not preserved; its `d21_fields()` is carried verbatim in [`solvers/day22_binary/b22.py`](../solvers/day22_binary/b22.py) |

## Prompt
> No binary is an island — this one leans on shared libraries for everything. Trace the exports, the imports, and the loader's handshake, and mind the boundaries.

## TL;DR
Day-20 contract (240 questions) plus a 12-question `d21` unit made of **two OCaml native members**: a loader
executable and a `.cmxs` plugin (an ELF shared object). The loader has no scored config; the plugin holds
exactly one CRC32-valid HCFG record, and both the "config" and "plugin config" fields come from it. The
questions named every member and rule explicitly, so the change was one small handler. Single solve and
time trial passed on the first submit.

## Artifact
WinZip-AES ZIP (password `infected`). New members in ZIP order: `d21--variant-000-loader.elf` and
`d21--variant-000-plugin.cmxs`.

Fields: `d21_artifact_sha256_{1,2}`, `d21_analysis_loader_machine`, `d21_analysis_plugin_machine`,
`d21_analysis_config_{campaign,domain,mutex,url}` and `d21_analysis_plugin_config_{campaign,domain,mutex,url}`.

As on Days 19 and 20, the new question texts were fully self-describing. For example:

> In evidence.zip, Use the unique d21-- member whose basename ends plugin.cmxs. Read the ELF e_machine
> field and submit its unsigned base-10 numeric value (for example, do not substitute an architecture label).

> … Use the d21-- plugin.cmxs member; the loader has no scored HCFG config. Scan the specified member for
> literal HCFG magic and accept the first record whose bounds, CRC32, and decoded JSON validate. …

## Solution
- `artifact_sha256_N`: SHA-256 of the d21 members in ZIP central-directory order (loader first).
- `loader_machine` / `plugin_machine`: `e_machine` in decimal, `62` for both.
- Config fields: scan the plugin for literal `HCFG`, keep the first record whose length fits the member,
  whose CRC32 matches, and whose payload parses as JSON. The same values fill both the `config_*` and the
  `plugin_config_*` fields.

```python
loader = next((b for n, b in fl if os.path.basename(n).lower().endswith("loader.elf")), None)
plugin = next((b for n, b in fl if os.path.basename(n).lower().endswith("plugin.cmxs")), None)
A["d21_analysis_loader_machine"] = machine_int(loader)
A["d21_analysis_plugin_machine"] = machine_int(plugin)
c = valid_hcfg(plugin)[0]["cfg"]
for pfx in ("d21_analysis_config_", "d21_analysis_plugin_config_"):
    for k in ("campaign", "domain", "mutex", "url"):
        A[pfx + k] = c.get(k, "none")
```

If the file names ever changed, the fallback picks the plugin by content (the ELF with `e_type` = `ET_DYN`).
The agent's diagnostics confirmed zero HCFG records in the loader and exactly one valid record in the plugin.

## Time Trial & Mastery
- **Single solve**: 252/252 computed, CORRECT on the first submit (about 1.7 s for the submit).
- **Time trial**: one process (start → gather → compute → submit), CORRECT in 3.6 s.
- **Mastery**: launched the same way. The morning agent's session ended right after launching it (its log
  file is empty), so no timing or set count was recorded for this mode; the event's final audit lists it as
  solved.

## Lessons / gotchas
- Pick each member by the basename suffix the question names, and keep a content-based fallback.
- "Shared library boundaries" was flavor: no question asked for exports, imports or relocations.
- When an agent dies mid-run, check the Game Master status rather than assuming the last step failed.
