# ⚙️ Crystal Clear

| | |
|---|---|
| **Day** | 13 |
| **Lane** | ⚙️ Binary Reverse Engineering |
| **Challenge ID** | `binary-reverse-engineering-day-13-crystal-dns-configuration` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day13_binary/b13.py`](../solvers/day13_binary/b13.py) · [`peek11.py`](../solvers/day13_binary/peek11.py) |

## Prompt
> Crystal compiles to native code with a distinctive shine. Fingerprint the runtime, then follow the DNS labels — this one has somewhere it wants to resolve.

## TL;DR
Day-12 contract plus a 10-question `d13` unit: a Crystal ELF whose config is a Base64 `SENG…` text inside a
Crystal `String` object in `.rodata`. Same fields and handler as `d09`/`d11`/`d12`. The only subtlety was
that `hcfg_offset` points at the first character of the text, not at the 12-byte Crystal string header
before it. The "DNS labels" were flavor text.

## Artifact
WinZip-AES ZIP (password `infected`), mastery 3 sets. The `d13` binary is a dynamically linked x86-64
Crystal ELF that links the Boehm GC (`GC_*` symbols), carries `/usr/share/crystal/src/...` paths and has a
`.gcc_except_table` section. In every variant seen (000, 002, 005, 007) the `SENG` literal was at file
offset 560188.

## Solution
A Crystal `String` in `.rodata` is laid out as `type_id` (1), then LE32 `bytesize`, LE32 `length` (here
`0x1fc`), then the bytes. The bytes are Base64 of a standard HCFG record.

| Field | Value |
|---|---|
| `format` / `architecture` / `machine` | `elf` / `x86-64` / `62` |
| `config_{campaign,domain,mutex,url}` | `BR13-000`, `node-000.day13.example.invalid`, `Global\HuntressBR13_000`, `https://node-000.day13.example.invalid/api/BR13-000` |
| `config_crc32_hex` | `0x%08x` of CRC32 over the decoded JSON |
| `hcfg_offset` | offset of the `S` of `SENG…`, `560188` (not the string header 12 bytes earlier) |

The decoded JSON also has `ipv4`, `windows_path`, `linux_path`, `service` and `host_model`; none were asked.

Distractors in `.rodata`: `decoy` / `sandbox` / `failure` strings, a `huntress.binary.dynamic_trace.v1`
template (`loopback_dns_query_plan`, `synthetic_dns_plan_only`) and a NamedTuple layout. There is no
length-prefixed DNS label encoding of the domain outside the Base64 config; "follow the DNS labels" does not
correspond to any question.

The change to the solver was adding `"d13"` to the handler tuple. Single solve banked the nine `d13` fields,
then `hcfg_offset` alone, then the rest.

## Time Trial & Mastery
Windows were longer this day: 80 s for time trial and 200 s for mastery (30 s on the days before and after).

| Mode | Questions | Time used / window |
|---|---|---|
| time_trial | 130 | 5.2 s / 80 s, one shot |
| mastery | 390 (3 × 130) | 8.1 s / 200 s, one shot |

## Lessons / gotchas
- For a language runtime string object, the offset answer is the start of the payload bytes, consistent
  with `d09` and `d11`.
- Prompts that mention a technique (DNS labels, templates, record layouts) are usually flavor. Check the
  question list before investing in the technique.
