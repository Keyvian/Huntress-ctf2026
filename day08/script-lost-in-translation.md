# 📜 Lost in Translation

| | |
|---|---|
| **Day** | 08 |
| **Lane** | 📜 Script Analysis |
| **Challenge ID** | `script-analysis-day-08-cross-language-iocs` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | The Day-8 solver (`d8script_solve.py`, Homebase VM) was not preserved; its header decoder survives as `decode_analysis()` in [`solvers/day09/sdec.py`](../solvers/day09/sdec.py) |

## Prompt
> The same indicators show up in every language the campaign speaks, each with its own quoting, escaping, and encoding accent. Normalize them to their exact form and find the one that doesn't match its siblings.

## TL;DR
**615 questions over 74 files.** The Day-7 set grew by 146 questions: eight PHP "polyglot" specimens, four
"host" fixtures (a PHP webshell, an HTA, two WSF jobs) and two more advanced-syntax Bash files. This day
introduced the specimen format that dominated the rest of the event: a one-line
`HUNTRESS_ANALYSIS_V1:<ENC>-<payload>` header whose payload, in one of several encoding "accents", decodes
to a `v=3|…` descriptor that **records every answer, including role and ATT&CK**. No role/attack mapping is
needed for these files: read the recorded values.

## Artifact
WinZip-AES ZIP (`infected`). File counts by extension: ps1 3, js 11, cmd 5, bat 4, vbs 10, py 14, sh 10,
mjs 8, php 9.

New this day:

| Files | Questions |
|---|---|
| `polyglot-php-{benign-utility,stager,dropper,downloader,uploader,launcher,persistence-descriptor,staged-chain}.php` | 8 × 11 |
| `host-php-webshell-php.php`, `host-hta-jscript-javascript.js`, `host-wsf-jscript-jscript.js`, `host-wsf-mixed-vbscript.vbs` | 4 × 11 |
| `associative-arrays.sh` (feature `associative_arrays`, primitive `declare_associative`), `array-slicing.sh` (feature `array_slicing`, primitive `indexed_array_slice`) | 2 × 7 |

The 11 polyglot/host questions: `role`, `attack`, `adapter`, `campaign`, `url` or `file-path`,
`stage-count`, `steps`, `host-profile`, `obfuscation`, `stage-profile`, `next-language`.

## Solution
### The analysis header
A PHP polyglot (abridged):

```php
<?php
// HUNTRESS_ANALYSIS_V1:B64-dj0zfGxhbmd1YWdlPXBocHxyb2xlPXN0YWdlcnx…
declare(strict_types=1);
$descriptor_9ea3dd51 = "dj0zfGxhbmd1YWdlPXBocHxyb2xlPXN0YWdlcnx…";
$plan_9ea3dd51 = ["descriptor" => $descriptor_9ea3dd51];
```

The host fixtures wrap the same header in their container, e.g. a WSF job
`<job id="HuntressMixedAnalysis"><script language="VBScript"><![CDATA[ ' HUNTRESS_ANALYSIS_V1:HB64-…`.

The "accents" in the prompt are the payload encodings:

| Tag | Decode |
|---|---|
| `B64` | Base64 |
| `HEX` | hex |
| `HB64` | hex → Base64 → text (hex of Base64) |
| `FRAG` | hex broken up by `.` separators; strip all non-hex characters, then hex-decode |
| `URL` | percent-decoding (supported defensively by the decoder) |

```python
ANALYSIS = re.compile(r"HUNTRESS_ANALYSIS_V1:([A-Z0-9]+)-([^\s\"'<>\]]+)")
if e == "B64":  return base64.b64decode(p + "=" * (-len(p) % 4)).decode()
if e == "HEX":  return bytes.fromhex(p).decode()
if e == "HB64": return base64.b64decode(bytes.fromhex(p).decode()).decode()
if e == "FRAG": return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", p)).decode()
```

The decoded descriptor (the stager from the example above):

```
v=3|language=php|role=stager|verdict=suspicious|attack=T1105|adapter=runtime_loader|
host_profile=standalone|obfuscation_profile=base64|stage_profile=two_stage_download_execute|
next_language=jscript|stage_count=2|steps=acquire_remote,dispatch_process|campaign_id=PHP-<8 hex>|
url=https://php-<10 hex>.example.invalid/stage|file_path=/tmp/huntress-php/.<16 hex>.stage
```

### Answer mapping for polyglots and hosts
| Question | Source |
|---|---|
| role, attack, adapter | `role`, `attack`, `adapter` as recorded |
| campaign | `campaign_id` (`PHP-<8hex>`) |
| url / file-path | `url` / `file_path` |
| stage-count, steps | `stage_count`; `steps` with `,` → `>` |
| host-profile | `host_profile` (`standalone` for polyglots, the container name for host fixtures) |
| obfuscation | `obfuscation_profile` (`base64`, `plain_hex`, `hex_base64`, `fragmented_hex`, matching the header tag) |
| stage-profile, next-language | `stage_profile`, `next_language` |

The new Bash fixtures follow the [Day 7](../day07/script-node-by-node.md) advanced-syntax pattern
(`advanced_syntax`, `T1059.004`). Everything else is unchanged from earlier days.

The prompt's "the one that doesn't match its siblings" never became a separate question in the recorded
contract. Every file is answered on its own descriptor.

## Time Trial & Mastery
- Time Trial used the same contract (615 answers) on a fresh variant and was solved right after Single
  Solve.
- Mastery was **3,075 answers (5 sets)**. The big mastery attempts came up **untimed** through `start`
  (`deadline: null`). The variant-dependent Batch `expansion`/`control` fields still needed candidate
  brute force, so Mastery ran as a detached background grind on the VM (bank deterministic groups, then try
  label candidates) until it returned CORRECT.

## Lessons / gotchas
- Once a specimen *records* its own role and ATT&CK ID, use the recorded values. Later days showed recorded
  roles that disagree with the steps (e.g. a `benign_utility` whose steps look like a dropper), and the grader
  wanted the recorded value every time.
- `FRAG` dots can fall anywhere, including mid-byte, so strip separators before hex-decoding instead of
  splitting on them.
- This header format carried the lane for the remaining 23 days. The decoder only had to be extended three
  times: split arrays ([Day 18](../day18/script-orphan-process.md)), headers inside escaped string literals
  ([Day 19](../day19/script-sharp-practice.md)) and layered `LYR` chains
  ([Day 23](../day23/script-press-start-to-decode.md)).
- Previous: [Day 7](../day07/script-node-by-node.md) · Next: [Day 9](../day09/script-all-the-world-s-a-stager.md).
