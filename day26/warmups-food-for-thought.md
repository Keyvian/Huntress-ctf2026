# 👶 Food for Thought

| | |
|---|---|
| **Day** | 26 |
| **Lane** | 👶 Warmups |
| **Challenge ID** | `warmups-day-26` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day26_quick/warm26.py`](../solvers/day26_quick/warm26.py) · audit [`warm_audit26.py`](../solvers/day26_quick/warm_audit26.py) · row dump [`warm_rows26.py`](../solvers/day26_quick/warm_rows26.py) |

## Prompt
> A very small language has quite a lot to say.

## TL;DR
**Brainfuck**. The blob is a 3.4 KB program of `+-<>[].` whose output is the sentence. `warm26.py` adds a pure-Python
Brainfuck interpreter (artifact code is interpreted, never executed natively). Mastery cost one wrong submit: on two
blobs, a ROT47 "decode" of the Ascii85 row out-scored the real one. The fix was to rank **strict-syntax codecs first** and
to audit every bundle before submitting.

## Artifact
- Single Solve and Time Trial: one Brainfuck program (`+-<>[].` only).
- Mastery: 128 sets, **26 rows** per blob. Every earlier codec in day order (b64, rot13, hex, binary, decimal, octal,
  URL, HTML, JSON `\u`, base32, b64url, reverse, atbash, caesar, rot47, morse→hex, bacon→hex, rail, UTF-16LE/BE hex,
  gzip-b64, zlib-b64, Ascii85, netstring, `U+` code points), plus **row 26, a Brainfuck program printing the slug tail**
  (e.g. `de-40`).

## Solution
`bf_run()` run-length-compiles `+ - < >` runs, precomputes the matching bracket for every `[`/`]`, then runs on a 64 KiB
tape of 8-bit wrapping cells, with `,` = EOF (0) and a step cap. `ook_to_bf()` (Ook! and short Ook) also feeds it. A
strict search over generic 8-symbol dialects (bracket pair found by equal counts and proper nesting, output symbol by a
message-length count, the other four symbols tried in every permutation of `+-<>`) runs only on whole blobs.

The Mastery bug: blobs 22 and 106 decoded their middle slug word as `kOoADvROmle`. On 4-character slug fragments, the
per-position ranking from Day 13 put the ROT47 of the framed Ascii85 row `<~@psG#~>` above the real decode `cast`, and the
lowercase template search then accepted it. The fix in `warm26.solve_mixed` puts strict-syntax labels first on every
row:

```python
STRONG_LABELS = {"a85", "ns", "cpU", "cpbs", "cpx", "cphtmlx", "cphtml", "cp0x", "bf", "ook", "bfx", "json", "html",
                 "url", "bin", "dec", "oct", "hex", "b32", "morsehex", "morseb32", "morsedec", "morse", "morselow",
                 "baconhex", "baconhexstr", "bacon", "bacon24", "baconup"}       # + any *gz / *16 label, padded b64
lc.sort(key=lambda t: (0 if _strong(t[0], f) else 1, rank.index(t[0]) if t[0] in rank else 99, -eng_score(t[1])))
```

## Time Trial & Mastery
All modes were regular untimed attempts. Single and Time Trial were CORRECT. The first Mastery run crawled for over
10 minutes because the generic dialect search ran on every row. It is now gated (≥ 64 tokens, ≤ 8 symbols, one nesting
bracket pair, ≤ 48 runs × 300k steps) and turned off for rows, and all 128 blobs compute in ~3 s. The one `incorrect`
full submit cost nothing in an untimed mode. `warm_audit26.py` (exact case-sensitive template match per blob, slug-word
frequency) found the two bad blobs in seconds. With the precedence fix, Mastery was CORRECT for all 128.

## Lessons / gotchas
- Learned per-position ranks are unreliable inside the slug, where the template gives no constraint. There, strict
  syntax must beat English statistics.
- Audit before the one Mastery submit. A wrong row decode shows up as a non-word that appears only once (a
  singleton like `kOoADvROmle`) among slug words that otherwise repeat across blobs.
- Interpret esoteric-language artifacts in a sandboxed interpreter with step limits. Never compile or run them.
