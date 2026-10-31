# 👶 Warmups — lane overview

Every warmup is one sentence, `Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: <slug>`,
hidden behind that day's encoding. The answer is the slug, `word-word-word-NN` (answer id `message`, format `pattern`,
normalization `trim`). The prompt always names the codec in a riddle ("sixty-four", "thirteen steps", "sixteen
fingers", "eight fingers", "Adobe might recognize the neighbors"…).

Single Solve and Time Trial give one `blob.txt`. **Mastery compounds.** Day N bundles 5N − 2 blobs (3 on Day 1, 153 on
Day 31), and from Day 4 each blob is a numbered list of `NN<TAB><fragment>` rows where **row k is encoded with Day k's
codec**. Concatenating the decoded rows rebuilds the sentence, so the slug tail sits in the newest rows. Every new codec
therefore also had to work on a 4–13 character fragment surrounded by every older codec.

## Orientation challenges (Day 1)

| Challenge | What it was |
|---|---|
| [Welcome Robots](../day01/welcome-robots.md) | Checks the Game Master loop: `op=start` returns an `issued_flag`, and you submit it back as answer id `flag`. |
| [Read the Rules](../day01/read-the-rules.md) | The flag is an HTML comment injected client-side into the rules page. Static HTML doesn't contain it, so it needs a rendered DOM. Submitted on the CourseStack lesson on Day 1, and again through the Game Master once it supported the challenge (2026-10-20). |

## Day by day

| Day | Challenge | What it added |
|---|---|---|
| 01 | [A Little Based](../day01/warmups-a-little-based.md) | Base64. The slug template. Mastery = ZIP of `blob-NN.txt` with a `01\t` index prefix |
| 02 | [Half a Turn](../day02/warmups-half-a-turn.md) | ROT13. A general breadth-first transform solver (`solve_warmup.py`) |
| 03 | [Hex Appeal](../day03/warmups-hex-appeal.md) | Hex. No code change |
| 04 | [Two of a Kind](../day04/warmups-two-of-a-kind.md) | 8-bit binary. **Mixed-codec rows** in Mastery; best candidate per row by template-word score |
| 05 | [By the Numbers](../day05/warmups-by-the-numbers.md) | Decimal bytes. One delivery per set; ~7 s timer beaten with parallel fetches |
| 06 | [Eight Is Enough](../day06/warmups-eight-is-enough.md) | Octal. Numeric rows must never stay raw; rate-limited fetches retried |
| 07 | [Percent Chance](../day07/warmups-percent-chance.md) | URL `%XX`. Solved by the release-morning run; no notes survive |
| 08 | [Entity Relations](../day08/warmups-entity-relations.md) | HTML `&#NN;`. Mastery back to a single ZIP |
| 09 | [Escape Room](../day09/warmups-escape-room.md) | JSON `"\uXXXX"`. Structural row detection (`w9m.py`); first fully unattended day |
| 10 | [Thirty-Two Below](../day10/warmups-thirty-two-below.md) | Base32. `warm10.py` (syntax-gated row codecs + template), the base of every later solver |
| 11 | [Safe Travels](../day11/warmups-safe-travels.md) | base64url. Rate-limit backoff (`gmx.GMX`) for three parallel agents |
| 12 | [Back at You](../day12/warmups-back-at-you.md) | Reversed text (whole and per line) |
| 13 | [Opposite Day](../day13/warmups-opposite-day.md) | Atbash. **Per-position codec learning** with an English trigram model |
| 14 | [Seven Steps](../day14/warmups-seven-steps.md) | Caesar +7 |
| 15 | [Room Forty-Seven](../day15/warmups-room-forty-seven.md) | ROT47 |
| 16 | [Dot Com](../day16/warmups-dot-com.md) | Morse, decoding to a hex string. Timed modes untimed by default from here |
| 17 | [Bacon Bits](../day17/warmups-bacon-bits.md) | Bacon a/b groups as hex nibbles (16-symbol alphabet) |
| 18 | [Off the Rails](../day18/warmups-off-the-rails.md) | Rail fence, 3 rails. Real 30 s / 105 s timers that day |
| 19 | [Little Things](../day19/warmups-little-things.md) | Hex of UTF-16LE + BOM. `u16()` applied after every byte decoder |
| 20 | [Big Entrance](../day20/warmups-big-entrance.md) | Hex of UTF-16BE + BOM. **Template-guided search**; scorer floor; capped frontier |
| 21 | [Under Pressure](../day21/warmups-under-pressure.md) | Base64(gzip). `inflate()` by magic bytes on all three decode paths |
| 22 | [Deflated Ego](../day22/warmups-deflated-ego.md) | Base64(zlib). No code change |
| 23 | [Eighty-Five Alive](../day23/warmups-eighty-five-alive.md) | Adobe Ascii85 (+ bare a85, b85, Z85) |
| 24 | [String Theory](../day24/warmups-string-theory.md) | Netstrings, peeled before everything else |
| 25 | [You Have a Point](../day25/warmups-you-have-a-point.md) | `U+XXXX` code points. Solvers chained by import + monkeypatching |
| 26 | [Food for Thought](../day26/warmups-food-for-thought.md) | Brainfuck interpreter. **Strict-syntax labels outrank statistics**; pre-submit audit |
| 27 | [Monkey Business](../day27/warmups-monkey-business.md) | Ook!. No code change; audit routine |
| 28 | [Back in Sixteen](../day28/warmups-back-in-sixteen.md) | Hex reversed per character. Strict `revhex` row decoder |
| 29 | [Rotten Base](../day29/warmups-rotten-base.md) | ROT13 applied to Base64 text |
| 30 | [Percent Percent](../day30/warmups-percent-percent.md) | Double percent-encoding. First Single Solve the layer search missed |
| 31 | [One More Thing](../day31/warmups-one-more-thing.md) | Base64 → gunzip → Base32 |

## The Mastery row map

Row k of every Mastery blob (from Day k onward) uses Day k's codec. This table is the decoder order a solver needs at the
end of the event:

| Rows | Codecs |
|---|---|
| 01–06 | Base64 · ROT13 · hex · 8-bit binary groups · decimal bytes · octal bytes (`040`) |
| 07–11 | URL `%XX` · HTML `&#NN;` · JSON `"\uXXXX"` · Base32 · base64url |
| 12–15 | reversed text · Atbash · Caesar +7 · ROT47 |
| 16–20 | Morse→hex · Bacon→hex · rail fence (3) · hex UTF-16LE (`fffe…`) · hex UTF-16BE (`feff…`) |
| 21–25 | Base64(gzip) · Base64(zlib) · Adobe Ascii85 (`<~…~>`) · netstring (`1:N,`) · `U+XXXX` |
| 26–31 | Brainfuck · Ook! · reversed hex · ROT13(Base64) · double percent · Base64(gzip(Base32)) |

## How the lane evolved

**Days 1–3: one codec per blob.** A single breadth-first solver (identity, ROT13, Base64, Base32, hex, up to three layers)
accepted the first output containing both a slug and "Game Master". The only Mastery wrinkles were the ZIP bundle and
the `NN\t` index prefix.

**Day 4: the format that defined the lane.** Mastery blobs became multi-row lists with a different codec per row.
Decoding the whole blob gave ROT13'd slugs (one `incorrect`). The fix was to decode each row separately, keep the
candidate that best matched the known sentence, and concatenate. Days 5–6 added numeric codecs (decimal, octal), which
brought the first tie-break: a purely numeric row is never left undecoded. Day 10 added syntax rules such as "a
leading-zero token means octal".

**Days 5–11: timers and delivery logistics.** Day 1's timed modes ran ~30 s. Day 5's 23-set Mastery gave ~7 s, so 23
per-set deliveries were fetched from a thread pool (5.8 s total). The delivery layout changed twice (one ZIP → one
delivery per set → one ZIP). From Day 9, a headless agent solved each day unattended from WSL. From Day 10, three
agents ran in parallel on one Game Master token. From Day 11, every call went through a rate-limit backoff wrapper.

**Days 12–15: letter ciphers break the scorer.** Reversal, Atbash, Caesar-7 and ROT47 all turn short fragments into
plausible letter soup. Day 13 got an `incorrect` (`quiet-grnnfh-copper-23`). The answer was to **learn the codec per row
position across the bundle**: average an English letter-trigram score per (row index, codec) over all blobs, then rank
each row's candidates by the learned codec.

**Days 16–20: compound codecs and the scale wall.** Morse that decodes to hex, Bacon groups as hex nibbles, rail-fence
transposition, and UTF-16 (applied as a post-step after every byte decoder). At 20 rows, the combination search never
finished (99% CPU, 1.8 GB, killed). The **template-guided search** replaced it: the concatenation so far must remain a
prefix of the known sentence, then become a slug. That makes the search linear in the number of rows.

**Days 21–25: wrappers and strict formats.** gzip/zlib by magic bytes (never header-less deflate), framed Ascii85,
netstrings and code points. Each was treated as unambiguous once its strict syntax matched, which skips the
ROT/Atbash/Base64 candidates. Day 25 also changed how the code was built: from then on each day's solver is a small
module that imports the previous one and monkeypatches `layers()`, `line_decode_l()` and `solve_blob()` in `warm24`.

**Days 26–31: esoteric languages, chains and audits.** A sandboxed Brainfuck/Ook! interpreter, then reversed hex,
ROT13-of-Base64, double percent and Base64→gunzip→Base32. Day 26's `incorrect` (a ROT47 "decode" of an Ascii85 row beat
the real one inside the slug) produced `STRONG_LABELS`, the rule that strict-syntax codecs always outrank the
statistical ones. It also produced the pre-submit audit: an exact case-sensitive template match, a scan for slug words
that appear only once (a misdecoded row shows up as a one-off non-word), and, from Day 28, a check that the slug tail
equals the strict decode of the newest rows.

**Timer policy** changed throughout: ~30 s (Day 1), ~7 s (Day 5), ~12 s (Day 10), untimed (Day 13), 30 s (Day 14). From
Day 16 the Game Master made Time Trial and Mastery "regular scored challenges by default" (untimed unless `run_for_time:true`
is requested). Day 18's warmups were the last with real timers (30 s / 105 s).

## Reusable techniques
- **Known-plaintext constraint.** The whole message is known except for the slug, so prune every search by prefix match
  against it instead of scoring and hoping.
- **Detect strictly, then decode.** Framing (`<~ ~>`, `H4sI`, BOM, `%25`), alphabet (`[01]{8}`, `[A-Z2-7]`, a/b only),
  structure (netstring lengths, nesting brackets) and padding identify most codecs without any statistics.
- **Statistics only for letter ciphers**, and pooled across the bundle (row position → codec), never on one fragment.
- **Post-steps on every byte decoder:** `inflate()` by magic and `u16()` by BOM or zero-byte pattern, so wrappers stack.
- **Cap and deduplicate every search frontier**, and give degenerate input (no letters) the worst score.
- **Offline first:** save `start.json` and the artifact, run `warm<N>.py local <dir>`, audit, diff against a dry run,
  then submit exactly once. Refuse to submit when any `answer_id` is missing.
- **Grow the solver by import + monkeypatch**, one small file per day, so earlier days keep working unchanged.

## Hardest moments
- **Day 4:** the first mixed-codec bundle. Whole-blob decoding gave ROT13'd slugs and an `incorrect`, and it took
  printing a blob row by row to see the per-row codecs.
- **Day 5:** a ~7 s Mastery timer for 23 separate deliveries, beaten by parallel fetch in 5.8 s.
- **Day 13:** short slug fragments that Atbash, ROT13 and reversal all decode into slug-shaped words. Solved by learning
  the codec per row position.
- **Day 20:** the combination search ran out of memory and time at 20 rows. The template-guided search replaced it.
- **Day 26:** two blobs out of 128 wrong because ROT47 garbage out-scored a real Ascii85 decode. Led to strict-label
  precedence and the audit.
- **Days 28 and 31:** a row with no decoder doesn't fail. It disappears into a minutes-long fallback. Since then:
  test one blob first, and write a strict row decoder for each new codec.
- **Day 7:** the one day without first-hand notes. The scheduled run solved it, and only the codec can be confirmed
  after the fact.
