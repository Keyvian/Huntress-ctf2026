# Huntress CTF 2026 — "AI Arena" writeups

Writeups for all **189 challenges** of the 31-day Huntress CTF 2026 ("AI Arena" edition), every one solved in every mode it offered (**561/561 challenge-modes**).

The edition was built for AI agents: a Game Master API hands out artifacts or live targets, times attempts and grades structured answers, and the challenges compound day after day. Most days were solved unattended by headless Claude agents launched by a scheduled task at the 09:00 ET release (see [How the solving was automated](docs/automation.md)).

> **Flags are redacted** throughout (`<redacted>`); flags were unique per team anyway. No credentials, tokens or challenge artifacts are included.

## Start here

- [The Game Master: modes, delivery and scoring mechanics](docs/game-master.md): read this first, every writeup assumes it.
- [How the solving was automated](docs/automation.md): the scheduled multi-agent pipeline and the web-lane watchdog.
- Lane overviews (how each lane evolved over 31 days):
  - [👶 Warmups](lanes/warmups.md)
  - [🔎 Metadata Forensics](lanes/metadata.md)
  - [📜 Script Analysis](lanes/script.md)
  - [📱 Mobile Android](lanes/mobile.md)
  - [⚙️ Binary / Reverse Engineering](lanes/binary.md)
  - [🌐 Web Exploitation](lanes/web.md)

## Special challenges

- [Welcome Robots](day01/welcome-robots.md): Day 1
- [Read the Rules](day01/read-the-rules.md): Day 1
- [⚙️ SHA1-Hulud](day30/binary-sha1-hulud.md): Day 30

## Challenges by day

Web Exploitation challenges are filed under their own number (web day-NN); they were released on GM days 19–31.

| Day | 👶 Warmups | 🔎 Metadata | 📜 Script | 📱 Mobile | ⚙️ Binary | 🌐 Web |
|---|---|---|---|---|---|---|
| [01](day01/README.md) | [A Little Based](day01/warmups-a-little-based.md) | [You Must Be This Hash to Ride](day01/metadata-you-must-be-this-hash-to-ride.md) | [Power Play](day01/script-power-play.md) | [Exported Trust](day01/mobile-exported-trust.md) | [ELF Aware](day01/binary-elf-aware.md) | [Back Up a Minute](day01/web-back-up-a-minute.md) |
| [02](day02/README.md) | [Half a Turn](day02/warmups-half-a-turn.md) | [Looks Can Be Deceiving](day02/metadata-looks-can-be-deceiving.md) | [Host With the Most](day02/script-host-with-the-most.md) | [Deep Link Drift](day02/mobile-deep-link-drift.md) | [Mangled](day02/binary-mangled.md) | [Permission to Slip](day02/web-permission-to-slip.md) |
| [03](day03/README.md) | [Hex Appeal](day03/warmups-hex-appeal.md) | [BOM Voyage](day03/metadata-bom-voyage.md) | [Expansion Pack](day03/script-expansion-pack.md) | [Intent Injection](day03/mobile-intent-injection.md) | [Table Manners](day03/binary-table-manners.md) | [Query Me This](day03/web-query-me-this.md) |
| [04](day04/README.md) | [Two of a Kind](day04/warmups-two-of-a-kind.md) | [Picture This](day04/metadata-picture-this.md) | [Dim and Dimmer](day04/script-dim-and-dimmer.md) | [Pending Intent Relay](day04/mobile-pending-intent-relay.md) | [Go Fish](day04/binary-go-fish.md) | [Stay in Your Directory](day04/web-stay-in-your-directory.md) |
| [05](day05/README.md) | [By the Numbers](day05/warmups-by-the-numbers.md) | [Chunk Norris](day05/metadata-chunk-norris.md) | [Hatch Careful](day05/script-hatch-careful.md) | [Backup Spill](day05/mobile-backup-spill.md) | [Rust Belt](day05/binary-rust-belt.md) | [Administratively Speaking](day05/web-administratively-speaking.md) |
| [06](day06/README.md) | [Eight Is Enough](day06/warmups-eight-is-enough.md) | [Portable Deception](day06/metadata-portable-deception.md) | [Shell We Begin](day06/script-shell-we-begin.md) | [Provider Paths](day06/mobile-provider-paths.md) | [Pool Party](day06/binary-pool-party.md) | [Reflect Upon This](day06/web-reflect-upon-this.md) |
| [07](day07/README.md) | [Percent Chance](day07/warmups-percent-chance.md) | [Seven-Zip, No Relation](day07/metadata-seven-zip-no-relation.md) | [Node by Node](day07/script-node-by-node.md) | [WebView Bridge](day07/mobile-webview-bridge.md) | [Routine Check](day07/binary-routine-check.md) | [Stored for Later](day07/web-stored-for-later.md) |
| [08](day08/README.md) | [Entity Relations](day08/warmups-entity-relations.md) | [What’s in the Box?](day08/metadata-whats-in-the-box.md) | [Lost in Translation](day08/script-lost-in-translation.md) | [Cleartext Session](day08/mobile-cleartext-session.md) | [Swift Justice](day08/binary-swift-justice.md) | [Session Impression](day08/web-session-impression.md) |
| [09](day09/README.md) | [Escape Room](day09/warmups-escape-room.md) | [Built Different](day09/metadata-built-different.md) | [All the World's a Stager](day09/script-all-the-world-s-a-stager.md) | [Trust Everyone](day09/mobile-trust-everyone.md) | [Nimble](day09/binary-nimble.md) | [Forged With Care](day09/web-forged-with-care.md) |
| [10](day10/README.md) | [Thirty-Two Below](day10/warmups-thirty-two-below.md) | [Where Do We Begin?](day10/metadata-where-do-we-begin.md) | [Bind Over Matter](day10/script-bind-over-matter.md) | [Network Config Split](day10/mobile-network-config-split.md) | [Zig Zag](day10/binary-zig-zag.md) | [Uploading Expectations](day10/web-uploading-expectations.md) |
| [11](day11/README.md) | [Safe Travels](day11/warmups-safe-travels.md) | [What’s My Name Again?](day11/metadata-whats-my-name-again.md) | [By Any Other Name](day11/script-by-any-other-name.md) | [Local Secrets](day11/mobile-local-secrets.md) | [D-Day](day11/binary-d-day.md) | [Template Temper](day11/web-template-temper.md) |
| [12](day12/README.md) | [Back at You](day12/warmups-back-at-you.md) | [Managed Expectations](day12/metadata-managed-expectations.md) | [AutoIt Takes Two](day12/script-autoit-takes-two.md) | [SQLite Assumptions](day12/mobile-sqlite-assumptions.md) | [Pascal's Wager](day12/binary-pascal-s-wager.md) | [Ask Again Later](day12/web-ask-again-later.md) |
| [13](day13/README.md) | [Opposite Day](day13/warmups-opposite-day.md) | [Product Placement](day13/metadata-product-placement.md) | [Zip Code](day13/script-zip-code.md) | [Keystore Misuse](day13/mobile-keystore-misuse.md) | [Crystal Clear](day13/binary-crystal-clear.md) | [Posted Too Much](day13/web-posted-too-much.md) |
| [14](day14/README.md) | [Seven Steps](day14/warmups-seven-steps.md) | [The Shortcut Home](day14/metadata-the-shortcut-home.md) | [Trust the Process](day14/script-trust-the-process.md) | [Predictable Crypto](day14/mobile-predictable-crypto.md) | [Selective Memory](day14/binary-selective-memory.md) | [The API Has Opinions](day14/web-the-api-has-opinions.md) |
| [15](day15/README.md) | [Room Forty-Seven](day15/warmups-room-forty-seven.md) | [A Word to the Wise](day15/metadata-a-word-to-the-wise.md) | [Crumb Trail](day15/script-crumb-trail.md) | [Native Library Secrets](day15/mobile-native-library-secrets.md) | [Stripped](day15/binary-stripped.md) | [Fetch Quest](day15/web-fetch-quest.md) |
| [16](day16/README.md) | [Dot Com](day16/warmups-dot-com.md) | [Return to Sender](day16/metadata-return-to-sender.md) | [Same Same, But Different](day16/script-same-same-but-different.md) | [JNI Boundary](day16/mobile-jni-boundary.md) | [Wasm Up](day16/binary-wasm-up.md) | [Shell Company](day16/web-shell-company.md) |
| [17](day17/README.md) | [Bacon Bits](day17/warmups-bacon-bits.md) | [Hear Me Out](day17/metadata-hear-me-out.md) | [Fetch Quest](day17/script-fetch-quest.md) | [Name Collapse](day17/mobile-name-collapse.md) | [Decoder Ring](day17/binary-decoder-ring.md) | [Reset Expectations](day17/web-reset-expectations.md) |
| [18](day18/README.md) | [Off the Rails](day18/warmups-off-the-rails.md) | [Frame of Reference](day18/metadata-frame-of-reference.md) | [Orphan Process](day18/script-orphan-process.md) | [Encrypted Strings](day18/mobile-encrypted-strings.md) | [Flow State](day18/binary-flow-state.md) | [Resolver Revolt](day18/web-resolver-revolt.md) |
| [19](day19/README.md) | [Little Things](day19/warmups-little-things.md) | [Little Endian on the Prairie](day19/metadata-little-endian-on-the-prairie.md) | [Sharp Practice](day19/script-sharp-practice.md) | [Reflection Maze](day19/mobile-reflection-maze.md) | [Jack in the Box](day19/binary-jack-in-the-box.md) | [Trust the Webhook](day19/web-trust-the-webhook.md) |
| [20](day20/README.md) | [Big Entrance](day20/warmups-big-entrance.md) | [Universal Appeal](day20/metadata-universal-appeal.md) | [The Butler Did It](day20/script-the-butler-did-it.md) | [Loaded Later](day20/mobile-loaded-later.md) | [Resourceful](day20/binary-resourceful.md) | [Serialized Offender](day20/web-serialized-offender.md) |
| [21](day21/README.md) | [Under Pressure](day21/warmups-under-pressure.md) | [Package Deal](day21/metadata-package-deal.md) | [Actions Speak Louder](day21/script-actions-speak-louder.md) | [Debug Me If You Can](day21/mobile-debug-me-if-you-can.md) | [Shared Custody](day21/binary-shared-custody.md) | [Double Spent](day21/web-double-spent.md) |
| [22](day22/README.md) | [Deflated Ego](day22/warmups-deflated-ego.md) | [Main Character Energy](day22/metadata-main-character-energy.md) | [Next, Next, Finish](day22/script-next-next-finish.md) | [Root of Trust](day22/mobile-root-of-trust.md) | [Bridge Troll](day22/binary-bridge-troll.md) | [Socket to Me](day22/web-socket-to-me.md) |
| [23](day23/README.md) | [Eighty-Five Alive](day23/warmups-eighty-five-alive.md) | [Page Me Maybe](day23/metadata-page-me-maybe.md) | [Press Start to Decode](day23/script-press-start-to-decode.md) | [Hook Line and Signal](day23/mobile-hook-line-and-signal.md) | [Trust Issues](day23/binary-trust-issues.md) | [Forwarded Misgivings](day23/web-forwarded-misgivings.md) |
| [24](day24/README.md) | [String Theory](day24/warmups-string-theory.md) | [Event Horizon](day24/metadata-event-horizon.md) | [Web of Lies](day24/script-web-of-lies.md) | [Emulator Alibi](day24/mobile-emulator-alibi.md) | [Spot the Difference](day24/binary-spot-the-difference.md) | [Fail Open Friday](day24/web-fail-open-friday.md) |
| [25](day25/README.md) | [You Have a Point](day25/warmups-you-have-a-point.md) | [Hive Mind](day25/metadata-hive-mind.md) | [Ashes to Assets](day25/script-ashes-to-assets.md) | [Integrity Signals](day25/mobile-integrity-signals.md) | [Out of Bounds](day25/binary-out-of-bounds.md) | [If a Breach Falls in a Log](day25/web-if-a-breach-falls-in-a-log.md) |
| [26](day26/README.md) | [Food for Thought](day26/warmups-food-for-thought.md) | [Before You Go](day26/metadata-before-you-go.md) | [Mixed Signals](day26/script-mixed-signals.md) | [Split Decision](day26/mobile-split-decision.md) | [Crash Course](day26/binary-crash-course.md) | [Trust the Build](day26/web-trust-the-build.md) |
| [27](day27/README.md) | [Monkey Business](day27/warmups-monkey-business.md) | [Packet Loss Prevention](day27/metadata-packet-loss-prevention.md) | [FROM Whence It Came](day27/script-from-whence-it-came.md) | [Dependency Surface](day27/mobile-dependency-surface.md) | [Compiler Says What](day27/binary-compiler-says-what.md) | [Internal Affairs](day27/web-internal-affairs.md) |
| [28](day28/README.md) | [Back in Sixteen](day28/warmups-back-in-sixteen.md) | [Where It All Began](day28/metadata-where-it-all-began.md) | [Out of Order](day28/script-out-of-order.md) | [Protocol Reconstruction](day28/mobile-protocol-reconstruction.md) | [Family Resemblance](day28/binary-family-resemblance.md) | [Pass the Identity](day28/web-pass-the-identity.md) |
| [29](day29/README.md) | [Rotten Base](day29/warmups-rotten-base.md) | [Trust Issues](day29/metadata-trust-issues.md) | [Make It Make Sense](day29/script-make-it-make-sense.md) | [White Box Key Recovery](day29/mobile-white-box-key-recovery.md) | [Fraternal Twins](day29/binary-fraternal-twins.md) | [Queue the Confusion](day29/web-queue-the-confusion.md) |
| [30](day30/README.md) | [Percent Percent](day30/warmups-percent-percent.md) | [Seeing Double](day30/metadata-seeing-double.md) | [Spill the Beans](day30/script-spill-the-beans.md) | [Layered Protections](day30/mobile-layered-protections.md) | [Campaign Trail](day30/binary-campaign-trail.md)<br>[SHA1-Hulud](day30/binary-sha1-hulud.md) | [Framework Roulette](day30/web-framework-roulette.md) |
| [31](day31/README.md) | [One More Thing](day31/warmups-one-more-thing.md) | [No Artifact Left Behind](day31/metadata-no-artifact-left-behind.md) | [The Full Transform](day31/script-the-full-transform.md) | [Mobile Arena Gauntlet](day31/mobile-mobile-arena-gauntlet.md) | [Final Boss](day31/binary-final-boss.md) | [Full Stack Incident](day31/web-full-stack-incident.md) |

## Repository layout

```
README.md            this index
docs/                Game Master mechanics, automation pipeline
lanes/               one overview page per lane
dayNN/               one writeup per challenge (all modes) + a day index
solvers/             solver scripts as used during the event (sanitized; paths/flags removed)
automation/          scheduled-task wrappers, agent prompts and the WSL GM helper (sanitized)
data/challenges.json challenge catalog: ids, titles, official prompts, mode metadata (no flags)
```

The solvers are kept as they ran during the event: research code, often one script per day that imports the previous day's. They need the GM helper in `automation/wsl/gm.py` and your own token, which is read from a file outside the repo.

## About these writeups

The organizers encouraged participants to use LLMs to write their writeups. These were drafted by Claude (Anthropic) from the solve notes, logs and solver code produced during the event.
