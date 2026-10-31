# 🌐 Web Exploitation — lane overview

The sixth and newest lane. Instead of a downloadable artifact, every challenge provisions one or more **live target web apps**: a started attempt returns `targets[]`, each with a `url`, and the answer is a proof string read out of the running app (`proof_<32 hex>`, submitted as `exact_text` under answer id `proof-1`, or `proof-1..N` in mastery — one per target). Each challenge is a different web framework and a different classic vulnerability, with routes, parameter names, ids, and error strings **randomized per attempt**, so nothing can be hard-coded; the exploit has to be rebuilt live from what the target discloses.

31 web challenges were released on GM days 19–31 (web has its own cadence). All were solved in all three modes — 93/93 — the full web event.

## Challenges

| Day | Challenge | What it added |
|---|---|---|
| 01 (GM 19) | [Back Up a Minute](../day01/web-back-up-a-minute.md) | Backup exposure: robots `Disallow` → directory listing → `.json.bak` proof |
| 02 (GM 19) | [Permission to Slip](../day02/web-permission-to-slip.md) | IDOR: foreign-owned record id from the activity feed, read via the object API |
| 03 (GM 19) | [Query Me This](../day03/web-query-me-this.md) | Blind boolean SQLi (UNION/comments filtered); threaded per-char extraction |
| 04 (GM 20) | [Stay in Your Directory](../day04/web-stay-in-your-directory.md) | LFI/path traversal to `/run/huntress/objective.txt` |
| 05 (GM 20) | [Administratively Speaking](../day05/web-administratively-speaking.md) | Broken access control; introduces the `/api/clues` recon endpoint |
| 06 (GM 21) | [Reflect Upon This](../day06/web-reflect-upon-this.md) | Reflected XSS gated behind a `nonce` + `Referer` callback |
| 07 (GM 21) | [Stored for Later](../day07/web-stored-for-later.md) | Stored XSS executed by an authenticated reviewer bot |
| 08 (GM 21) | [Session Impression](../day08/web-session-impression.md) | Session fixation: plant the victim's leaked session id |
| 09 (GM 22) | [Forged With Care](../day09/web-forged-with-care.md) | CSRF: `csrf_token` ignored, `Sec-Fetch-Site: cross-site` is the gate |
| 10 (GM 22) | [Uploading Expectations](../day10/web-uploading-expectations.md) | Upload filter bypass (lowercase `.html`) → SSTI `{{objective}}` |
| 11 (GM 23) | [Template Temper](../day11/web-template-temper.md) | SSTI/SpEL: `{{objective}}` in the Spring render context |
| 12 (GM 23) | [Ask Again Later](../day12/web-ask-again-later.md) | Deferred/second-order SQLi via a stored filter |
| 13 (GM 23) | [Posted Too Much](../day13/web-posted-too-much.md) | Mass assignment: over-post a privileged property |
| 14 (GM 24) | [The API Has Opinions](../day14/web-the-api-has-opinions.md) | Combinatorial API authz gap (id × field × action) |
| 15 (GM 24) | [Fetch Quest](../day15/web-fetch-quest.md) | SSRF to a loopback-only internal service (`:8080`) |
| 16 (GM 25) | [Shell Company](../day16/web-shell-company.md) | OS command injection (`; cat /run/huntress/objective.txt`) |
| 17 (GM 25) | [Reset Expectations](../day17/web-reset-expectations.md) | Reset token not bound to the account it's redeemed against |
| 18 (GM 25) | [Resolver Revolt](../day18/web-resolver-revolt.md) | GraphQL field-level authz bypass via the record resolver |
| 19 (GM 26) | [Trust the Webhook](../day19/web-trust-the-webhook.md) | Forged-webhook trust: no signature check, just a well-formed event |
| 20 (GM 26) | [Serialized Offender](../day20/web-serialized-offender.md) | Insecure deserialization of a client-supplied session blob |
| 21 (GM 27) | [Double Spent](../day21/web-double-spent.md) | Double-spend / TOCTOU race on a one-shot credit |
| 22 (GM 27) | [Socket to Me](../day22/web-socket-to-me.md) | Unauthorized WebSocket event stream (`?stream=`) |
| 23 (GM 27) | [Forwarded Misgivings](../day23/web-forwarded-misgivings.md) | Trusted reverse-proxy header spoof (`X-Forwarded-For: 127.0.0.1`) |
| 24 (GM 28) | [Fail Open Friday](../day24/web-fail-open-friday.md) | Fail-open authorization (decode exception → allow) |
| 25 (GM 28) | [If a Breach Falls in a Log](../day25/web-if-a-breach-falls-in-a-log.md) | Log/audit discrepancy (export masked as `page_view`) |
| 26 (GM 29) | [Trust the Build](../day26/web-trust-the-build.md) | Signed-manifest integrity bypass (stale signature never re-checked) |
| 27 (GM 29) | [Internal Affairs](../day27/web-internal-affairs.md) | SSRF chained into object-level authz (foreign case id) |
| 28 (GM 30) | [Pass the Identity](../day28/web-pass-the-identity.md) | Delegated-identity header trust (`X-Delegated-User: executive`) |
| 29 (GM 30) | [Queue the Confusion](../day29/web-queue-the-confusion.md) | Queue owner-binding bypass (queue as `restricted_owner`) |
| 30 (GM 31) | [Framework Roulette](../day30/web-framework-roulette.md) | Final gauntlet: reskinned vuln + `Vary`-leaked role header; mastery mixes the catalog |
| 31 (GM 31) | [Full Stack Incident](../day31/web-full-stack-incident.md) | Final gauntlet: multi-stage reproduce-then-remediate chain |

## How the lane evolved

**No artifact, live targets.** The whole lane runs against ephemeral containers. A started attempt returns `targets[]`; an untimed target idles out after ~30 minutes of inactivity, and a fresh start gives a fresh one. Don't thrash the same slot with concurrent start/retry, and never mix the bare-API path with the browser arena on one challenge — they share the single live-target slot and expire each other's targets.

**Modes and the clock.** Every challenge has three modes. Single Solve is untimed and root-mounted. Time Trial and Mastery carry a server-enforced countdown (ranked deadline 120 s in the catalog), but the GM exposes a dual pool: sending `run_for_time:false` on the `/time_trial` and `/mastery` routes plays the *same* mode **untimed**, with no Hall-of-Fame time. We solved every timed mode this way — the headless timed container is unreachable for ~60 s while booting and then serves `expired`, so fighting the clock headless is a losing game. The single-solve route (base id, no suffix) rejects `run_for_time` entirely (`timed_intent_not_available`), so the key is omitted there and set to `false` only on the two suffixed routes. Mastery bundles grow over the lane — 2 sets early (days 01–07), stepping to 3, 4, 5, 6, and 8 sets by Day 31 — and **mixes challenge types**, so each target is classified and solved independently.

**`/api/clues` and the compounding contract.** From Day 05 on, most targets link a `GET /api/clues` JSON object that names the randomized routes and markers. This is the lane's recon backbone. Over time a vocabulary of clue keys accreted — `callback_nonce`, `session_hint`, `moderator_data_route`, `preferences_route`, `upload_shape`, `feature_route`, `secondary_route`, `inventory_route`, `protected_reference`, `stream_reference`, `deployment`, `policy_format_route`, `update_feed`, `case_directory_route`, `identity_directory_route`, `owner_directory_route`, `final_route`/`request_log_route`, … — and the grader's `effect` labels (`framework_authorization_bypassed`, `serialized_role_trusted`, `queue_owner_binding_bypassed`, `incident_detected_and_remediated`, …) became the proof oracle. Several late challenges deliberately reuse the *generic* `{feature_route}` or `{feature_route, secondary_route}` shape with no unique key, so they can only be told apart by a cheap live probe. The final gauntlet (Days 30–31) strips even the skins and randomizes route/error names, forcing pure behavioral classification; mastery there mixes the entire back catalog.

## Reusable toolchain

One unified headless solver drives the whole lane: [`solvers/web/webrun.py`](../solvers/web/webrun.py). It is API-only (no browser), provisions each mode, polls for readiness, and for every target runs `detect(home, clues, url)` → one of ~30 type tags → the matching `solve_<type>` function, mapping one proof per target so mixed mastery bundles just work. `detect()` fetches `/api/clues` and branches on its fields first (the reliable discriminator), falling back to HTML heuristics and, for the ambiguous generic shapes, to a cheap live probe:

- **Unique clue keys** route directly: `callback_nonce`→reflect, `session_hint`→session, `stream_reference`→websocket, `deployment`→forwarded, `policy_format_route`→failopen, `update_feed`+`update_policy`→trustbuild, `case_directory_route`+`topology_route`→internalaffairs, `identity_directory_route`→delegidentity, `owner_directory_route`→queuebind, `final_route`+`request_log_route`→fullstack, `recovery_guide_route`→resettoken, `event_type`+`owner_scope`→webhook, `state_format_route`→deserialize, `input_parameter`+`example_path`→cmdinject, `inventory_route`/`protected_reference`→apiauthz.
- **Ordering matters:** keys that carry a `feature_route` but no `secondary_route` (webhook, deserialize, websocket, forwarded, failopen, trustbuild, internalaffairs) are checked *before* the generic feature-route block, or they misdetect as admin/SSTI. Keys that carry both routes (delegidentity, queuebind, fullstack) are checked before the feat+sec block, or their 403/400 secondary misroutes to massassign/admin.
- **Live probes** disambiguate the truly generic shapes: feature-route-no-secondary → probe `?template={{7*7}}` (49 ⇒ SSTI/day-11, else admin/day-05); feat+sec → `GET secondary_route` and read the body (`missing_event`/`page_view`+`export_id`⇒logaudit, `credit`/`overspent`⇒doublespend, `internal_only`⇒ssrf, 403 `administrator_required`⇒massassign, rows/`delayed_query`⇒delayedsqli); day-30's forwarded skin is caught by `evaluated_client`/`gateway_context`/`loopback` in a bare feature GET.

Supporting scripts live alongside it: [`recon_web.py`](../solvers/web/recon_web.py) (dumps targets + home + `/api/clues` + `/openapi.json` + `/robots.txt` — the first step for any new-type triage), and the superseded early per-type scripts [`web01_backup.py`](../solvers/web/web01_backup.py), [`web02_idor.py`](../solvers/web/web02_idor.py), [`webrun_sqli.py`](../solvers/web/webrun_sqli.py), [`web_tt_oneshot.py`](../solvers/web/web_tt_oneshot.py). `webrun.py --backlog` clears every unsolved web mode across all released challenges and is what the daily automation ran.

Recurring techniques worth keeping:

- **Rebuild from the live target every time** — read the routes, parameter names, and ids out of `/api/clues`, the homepage, and 400/405 error bodies rather than hard-coding anything.
- **Spray a superset** when the exact privileged field/value/header name is randomized — used for mass assignment (Day 13), forged webhook (Day 19), deserialization role (Day 20), and the delegated-identity header (Day 28).
- **Chain two weaknesses** — stored XSS + reviewer privileges (Day 07), SSRF + missing object authz (Day 27), and the full reproduce-then-remediate chain (Day 31).
- **Thread the slow primitives** — blind boolean SQLi (Day 03) is the only solver at real risk against a clock; a `ThreadPoolExecutor` over the per-character search keeps it fast.
- **Classify by behavior, not skin** — the final gauntlet randomizes names, so `detect()`'s live probes carry the load.

## Hardest moments

- **The lane was missed entirely at first.** The original auto-solver grouped only five lanes (script / warmups+metadata+mobile / binary); web was never attempted until it was discovered on 2026-10-19 via the GM guidance ("across six lanes … Web Exploitation"). This was a tooling gap, not a blocked token — once a web lane was wired in, the backlog cleared quickly.
- **Day 21 (Double Spent) wedged a slot.** Before `detect()` knew about the double-spend type, the backlog misclassified it as mass assignment and POSTed to the feature route, spending the single credit and leaving the instance stuck at 0 — and a consumed single-solve instance only reprovisions after the ~30-minute idle reset (`retry` is `operation_not_allowed` for single). The fix was to pause the watcher, kill the in-flight backlog, let the slot idle for 30 minutes, then fire a barrier-synchronized burst as the *first* writes on a fresh instance. With `detect()` now routing it to the race solver, first contact is the burst.
- **Day 19 (Trust the Webhook) looked like crypto.** 1344 HMAC combinations (header names × secrets × algorithms × encodings × prefixes), malformed JSON, every signature header, and a JWT `alg:none` all returned the same flat `webhook_rejected`. There was no signature to defeat — the gate only wanted a complete, well-formed event — so the solver sprays a superset event body.
- **Day 24 (Fail Open Friday) inverted the obvious attack.** A forged "allow" decision with the right prefix is still *denied* (the decision is honestly evaluated); the proof comes from making the decoder *throw*, so the caught exception fails open.
- **Day 30 (Framework Roulette) hid the header name.** The second-layer role header's name is randomized per instance; 587 common names × values were flat-rejected. The only way in was reading the disclosed name out of the response `Vary: x-arena-<hex>` header — and using the value `administrator` even though the gate's policy said `staff_only`.
- **Browser-only `read-the-rules`.** The Day-1 orientation freebie's flag is injected into a client-rendered HTML comment on the rules page by JavaScript; a plain `requests` GET returns only the Next.js shell, so it needed a rendered DOM (browser) to read the comment — the one web-adjacent task the headless HTTP solver couldn't do alone.
