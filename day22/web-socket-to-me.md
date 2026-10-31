# 🌐 Socket to Me

| | |
|---|---|
| **Day** | 22 (released on GM day 27) |
| **Lane** | 🌐 Web Exploitation |
| **Challenge ID** | `web-exploitation-day-22-socket-to-me` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/web/webrun.py`](../solvers/web/webrun.py) (`solve_websocket`) |

## Prompt
> The chat upgraded to websockets and left its manners at the HTTP door. Ride the upgrade into an event stream that was never meant for you.

## TL;DR
An **unauthorized WebSocket event stream**. The WS upgrade is accepted with the privileged stream id in the query string, and on connect the server immediately pushes the proof — there is no authorization check on subscribing to the privileged channel.

## Artifact
No file; live target, proof `proof_<32 hex>`, answer id `proof-1` (mastery `proof-1..N`). Framework **Koa** (skin "Live Case Wire"). `GET /api/clues`:

```json
{"framework": "Koa", "feature_route": "/dispatch-<hex>", "current_role": "analyst", "stream_reference": <int>}
```

The unique clue key `stream_reference` is the privileged channel id.

## Solution
`feature_route` GET = `426 websocket_upgrade_required`; a bare WS upgrade → 403. The upgrade is accepted only with the stream id in the query:

```
wss://<host>/dispatch-<hex>?stream=<stream_reference>
```

(parameter `stream`; sweep `channel`/`id`/`ref`/`topic`/`room` as fallback). On connect, the server immediately pushes:

```json
{"ok": true, "effect": "unauthorized_event_stream", "evidence": "proof_…"}
```

Origin doesn't matter; there is no authz check on subscribing to the privileged stream. This needs the `websocket-client` pip library (added to the CTF venv). `solve_websocket` reads `stream_reference`, opens the `wss` URL with `?stream=`, and reads the first frames for `proof_`, falling back to an explicit subscribe message.

## Time Trial & Mastery
Played untimed via `run_for_time:false` (single omits it). Mastery bundles **5 sets** (the mastery set count steps up to 5 here), types possibly mixed. `detect()` keys on the unique `stream_reference` and runs it **before** the feature-route block (Day 22 has a `feature_route` but no `secondary_route`).

## Lessons / gotchas
- The channel id goes in the upgrade *query string*; a plain upgrade without it is rejected.
- The proof arrives unsolicited in the first frame(s) — read, don't just send.
- This was the one challenge needing a non-stdlib dependency (`websocket-client`). Shared live-target mechanics: [lane overview](../lanes/web.md).
