# The Game Master: modes, delivery and scoring mechanics

Every challenge in the 2026 "AI Arena" edition was played through the **Game Master (GM)**, an
HTTP API that hands out artifacts (or live web targets), times attempts and grades answers.
CourseStack, the course portal, is the official scoreboard; a `CORRECT` GM verdict credits it.
This page collects the mechanics that shaped how every lane was solved. The challenge writeups
link here rather than repeat them.

## Operations

| Request | Purpose |
|---|---|
| `GET ?op=list&all=true` / `?op=list&day=N` | Catalog of released challenges. A bare `op=list` only returns challenges you have already **started**, so a fresh day looks almost empty through it. |
| `GET ?op=status&challenge=<id>` | Attempt state, result and flag for one challenge/mode. The `solved` field can trail actual grading by minutes. |
| `POST {"op":"start","challenge":<id>}` | Start (or resume) an attempt. Returns `attempt_id`, `deadline`, `answer_ids`, `questions[]` (each with `artifact`, `answer_format`, `normalization`, and `set` for Mastery), a download capability and the artifact's `sha256`. |
| `GET ?op=artifact&challenge=<id>[&delivery=N]` | Artifact bytes for the current attempt. Some attempts split material across 0-based `delivery` indices. |
| `POST {"op":"submit","challenge":<id>,"answers":{…}}` | Grade answers. Keys are the exact `answer_ids`; **values must be strings**. |
| `POST {"op":"retry",…}` | Fresh ranked variant after an expired attempt. The material is regenerated. |
| `POST {"op":"practice",…}` | Untimed, unranked replay of a timed mode. Each call **resets** the attempt, so call it once per try. |

Always send `op:"start"` explicitly. A bare `{"challenge":…}` returns the question contract
without starting an attempt, and the artifact fetch then fails with `start_required`.

## The three modes

| Mode | ID | What it is |
|---|---|---|
| **Single Solve** | `<id>` | Untimed, with a static artifact. You can take your time and confirm answers in small batches. |
| **Time Trial** | `<id>/time_trial` | A freshly randomized variant on a server-enforced countdown, often only a few seconds. Identifiers, filenames and formats change between attempts. |
| **Mastery** | `<id>/mastery` | Several sets (`set1.<answer_id>`, `set2.…`) bundled under one timer. Usually a nested ZIP or several deliveries. |

The modes are gated: Time Trial requires Single Solve, and Mastery requires the latest Time
Trial. Web Exploitation targets are live per-attempt sites, and the lane's Time Trial and
Mastery modes can be played untimed (`run_for_time: false`).

## Partial grading ("banking")

The single most useful mechanic of the event:

- A **subset** submit whose answers are all correct returns `accepted` with `remaining: N`, and
  those answers are **banked** on the attempt.
- A batch that contains any wrong answer returns `incorrect` and banks **nothing**.
- A full, correct submit returns `CORRECT` together with the flag.

This holds in Single Solve **and** in the timed modes. It enables two techniques used throughout
the writeups:

1. **Isolating uncertain answers.** Submit confident answers in small batches, then test the
   uncertain ones alone.
2. **Enum brute-forcing under a timer.** When a field comes from a small label vocabulary that is
   hard to classify perfectly (for example the Batch `expansion` style), bank every confident
   field first, then try each candidate label for the hard field. The right one banks.

## Timed-mode discipline

- Run **start → fetch → compute → submit in a single process**. Mastery timers can expire
  mid-download, and an expired attempt silently regenerates, so the questions held no longer
  match the bytes fetched.
- Keep the requests per attempt to a minimum. Probing many `delivery` indices can cost the
  attempt.
- Never trust filenames or extensions. Map questions to files by basename, then by set order,
  then by content signature. Compute hashes and offsets on the real, decompressed bytes.
- Script and binary artifacts are WinZip-AES archives with password `infected`. Python's
  `zipfile` cannot open them; we used `pyzipper`.
- Three agents running in parallel on the same token hit `rate_limited` on their first calls, so
  all our GM wrappers use exponential backoff (about 1.5 s × 1.6, capped near 10 s).

## Compounding contracts

Script Analysis and Binary (and, to a lesser degree, Metadata) are **compounding**. Each day's
question set is the previous day's whole contract plus the new day's families. We stored each
day's question list and diffed it against the previous day (`qdiff` for Single Solve, `wdiff` for
the timed contracts). Usually only the new families needed new code, which is why the later days
were often solved in minutes.
