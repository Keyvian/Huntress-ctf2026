# Read the Rules

| | |
|---|---|
| **Day** | 01 (orientation) |
| **Lane** | Welcome |
| **Challenge ID** | `read-the-rules` |
| **Modes** | Single Solve ✅ |
| **Solver** | none (browser DOM read + one submit) |

## Prompt
> Please follow the rules for the Huntress CTF!
>
> Read the rules at https://ctf.huntress.com/rules
>
> If you look closely, you can find a flag!
>
> The flag is hidden in the page itself — invisible on screen, but present in the page HTML. Inspect the page (your browser developer tools will do) and submit the exact flag value you find.
>
> Submit it to the Game Master here, or in the Read the Rules CourseStack lesson, to prove you have read the rules.

## TL;DR
The flag is an HTML comment near the end of the **rendered** rules page: `<div><!-- flag{<32 hex>} --></div>`. The page
is a client-rendered Next.js (CourseStack) app, so a plain HTTP GET only returns the shell and never shows the comment.
You need the live DOM. The visible rules text even says there is no flag on the page. Ignore that.

## Artifact
No artifact. The target is the public rules page.

## Solution
1. `requests.get("https://ctf.huntress.com/rules")` returns a ~7 KB Next.js shell. `__NEXT_DATA__` holds only tenant
   metadata (branding, help links), not the rules content, and no flag.
2. Open the page in a real browser. We used the player's already signed-in Chrome. The rules render client-side, and
   the injected HTML comment is in the DOM. With DevTools, search Elements for `flag{`. Alternatively, the 2026-10-20 session used Claude-in-Chrome:
   ```js
   document.documentElement.outerHTML.match(/flag\{[0-9a-f]{32}\}/)[0]
   ```
3. Submit the exact value, including the `flag{…}` wrapper. The value is not reproduced here.

## Submission history
- **Day 1:** the Game Master did not manage this challenge yet. `start` returned `{"error":"artifact_unavailable"}` and
  every other op returned `start_required`. The player pasted the flag into the CourseStack "Read the Rules" lesson by
  hand.
- **2026-10-20:** a full Game Master audit still listed `read-the-rules` as unsolved there. `start` now worked (answer id
  `flag`). We re-read the flag from the rendered DOM and submitted `{"flag": "flag{…}"}`, which came back CORRECT, so
  both the portal and the Game Master record it.

## Time Trial & Mastery
Single mode only.

## Lessons / gotchas
- "Present in the page HTML" here means the rendered DOM, not the HTTP response body. For SPA pages, scraping without a
  browser comes back empty.
- The portal and the Game Master can disagree about what is solved. A periodic audit through `op=list` caught this one.
