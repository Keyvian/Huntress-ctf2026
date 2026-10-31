# 📱 Trust Everyone

| | |
|---|---|
| **Day** | 09 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-09-trust-everyone` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day09/mob9.py`](../solvers/day09/mob9.py) |

## Prompt
> Exploit a challenge CA accepted by a permissive trust implementation.

## TL;DR
This was the first fully autonomous day. The scheduled 09:00 ET wrapper detected the release and a headless agent
solved it from the local WSL toolchain (Homebase VM off). The APK container is unchanged, and all three modes used
`codec:"base64"`. `mob9.py` was written that morning as a *universal*
solver: it finds every APK (default artifact, extra deliveries, nested ZIPs), decodes any known codec, checks the
`ANS-` pattern and submits. Every later mobile solver grew out of it, and Day 10 used it unchanged.

## Artifact
- Start response: one question `answer`, artifact `trust_everyone.apk`, text *"For case MOB-09-… in package
  com.huntress.mobile.d09.v…: Exploit a challenge CA accepted by a permissive trust implementation. Submit only the
  exact backend answer code returned for this case."* Format `pattern`, normalization `exact`.
- `trust_everyone.apk` is 12,704 bytes, detected as "Android package (APK), with AndroidManifest.xml, with APK Signing Block":

| Member | Size |
|---|---|
| `AndroidManifest.xml` | 3,488 |
| `assets/huntress_puzzle.json` | 101 |
| `classes.dex` | 2,584 |
| `META-INF/FIXTURE-.SF` | 422 |
| `META-INF/FIXTURE-.RSA` | 1,367 |
| `META-INF/MANIFEST.MF` | 298 |

- Mastery: `set1.answer` … `set5.answer`, all `base64` on this attempt.

## Solution
**Theme.** A "trust everyone" `X509TrustManager` (empty `checkServerTrusted`), a `HostnameVerifier` that returns `true`,
or a Network Security Config `<trust-anchors>` with `<certificates src="user"/>` lets a proxy with its own CA
intercept TLS. Here the prompt adds a challenge-owned CA. The answer still lives in the puzzle asset.

**Extraction (`mob9.py`):**

```python
ANS = re.compile(r"ANS-[0-9A-F]{16}")

def puzzle_answer(apk):
    p = json.loads(zipfile.ZipFile(io.BytesIO(apk)).read("assets/huntress_puzzle.json"))
    if p.get("codec") == "split" or "parts" in p:
        ...                                  # Day-5 scatter, gather as fallback
    s = p["data"]
    for _ in range(6):                       # peel until the pattern matches
        if ANS.fullmatch(s.strip()):
            return s.strip(), p
        s = dec(p.get("codec"), s)
    return s, p
```

`apks_from(raw)` recurses into nested ZIPs until it finds a member set containing `assets/huntress_puzzle.json`, so
the same code handles "one APK", "zip of APKs" and "one APK per delivery".

## Time Trial & Mastery
- Time Trial: `base64`, solved on the first submit.
- Mastery: `mob9.py` fetches the default artifact and, if it holds fewer APKs than there are `answer_ids`, fetches
  `delivery=1..n-1`. Five `base64` APKs were decoded and accepted in one submit.

## Lessons / gotchas
- Moving from the Homebase VM to the local WSL venv (`~/ctf-venv`) cost nothing here. The mobile lane needs only
  `zipfile`, `json` and `base64`.
- Iterated decoding (`for _ in range(6)`) protects against layered encodings that never actually appeared. The
  pattern check is what matters.
