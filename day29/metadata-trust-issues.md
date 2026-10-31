# 🔎 Trust Issues

| | |
|---|---|
| **Day** | 29 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-29-trust-issues` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day29_quick/m29.py`](../solvers/day29_quick/m29.py) + certificate parser [`x509.py`](../solvers/day29_quick/x509.py) |

## Prompt
> Certificates appear in binaries, packages, mail, captures, and disk images. Fingerprint each one, collapse duplicates, and identify the trust claim unsupported by evidence.

## TL;DR
The new field is `x509.sha256_fingerprint` for `certificate-001.pem`: the SHA-256 of the certificate's **DER** bytes,
i.e. of the base64 body of the PEM block, not of the `.pem` text file. The answer is lowercase hex without colons
(the grader is case-insensitive). The value was checked against `openssl x509 -fingerprint -sha256`.

## Artifact
- Variant 000: a self-signed Ed25519 leaf, `CN=arena-<hex>.example.test, O=Huntress CTF, C=US`, valid
  2026-10-01 → 2027-10-01, SAN equal to the CN. All 13 mastery certificates were single-block PEM.
- Answer id `d29-x509-001-x509-sha256-fingerprint`.
- Time Trial: **34 questions**. Mastery: **13 sets × 34 = 442**. The synthesis question lists `certificate-001.pem`
  among six files. Note that the synthesis question hashes the *whole file* (PEM text), while this field hashes the
  DER. They are different digests of the same evidence.

## Solution
```python
PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)
der = base64.b64decode(re.sub(rb"\s+", b"", PEM_RE.search(b).group(1)))
answer = hashlib.sha256(der).hexdigest()           # == openssl x509 -noout -fingerprint -sha256, minus colons
```

`x509.py` decodes every PEM block (also `TRUSTED` / `X509` variants, or raw DER) and also exposes the SHA-1
fingerprint, serial, subject and issuer, validity dates, a self-signed flag, signature algorithm, DNS SANs, CA flag,
subject key identifier and certificate count. Those were prepared for the "collapse duplicates / unsupported trust
claim" story, which stayed decorative: no other x509 question appeared.

## Time Trial & Mastery
Regular untimed attempts. One set's `roster-filename` question was again handled by the
[Day 24](../day24/metadata-event-horizon.md) stem-matching override. Single CORRECT, Time Trial CORRECT 34/34 one-shot,
Mastery CORRECT 442/442.

## Lessons / gotchas
- A certificate fingerprint is always computed over DER. Hashing the PEM file gives a stable but wrong value. In this
  contract the PEM-file hash is also exactly what the synthesis question uses for the same file, so the two are easy
  to mix up.
- One honest field per new file type, again, despite the story.
