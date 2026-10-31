# 📱 Encrypted Strings

| | |
|---|---|
| **Day** | 18 |
| **Lane** | 📱 Mobile Android |
| **Challenge ID** | `mobile-android-day-18-encrypted-strings` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day18_quick/mob17.py`](../solvers/day18_quick/mob17.py) (Day-17 solver, unchanged) |

## Prompt
> Recover only the strings that reach security-sensitive Android and backend APIs.

## TL;DR
The Single Solve puzzle was `{"codec":"xor","data":"<base64>","key":20}`, the [Day 11](../day11/mobile-local-secrets.md)
XOR codec with a different key. The dex has an `EncryptedStrings` class with `CONTROL="string_decryption"` and the
usual decoys. `mob17.py` decoded every mode without changes.

## Artifact
- `classes.dex`: the `ChallengeActivity` WebView stub plus `EncryptedStrings` constants (`CONTROL="string_decryption"`),
  the `127.0.0.1:19090` backend and the `client_secret=SECRET-…` red herring.
- Mastery: 5 sets, delivered as `encrypted_strings_mastery_01.apk` … `_05.apk` (one APK per set; the solver used
  the default artifact plus `delivery=1..4`). Codecs: `base64`, `caesar`, `hex`, `base64`, `xor`.

## Solution
**Theme.** String encryption (DexGuard style, or a hand-rolled `decrypt(byte[], key)` helper) hides URLs, keys and
SQL until runtime. The analyst's job is to decrypt only the strings that reach sensitive sinks
(`WebView.loadUrl`, `Cipher.init`, HTTP clients), not every blob in the dex. Here, the one string that "reaches
the backend" is the puzzle value.

**Extraction:** `xor_dec(data, 20)`. Base64-decode, XOR every byte with `0x14`, then check the result against
`ANS-[0-9A-F]{16}`.

## Time Trial & Mastery
- Metadata and mobile Time Trial/Mastery were regular untimed attempts (`deadline: None`,
  `run_for_time_supported: true`, not requested).
- All three modes were `CORRECT` on the first submit.

## Lessons / gotchas
- Mastery sets keep drawing codecs from earlier days. The decoder has to keep every branch.
