# 🔎 Package Deal

| | |
|---|---|
| **Day** | 21 |
| **Lane** | 🔎 Metadata Forensics |
| **Challenge ID** | `metadata-forensics-day-21-package-deal` |
| **Modes** | Single Solve ✅ · Time Trial ✅ · Mastery ✅ |
| **Solver** | [`solvers/day21_quick/m21.py`](../solvers/day21_quick/m21.py) + APK identity parser [`apk.py`](../solvers/day21_quick/apk.py) |

## Prompt
> Mobile packages have been mirrored under friendly filenames. Recover Android package identities, distinguish rebuilds from clones, and expose the borrowed product name.

## TL;DR
The new field is `apk.package_name` for `mobile-001.apk`: the `package` attribute of the root `<manifest>` element in
the **binary** `AndroidManifest.xml` (AXML). Decoding AXML in pure Python gave `com.huntress.arena.p08281778`, CORRECT
in all three modes. The parser also extracts signer certificates (v1 and v2) for the rebuild-versus-clone question the
prompt suggested. That question never came.

## Artifact
- `mobile-001.apk` (8,535 bytes): binary `AndroidManifest.xml`, `classes.dex`, v1 signature files
  `META-INF/FIXTURE-.SF` / `.RSA`, and an APK Signing Block with a v2 signature.
- Answer id `d21-apk-001-apk-package-name`.
- Time Trial: **26 questions**. Mastery: **5 sets × 26 = 130**. The same APK appeared in every variant. The synthesis
  question now lists `mobile-001.apk`.

## Solution
Android compiles the manifest into AXML: a chunked binary format with a string pool (UTF-8 or UTF-16), a resource map
(attribute resource ids), and start/end element chunks whose attributes are typed values. The package name is a plain
string attribute on the first `<manifest>` start-element:

```python
# apk.axml(): chunk walk. 0x0001 = string pool, 0x0180 = resource map,
# 0x0102 = start element (name, then attributes of 20 bytes each), 0x0103 = end element
root, elems = axml(zipfile.ZipFile(io.BytesIO(apk)).read("AndroidManifest.xml"))
answer = root["attrs"]["package"]        # root element is <manifest>
```
An attribute whose name string is empty is named through the resource map (`android:versionCode` and friends), which is
why the map has to be parsed even for this simple field.

`apk.py` is a full identity record:

- AXML decoding: string pool, resource-map attribute names, typed values.
- `manifest()`: package, versionCode / versionName, uses-sdk, application label, launcher activity, components,
  permissions.
- v1 PKCS#7 certificates (via `cryptography`) and APK Signing Block v2/v3 certificates, with MD5 / SHA-1 / SHA-256
  fingerprints, subject and issuer CN, serial, validity and SPKI hash.
- `classes*.dex` hashes, the list of signature schemes, the member list.

It was cross-checked against `aapt dump badging` and apktool output: package, versionCode 1, versionName 1.0, sdk 23/23,
label `Huntress Evidence 08281778`, and identical v1 and v2 certificates.

The prepared (unused) reading of the prompt: same package with a different signer = clone; same signer with a
different versionCode or dex = rebuild; a "borrowed product name" = an application label that does not match the
package.

## Time Trial & Mastery
The scheduled 09:00 ET agent banked other lanes' singles and started the metadata single, then stopped with an empty
log. A manual re-run finished the remaining modes about 45 minutes later. All metadata modes were regular untimed
attempts: Single CORRECT, Time Trial 26/26, Mastery 130/130. `m21.py` added a `--partial` guard that refuses to submit an
incomplete answer set unless explicitly asked.

## Lessons / gotchas
- Never read an APK's manifest as text. It is AXML. The `package` string is in the string pool, and a `strings`/grep
  hit can belong to a component or a permission name instead.
- An APK is also the delivery format of the mobile lane, but the two lanes care about different parts. The mobile lane
  reads `assets/` and the dex, while metadata reads the manifest and signing blocks.
