# How the APK Scanner works

## The scan, step by step

1. **Read the bytes.** `scan_bytes()` takes the uploaded APK as bytes.
   Nothing is written to disk and no network request is made. Files
   over 50 MB are rejected.
2. **Check the format.** An APK is a ZIP archive, so the file must
   start with the `PK` magic bytes and open with `zipfile`. If not,
   the result is a single FILE-01 finding — never a crash.
3. **Parse the manifest.** `AndroidManifest.xml` inside the APK is a
   binary file, not XML text. `axml.py` parses it (see below) and the
   scanner extracts the package name, SDK versions, flags
   (`debuggable`, `allowBackup`, `usesCleartextTraffic`), the
   permission list, and every component.
4. **Read the dex strings.** `classes.dex` (and `classes2.dex`, …)
   are read in memory and their printable ASCII strings are extracted.
   The scanner matches those strings against the DEX-01 categories
   and collects every URL. It also hashes the dex and measures its
   entropy.
5. **Check the signature.** The `META-INF/` members are listed: a
   `.RSA`/`.DSA`/`.EC` file means the APK is signed, and its bytes
   are searched for the text "Android Debug" (debug certificates
   contain that string). `MANIFEST.MF` must be present.
6. **Check the archive.** Member names are checked for path
   traversal and nested APKs, native `.so` files are counted, and the
   compression ratio of every member is computed from zip metadata —
   no extraction needed.
7. **Score.** Findings are added up per rule ID (critical 25, high
   15, medium 8, low 3, info 0), and each rule's contribution is
   capped — no single rule may add more than 25 points (PERM-01
   and DEX-01 are capped at 24). The total is capped at 100. The
   verdict is Safe (0–9), Suspicious (10–29), High Risk (30–49) or
   Malicious (50–100).

## Why the scoring is capped per rule

A score that simply adds up every finding punishes size: a large
legitimate app has more components, more permissions and more dex
strings than a small one, so its findings add up past Malicious
even when nothing in it is actually dangerous. That is exactly
what happened before the 17 Nov 2026 tuning — NewPipe 0.29.3 and
the F-Droid client 2.0.3 both scored Malicious (100).

The fix is in the rules, not in the apps (there is no
package-name exception anywhere):

- **EXP-01:** an exported component with an intent-filter, or one
  protected by a permission, is public by design and scores 0
  (info — still listed, so the public surface stays visible).
  Only an export with no intent-filter *and* no permission is
  high. A boot/SMS receiver is medium.
- **PERM-01:** only SEND_SMS, READ_SMS, BIND_DEVICE_ADMIN and
  BIND_ACCESSIBILITY_SERVICE are high; every other dangerous
  permission is low, and the rule contributes at most 24 points.
- **PERM-02:** the permission count is only ever low (>15) or
  medium (>25) — it double-counts PERM-01.
- **DEX-01:** SMS, contacts, device-admin, dynamic loading, root
  checks and exfiltration stay high; overlay/accessibility is
  medium; reflection and long base64 blobs are low (normal
  libraries use both), and the rule contributes at most 24 points.
- **DBG-01:** cleartext traffic is low — the flag is a
  capability, not observed insecure traffic.

After the fix, re-downloaded from F-Droid and re-scanned: NewPipe
**Suspicious (15)**, F-Droid **Suspicious (29)** — F-Droid sits
exactly at the top of Suspicious (30 permissions, cleartext
allowed, four low permissions). The malicious example still
scores Malicious (100) and the benign one Safe (0), so the caps
cost a truly dangerous app nothing: its strong signals (unsigned,
debuggable, SMS permissions, dynamic loading, exfiltration) are
spread across many rules, and no single cap binds them all.

## The binary manifest parser (`axml.py`)

A binary AndroidManifest.xml starts with the magic `0x00080003`,
then a series of chunks. Each chunk begins with a type, a header
size and a chunk size.

- **String pool (0x0001).** The header gives the string count, style
  count, flags and the offset where the strings start. Bit `0x100`
  of the flags means the strings are UTF-8; otherwise they are
  UTF-16. Lengths are varints in UTF-8 mode (one byte, or two if the
  high bit is set) and uint16s in UTF-16 mode. Every other chunk
  refers to strings by index into this pool.
- **Namespace start/end (0x0100/0x0101).** Carries a prefix and a URI
  (for example `android` → `http://schemas.android.com/apk/res/android`).
  The parser reads them but does not need them for the checks.
- **Start element (0x0102).** Gives the element name (a string-pool
  index) and a list of attributes. Each attribute is 20 bytes:
  namespace index, name index, raw string value (or `0xFFFFFFFF`),
  and a typed value — size, data type, data. Data types the parser
  understands: string (`0x03`, data is a string-pool index), float
  (`0x04`), int (`0x10`), boolean (`0x12`, data is 0 or
  `0xFFFFFFFF`), reference (`0x01`).
- **End element (0x0103).** Pops the element stack.

The parser rebuilds the element tree, then `parse_manifest()` walks
it: `uses-sdk` gives the SDK versions, `uses-permission` gives the
permissions, `application` gives the flags, and `activity`,
`activity-alias`, `service`, `receiver` and `provider` elements
become components, with their `exported` flag, protecting
`permission`, and the `action` names inside their `intent-filter`
children.

## The example APKs (`data/examples/make_examples.py`)

No `.apk` binaries are stored in the repo. The script builds both
examples in memory: a minimal AXML writer (string pool, namespace
chunks, start/end elements — the mirror image of the parser) writes
the manifest, a synthetic `classes.dex` holds the example strings,
and `zipfile` packs the APK. The writer supports both UTF-8 and
UTF-16 string pools, and the test suite checks that the parser reads
back exactly what the writer wrote.

- **Benign:** `com.example.benign`, INTERNET only, nothing exported,
  not debuggable, target SDK 34, signed (META-INF files present).
- **Malicious:** `com.evil.fakebank`, SEND_SMS / READ_SMS /
  READ_CONTACTS / RECORD_AUDIO / BIND_DEVICE_ADMIN /
  REQUEST_INSTALL_PACKAGES, exported activity and receiver (the
  receiver wakes on BOOT_COMPLETED), debuggable, cleartext traffic
  allowed, target SDK 23, dex strings for SMS sending, dynamic code
  loading, root checks and a Discord webhook, plus a nested APK and a
  native library — and no signature files at all.
