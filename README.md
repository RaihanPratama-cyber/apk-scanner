# APK Scanner

Check an Android APK **before** you install it.

A lot of Android malware arrives as an APK outside the Play Store — a
"free" game, a "cracked" app, a banking app sent over WhatsApp. Once
installed it can read your SMS (including OTP codes), steal your
contacts, or install more apps. This tool reads the APK as bytes,
checks it against a set of explainable rules, and tells you exactly
what it found — with the evidence and what to do about it — before the
APK is ever installed.

It is the Android-specific companion to
[malware-file-scanner](https://github.com/RaihanPratama-cyber/malware-file-scanner)
(generic files). That scanner treats an APK as a plain ZIP; this one
understands Android: it parses the binary `AndroidManifest.xml`,
checks permissions and exported components, reads the strings in
`classes.dex`, and verifies the signature.

Built as a portfolio project by **Raihan Pratama** (Politeknik Caltex
Riau, Teknologi Rekayasa Komputer, 3 TRK A).

> ⚠️ **A "Safe" verdict is not a guarantee.** This is static analysis
> only — no decompilation of dex bytecode, no runtime behaviour, and
> string-based dex checks can miss obfuscated code. Only install APKs
> from sources you trust.

## What it checks

| Rule | Category | What it looks for |
| --- | --- | --- |
| PERM-01 | Permissions | Dangerous permissions — only SEND_SMS, READ_SMS, BIND_DEVICE_ADMIN and BIND_ACCESSIBILITY_SERVICE are high; every other dangerous permission is low (see "Why legitimate apps don't score Malicious" below) |
| PERM-02 | Permissions | More than 15 permissions (low), more than 25 (medium) — a count alone is a weak signal |
| EXP-01 | Components | Exported activity/service/receiver/provider; only an export with no intent-filter and no protecting permission is high — exports that are public by design are info, and a receiver that wakes on boot/SMS is medium |
| DBG-01 | Build | `debuggable=true` (high), `allowBackup=true` (low), `usesCleartextTraffic=true` (low), old target/min SDK |
| DEX-01 | Dex strings | SMS sending, contacts access, device admin, dynamic code loading, root checks, exfiltration URLs (high); overlay/accessibility (medium); reflection and long base64 blobs (low) |
| URL-01 | Dex strings | Every distinct URL found in the code (info) |
| CERT-01 | Signing | No signature file (high), signed with a debug certificate (high), MANIFEST.MF missing (medium) |
| ZIP-01 | Archive | Path traversal, nested APK, native libraries (info), zip-bomb compression ratio |
| HASH-01 | Identity | MD5/SHA-1/SHA-256 of the APK and of `classes.dex` |
| ENT-01 | Dex | `classes.dex` entropy above 7.5 — packed or obfuscated dex |
| MANI-01 | Manifest | Manifest missing or unparseable (high) — the other checks still run |
| FILE-01 | Format | Not a ZIP/APK at all (high) |

## Scoring

| Verdict | Score |
| --- | --- |
| Safe | 0–9 |
| Suspicious | 10–29 |
| High Risk | 30–49 |
| Malicious | 50–100 |

Critical findings are worth 25 points, high 15, medium 8, low 3, info 0.
The score is capped at 100, and any single critical finding pushes the
verdict to at least High Risk.

**Per-rule caps.** The score is added up per rule ID, and no single
rule may contribute more than 25 points (PERM-01 and DEX-01 are
capped at 24). A large app can otherwise pile up dozens of findings
from one rule — ten exported components, ten permissions, ten dex
strings — and look "Malicious" on volume alone. A cap keeps each
rule's voice in proportion: one unprotected export or one SMS
permission is the signal; the tenth one adds little new information.

## Why legitimate apps don't score Malicious

The first version of this scanner called two real, legitimate apps
"Malicious" — NewPipe 0.29.3 and the F-Droid client 2.0.3 both scored
100. They are not malware; the rules were adding up too fast on
large legitimate apps. Three things were wrong, and all three were
fixed by changing the rules, not by whitelisting the apps (there is
no package-name exception anywhere in the scanner):

1. **Exported components.** An exported activity with an
   intent-filter is public *by design* — Android 12+ requires
   `android:exported` to be set explicitly, and launcher activities,
   share targets and media-button receivers are meant to be reached
   from outside the app. The old rule scored every unprotected
   export high. Now an export with an intent-filter, or one
   protected by a permission, is listed as info (0 points); only an
   export with no intent-filter *and* no protecting permission is
   high. A receiver that wakes on boot or SMS is medium, not high.
2. **Permissions.** Only SEND_SMS, READ_SMS, BIND_DEVICE_ADMIN and
   BIND_ACCESSIBILITY_SERVICE are high. The rest — camera, contacts,
   location, storage — are low: a camera app uses the camera, a file
   manager reads storage. They only matter in combination, and
   PERM-01 is capped at 24 points in total. The permission *count*
   (PERM-02) is only ever low/medium, because it double-counts
   PERM-01.
3. **Dex strings.** Reflection and long base64 blobs are low, not
   medium/high: normal libraries use reflection and ship long
   encoded blobs (certificates, embedded assets). SMS, contacts,
   device-admin, dynamic code loading, root checks and exfiltration
   URLs stay high, and DEX-01 is capped at 24 points in total.

**Validation (17 Nov 2026, re-downloaded from F-Droid and scanned
again after the fix):**

| App | Before the fix | After the fix |
| --- | --- | --- |
| NewPipe 0.29.3 (`org.schabi.newpipe`) | Malicious, 100 (35 findings) | Suspicious, 15 (35 findings) |
| F-Droid client 2.0.3 (`org.fdroid.fdroid`) | Malicious, 100 (39 findings) | Suspicious, 29 (39 findings) |

F-Droid sits exactly at the top of Suspicious (29): it asks for 30
permissions, allows cleartext traffic, and ships four low-severity
permissions — all real attack surface, none of it proof of malware.
The malicious example still scores Malicious (100, 24 findings)
and the benign example still scores Safe (0), so the fix did not
weaken the scanner — it only stopped volume from masquerading as
danger. Judge an APK by its findings (does it ask for SMS
permissions? is it debuggable? is it unsigned?), not by the
verdict alone.

## How to run

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000, upload an APK (max 50 MB), or load one of
the built-in examples. The two examples are generated on the fly by
`data/examples/make_examples.py` — no `.apk` binaries are stored in
this repo.

## API

- `GET /health` — `{"status": "ok"}`
- `GET /api/examples` — the two built-in examples
- `GET /api/example/<benign|malicious>` — scan the example APK
- `POST /api/scan` — multipart upload, field `file`, returns the full
  JSON result (`verdict`, `score`, `findings`, `app`, `file`, `urls`)

## How the manifest parser works

Android stores the manifest as a binary file (AXML): a string pool,
then chunks for namespaces, start/end elements and attributes. The
parser in `axml.py` is written from scratch with the Python standard
library only — no `androguard`, no Java tools. It supports both UTF-8
and UTF-16 string pools, typed attribute values (string, int, boolean,
float, reference), and extracts the package name, SDK versions, flags,
permissions and every component with its `exported` flag and
intent-filter actions. `docs/HOW_IT_WORKS.md` has the details.

## Tests (after the 17 Nov 2026 tuning)

```bash
pytest -q
```

82 tests cover the AXML writer→parser round-trip (UTF-8 and UTF-16),
every rule firing on the malicious example and not on the benign one,
hash/entropy computation, zip risks, malformed inputs, scoring, and
the Flask API. The scanner is verified to make no network requests
and to never write files to disk while scanning.

The 82 are the original 74, updated for the new severities (common
permissions low, exported-with-intent-filter info, boot receiver
medium, reflection/obfuscation low, cleartext low, permission-count
thresholds) plus 8 new regression tests locking in the tuning —
PERM-01 cap 24, DEX-01 cap 24, default per-rule cap 25, caps
preventing a Malicious verdict on volume alone, and a capped rule
plus a real signal still reaching Malicious.

## Honest limits

- Static analysis only. It never decompiles dex bytecode and never
  runs the app, so it cannot see behaviour that only happens at runtime.
- Dex checks read printable strings. Heavily obfuscated or encrypted
  code can hide its strings — high dex entropy is flagged for exactly
  this reason, but it is a hint, not proof.
- The manifest parser is best-effort. Unusual or malformed manifests
  produce a MANI-01 finding instead of a crash, and the other checks
  still run.
- There is no cloud reputation lookup (no VirusTotal): a brand-new
  malicious APK with no suspicious strings can pass as Safe.
- **Real-app check (17 Nov 2026):** the parser was validated against
  two real APKs from F-Droid — NewPipe 0.29.3 and the F-Droid client
  2.0.3 — and reads their real package names, versions, SDK levels,
  permissions and signing status correctly. The first version of the
  scanner scored both **Malicious (100)**, which was wrong: large
  legitimate apps have many exported components and broad
  permissions, and the findings added up. The rules were fixed
  (per-rule score caps; exported-with-intent-filter and protected
  components are info; common permissions are low; reflection and
  base64 blobs are low) and both apps were re-downloaded and scanned
  again: NewPipe **Suspicious (15)**, F-Droid **Suspicious (29)**.
  There is no package-name exception in the scanner — the fix is
  rule-based. F-Droid sits exactly at the top of Suspicious: 30
  permissions, cleartext traffic allowed, four low-severity
  permissions. The verdict therefore means "attack surface /
  suspicious signals — read the findings", not "this app is
  malware". Judge an APK by its findings (for example: does it ask
  for SMS permissions? is it debuggable? is it unsigned?), not by
  the verdict alone.
- A Safe verdict means "nothing suspicious found by these checks",
  not "this APK is safe".
