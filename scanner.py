"""APK Scanner — static analysis for Android APK files.

Defensive / educational tool only. It analyses an APK *before* the
user installs it and explains every finding with evidence. It only
reads the supplied bytes; it never executes, installs or runs anything
from the APK, never extracts files to disk, and makes no network
requests at all. The binary AndroidManifest.xml is parsed with the
stdlib-only parser in axml.py; dex files are only scanned for
printable strings, never decompiled or executed.

A "Safe" verdict is NOT a guarantee: this is static analysis only.
It cannot see runtime behaviour, and string-based dex checks can miss
obfuscated code. Always review the findings, and only install APKs
from sources you trust.
"""

import hashlib
import io
import math
import re
import struct
import zipfile

from axml import AxmlError, parse_manifest

MAX_APK_SIZE = 50 * 1024 * 1024          # 50 MB
MAX_STRINGS_BYTES = 2 * 1024 * 1024      # strings scanned per dex file
ZIP_BOMB_RATIO = 100

SEVERITY_POINTS = {"critical": 25, "high": 15, "medium": 8, "low": 3,
                   "info": 0}

# Per-rule scoring caps: no single rule ID may contribute more than
# this many points to the total score. Large legitimate apps can
# otherwise pile up dozens of low/medium findings from one rule (many
# exported components, many permissions, many dex strings) and look
# "Malicious" on volume alone. A cap keeps each rule's voice in
# proportion: one unprotected export or one SMS permission is the
# signal; the tenth one adds little new information.
DEFAULT_RULE_SCORE_CAP = 25
RULE_SCORE_CAPS = {
    "PERM-01": 24,   # dangerous permissions together count at most 24
    "DEX-01": 24,    # dex string categories together count at most 24
}

# Short permission name -> severity. The full name in a manifest is
# "android.permission.<SHORT>".
# Only the four permissions that let an app act on the user's behalf
# in a way that is hard to undo are high. Every other dangerous
# permission is low: on its own it is normal for legitimate apps
# (a camera app uses CAMERA, a file manager reads storage), and it
# only matters in combination with other findings.
DANGEROUS_PERMISSIONS = {
    "SEND_SMS": "high",
    "READ_SMS": "high",
    "BIND_DEVICE_ADMIN": "high",
    "BIND_ACCESSIBILITY_SERVICE": "high",
    "RECEIVE_SMS": "low",
    "READ_CONTACTS": "low",
    "WRITE_CONTACTS": "low",
    "READ_CALL_LOG": "low",
    "WRITE_CALL_LOG": "low",
    "RECORD_AUDIO": "low",
    "CAMERA": "low",
    "ACCESS_FINE_LOCATION": "low",
    "ACCESS_COARSE_LOCATION": "low",
    "READ_EXTERNAL_STORAGE": "low",
    "WRITE_EXTERNAL_STORAGE": "low",
    "REQUEST_INSTALL_PACKAGES": "low",
    "SYSTEM_ALERT_WINDOW": "low",
    "READ_PHONE_STATE": "low",
    "GET_ACCOUNTS": "low",
    "READ_CALENDAR": "low",
    "WRITE_CALENDAR": "low",
    "BODY_SENSORS": "low",
    "USE_FINGERPRINT": "low",
    "USE_BIOMETRIC": "low",
}

PERMISSION_DESCRIPTIONS = {
    "SEND_SMS": "can send text messages (and spend your credit) without you seeing them",
    "READ_SMS": "can read your text messages, including OTP codes",
    "RECEIVE_SMS": "can intercept incoming text messages, including OTP codes",
    "BIND_DEVICE_ADMIN": "can become a device administrator and lock or wipe the phone",
    "BIND_ACCESSIBILITY_SERVICE": "can read the screen and tap for you — a common banking-trojan trick",
    "READ_CONTACTS": "can read your address book",
    "WRITE_CONTACTS": "can change your address book",
    "READ_CALL_LOG": "can read who you called and when",
    "WRITE_CALL_LOG": "can change your call history",
    "RECORD_AUDIO": "can record audio from the microphone",
    "CAMERA": "can take photos and video",
    "ACCESS_FINE_LOCATION": "can track your precise location",
    "ACCESS_COARSE_LOCATION": "can track your approximate location",
    "READ_EXTERNAL_STORAGE": "can read files on your storage",
    "WRITE_EXTERNAL_STORAGE": "can change files on your storage",
    "REQUEST_INSTALL_PACKAGES": "can install other apps on your phone",
    "SYSTEM_ALERT_WINDOW": "can draw windows over other apps (overlay attacks)",
    "READ_PHONE_STATE": "can read your phone number, IMEI and call state",
    "GET_ACCOUNTS": "can list the accounts on your phone",
    "READ_CALENDAR": "can read your calendar",
    "WRITE_CALENDAR": "can change your calendar",
    "BODY_SENSORS": "can read body sensors such as heart rate",
    "USE_FINGERPRINT": "can use fingerprint authentication",
    "USE_BIOMETRIC": "can use biometric authentication",
}

# Dex string categories: category -> (patterns, severity, explanation).
# Patterns are matched case-insensitively against the dex strings,
# except the base64 pattern which is a regex.
DEX_CATEGORIES = {
    "sms": (["SmsManager", "sendTextMessage", "sendMultipartTextMessage"],
            "high", "sends text messages from code"),
    "contacts": (["ContactsContract", "CallLog"],
                 "high", "reads contacts or call history from code"),
    "device_admin": (["DevicePolicyManager", "DeviceAdminReceiver"],
                     "high", "uses device-admin APIs"),
    "overlay_accessibility": (["AccessibilityService", "TYPE_APPLICATION_OVERLAY",
                               "SYSTEM_ALERT_WINDOW"],
                              "medium", "uses accessibility or overlay APIs"),
    "dynamic_loading": (["DexClassLoader", "PathClassLoader", "loadDex",
                         "defineClass"],
                        "high", "loads extra code at runtime — the scanned code may not be all of it"),
    # Reflection and long base64 blobs are low: normal libraries
    # use reflection (serialisation, dependency injection) and ship
    # long encoded blobs (certificates, embedded assets), so on their
    # own they are weak signals. They matter in combination, and the
    # DEX-01 per-rule cap keeps them from dominating the score.
    "reflection": (["Class.forName", "getDeclaredMethod", "Method.invoke"],
                   "low", "uses reflection to call code by name, hiding what it does"),
    "root": (["/system/bin/su", "/system/xbin/su", "Superuser", "which su",
              "test-keys"],
             "high", "checks for root access"),
    "exfiltration": (["discord.com/api/webhooks", "api.telegram.org",
                      "webhook", "pastebin", "ngrok"],
                     "high", "sends data to an external webhook or paste site"),
}

BASE64_RE = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _hashes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def _extract_strings(data):
    """Printable ASCII strings (>= 4 chars) from bytes, capped."""
    chunk = data[:MAX_STRINGS_BYTES]
    return [m.group(0).decode("ascii") for m in PRINTABLE_RE.finditer(chunk)]


def _short_permission(full_name):
    prefix = "android.permission."
    if full_name.startswith(prefix):
        return full_name[len(prefix):]
    return full_name


class ApkScanResult:
    def __init__(self, filename, data):
        self.findings = []
        self.filename = filename
        self.data = data
        self.hashes = _hashes(data)
        self.app = {
            "package": None, "version_name": None, "version_code": None,
            "min_sdk": None, "target_sdk": None, "permissions": [],
            "exported_components": [], "debuggable": None,
            "allow_backup": None, "uses_cleartext_traffic": None,
            "signed": None, "debug_signed": False,
        }
        self.file_info = {
            "name": filename, "size": len(data),
            "md5": self.hashes["md5"], "sha1": self.hashes["sha1"],
            "sha256": self.hashes["sha256"], "dex_sha256": None,
            "entropy": None,
        }
        self.urls = []

    # -- finding helper --------------------------------------------------
    def add(self, rule, category, title, severity, evidence, explanation,
            fix):
        self.findings.append({
            "id": rule, "category": category, "title": title,
            "severity": severity,
            "evidence": (evidence or "")[:200],
            "explanation": explanation, "fix": fix,
        })

    # -- scoring ---------------------------------------------------------
    def _score_and_verdict(self):
        # Score per rule ID, then cap each rule's contribution: a
        # single rule can never dominate the verdict, however many
        # findings it produced (see RULE_SCORE_CAPS).
        per_rule = {}
        for f in self.findings:
            per_rule[f["id"]] = (per_rule.get(f["id"], 0)
                                 + SEVERITY_POINTS[f["severity"]])
        score = 0
        for rule, total in per_rule.items():
            cap = RULE_SCORE_CAPS.get(rule, DEFAULT_RULE_SCORE_CAP)
            score += min(total, cap)
        score = min(score, 100)
        has_critical = any(f["severity"] == "critical"
                           for f in self.findings)
        if score >= 50 or (has_critical and score >= 30):
            verdict = "Malicious"
        elif score >= 30 or has_critical:
            verdict = "High Risk"
        elif score >= 10:
            verdict = "Suspicious"
        else:
            verdict = "Safe"
        return verdict, score

    def to_dict(self):
        verdict, score = self._score_and_verdict()
        return {
            "verdict": verdict, "score": score,
            "findings": self.findings, "app": self.app,
            "file": self.file_info, "urls": self.urls,
            "summary": (
                "%s — score %d, %d finding(s). %s"
                % (verdict, score, len(self.findings),
                   "Review every finding before installing this APK."
                   if self.findings else
                   "No suspicious signals found by these checks.")),
        }


def scan_bytes(data: bytes, filename: str):
    """Analyse APK bytes. Never writes to disk, never uses the network."""
    if len(data) > MAX_APK_SIZE:
        raise ValueError("APK is larger than 50 MB (%d bytes)" % len(data))
    result = ApkScanResult(filename, data)

    if not data.startswith(b"PK"):
        result.add("FILE-01", "format", "Not a valid APK file", "high",
                   filename,
                   "The file does not start with the ZIP magic bytes, so it "
                   "is not an APK (APKs are ZIP archives).",
                   "Do not install it. Get the app from the Play Store or "
                   "the developer's official site.")
        return result.to_dict()

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        result.add("FILE-01", "format", "Not a valid APK file", "high",
                   filename,
                   "The file claims to be a ZIP/APK but its central "
                   "directory is broken.",
                   "Do not install it. Get the app from the Play Store or "
                   "the developer's official site.")
        return result.to_dict()

    members = zf.infolist()
    names = [info.filename for info in members]

    _check_manifest(result, zf, names)
    _check_dex(result, zf, names)
    _check_signing(result, zf, names)
    _check_archive(result, members)
    return result.to_dict()


def scan_file(path):
    with open(path, "rb") as fh:
        data = fh.read()
    return scan_bytes(data, path.split("/")[-1].split("\\")[-1])


# ------------------------------------------------------------------ checks
def _check_manifest(result, zf, names):
    if "AndroidManifest.xml" not in names:
        result.add("MANI-01", "manifest",
                   "AndroidManifest.xml is missing", "high",
                   "no AndroidManifest.xml in the APK",
                   "Every Android app must have a manifest. Without one "
                   "the app cannot be identified at all.",
                   "Do not install it.")
        return
    try:
        manifest = parse_manifest(zf.read("AndroidManifest.xml"))
    except Exception as exc:  # never let a weird manifest crash the scan
        result.add("MANI-01", "manifest",
                   "AndroidManifest.xml could not be parsed", "high",
                   str(exc)[:200],
                   "The binary manifest is malformed or uses a format this "
                   "parser does not understand, so permissions and "
                   "components could not be checked.",
                   "Do not install it unless you can verify it another way.")
        return

    app = result.app
    app["package"] = manifest["package"]
    app["version_name"] = manifest["version_name"]
    app["version_code"] = manifest["version_code"]
    app["min_sdk"] = manifest["min_sdk"]
    app["target_sdk"] = manifest["target_sdk"]
    app["debuggable"] = manifest["debuggable"]
    app["allow_backup"] = manifest["allow_backup"]
    app["uses_cleartext_traffic"] = manifest["uses_cleartext_traffic"]
    app["permissions"] = manifest["permissions"]
    app["exported_components"] = [
        {"type": c["type"], "name": c["name"], "exported": c["exported"]}
        for c in manifest["components"] if c["exported"] is True]

    # PERM-01: dangerous permissions.
    for full in manifest["permissions"]:
        short = _short_permission(full)
        if short in DANGEROUS_PERMISSIONS:
            severity = DANGEROUS_PERMISSIONS[short]
            desc = PERMISSION_DESCRIPTIONS.get(short, "is a sensitive permission")
            result.add("PERM-01", "permissions",
                       "Dangerous permission: %s" % short, severity, full,
                       "This permission %s." % desc,
                       "Ask yourself whether this app really needs it. If "
                       "not, do not install it.")

    # PERM-02: permission count. A count on its own is a weak signal
    # — it double-counts the dangerous permissions already scored by
    # PERM-01, and a legitimate app store or file manager can easily
    # ask for 30 permissions. So the count is only ever a low/medium
    # note, never high.
    count = len(manifest["permissions"])
    if count > 25:
        result.add("PERM-02", "permissions",
                   "Excessive permissions (%d)" % count, "medium",
                   "%d permissions requested" % count,
                   "The app asks for far more permissions than a normal "
                   "app of its kind.",
                   "Check each permission against what the app claims to do.")
    elif count > 15:
        result.add("PERM-02", "permissions",
                   "Many permissions (%d)" % count, "low",
                   "%d permissions requested" % count,
                   "The app asks for a lot of permissions.",
                   "Check each permission against what the app claims to do.")

    # EXP-01: exported components.
    # An exported component WITH an intent-filter is public by design:
    # Android 12+ requires android:exported to be set explicitly, and
    # launcher activities, share targets and media-button receivers
    # are meant to be reached from outside the app. The same goes for
    # a component protected by a permission: only callers holding
    # that permission can reach it. Both are listed as info so the
    # user can see the app's public surface, but they score nothing
    # — scoring them punished every large legitimate app (NewPipe
    # and the F-Droid client have 9–10 such components each) for
    # doing exactly what Android expects. The real risk is an
    # exported component with NO intent-filter and NO protecting
    # permission — any app on the phone can talk to it, and nothing
    # about it is meant to be public. That stays high.
    for comp in manifest["components"]:
        if comp["exported"] is not True:
            continue
        label = "%s %s" % (comp["type"], comp["name"])
        if comp["has_intent_filter"]:
            result.add("EXP-01", "components",
                       "Exported component (public by design): %s" % label,
                       "info", label,
                       "This component is exported and has an intent "
                       "filter, so it is meant to be reached from outside "
                       "the app (a launcher activity, a share target, a "
                       "media-button receiver). That is normal.",
                       "Check that the actions it handles are the ones the "
                       "app claims to offer.")
        elif comp["permission"]:
            result.add("EXP-01", "components",
                       "Exported component (protected): %s" % label,
                       "info", label,
                       "This component is exported, but only apps holding "
                       "the %s permission can talk to it."
                       % comp["permission"],
                       "Make sure the protecting permission is one you trust.")
        else:
            result.add("EXP-01", "components",
                       "Exported component with no protection: %s" % label,
                       "high", label,
                       "This component is exported, has no intent filter "
                       "and no permission check, so any other app on the "
                       "phone can talk to it.",
                       "Do not install apps that expose unprotected "
                       "components.")
        if comp["type"] == "receiver" and any(
                a in ("android.intent.action.BOOT_COMPLETED",
                      "android.intent.action.SMS_RECEIVED")
                for a in comp["actions"]):
            result.add("EXP-01", "components",
                       "Exported receiver starts on boot / on SMS: %s" % label,
                       "medium", label,
                       "This receiver wakes the app on boot or when an SMS "
                       "arrives, even if you never open the app.",
                       "Waking on boot is normal for some apps (media "
                       "players, alarms), but combined with SMS permissions "
                       "it is a classic pattern for SMS stealers.")

    # DBG-01: debug / backup / cleartext / SDK levels.
    if manifest["debuggable"] is True:
        result.add("DBG-01", "build",
                   "App is debuggable", "high", "android:debuggable=true",
                   "A debuggable app can be inspected and modified while "
                   "it runs. Release apps are never debuggable.",
                   "Do not install a debuggable app from outside the Play Store.")
    if manifest["allow_backup"] is True:
        result.add("DBG-01", "build",
                   "App allows backups", "low", "android:allowBackup=true",
                   "The app's data can be copied off the phone with adb backup.",
                   "Harmless for most apps, but sensitive data could leak.")
    if manifest["uses_cleartext_traffic"] is True:
        result.add("DBG-01", "build",
                   "App allows cleartext (HTTP) traffic", "low",
                   "android:usesCleartextTraffic=true",
                   "The app is allowed to send data over plain HTTP, "
                   "where it can be read or changed on the network. But "
                   "this flag is a capability, not observed behaviour — "
                   "many apps ship it for legacy compatibility while all "
                   "real traffic is HTTPS — so on its own it is a weak "
                   "signal.",
                   "Prefer apps that only use HTTPS.")
    target = manifest["target_sdk"]
    if isinstance(target, int) and target < 26:
        result.add("DBG-01", "build",
                   "Old target SDK (%d)" % target, "medium",
                   "android:targetSdkVersion=%d" % target,
                   "Apps targeting old Android versions skip years of "
                   "security rules.",
                   "Prefer apps targeting a recent Android version.")
    minimum = manifest["min_sdk"]
    if isinstance(minimum, int) and minimum < 21:
        result.add("DBG-01", "build",
                   "Very old minimum SDK (%d)" % minimum, "low",
                   "android:minSdkVersion=%d" % minimum,
                   "The app supports very old Android versions, which "
                   "suggests it has not been maintained.",
                   "Prefer apps that are actively maintained.")


def _check_archive(result, members):
    """ZIP-01: traversal, nested APKs, native libraries, zip bombs."""
    so_count = 0
    for info in members:
        name = info.filename
        if name.startswith(("/", "\\")) or ".." in name.split("/"):
            result.add("ZIP-01", "archive",
                       "Path traversal in APK member", "high", name,
                       "A member name escapes the APK directory, which is "
                       "a trick used to overwrite files when extracted.",
                       "Do not install or extract this APK.")
        if name.lower().endswith(".apk"):
            result.add("ZIP-01", "archive",
                       "Nested APK inside the APK", "medium", name,
                       "The APK contains another APK file, a common way to "
                       "hide a second payload.",
                       "Inspect the nested APK separately before trusting "
                       "this one.")
        if name.startswith("lib/") and name.endswith(".so"):
            so_count += 1
        if info.file_size > 0 and info.compress_size > 0:
            ratio = info.file_size / info.compress_size
            if ratio > ZIP_BOMB_RATIO:
                result.add("ZIP-01", "archive",
                           "Possible zip bomb (%.0fx compression)" % ratio,
                           "high", name,
                           "This member expands to more than 100 times its "
                           "stored size, which can exhaust disk or memory.",
                           "Do not extract this APK.")
    if so_count:
        result.add("ZIP-01", "archive",
                   "Native libraries included (%d .so file(s))" % so_count,
                   "info", "%d native libraries in lib/" % so_count,
                   "Native code runs outside the usual Android sandbox "
                   "checks, so it deserves a closer look.",
                   "Native libraries are normal in many apps; this is "
                   "only a note, not a warning.")


def _check_dex(result, zf, names):
    dex_names = [n for n in names if n.endswith(".dex")]
    if not dex_names:
        return
    all_strings = []
    for name in dex_names:
        dex = zf.read(name)
        if name == "classes.dex":
            result.file_info["dex_sha256"] = hashlib.sha256(dex).hexdigest()
            result.file_info["entropy"] = _entropy(dex)
            if result.file_info["entropy"] > 7.5:
                result.add("ENT-01", "dex",
                           "classes.dex has very high entropy (%.2f)"
                           % result.file_info["entropy"],
                           "medium",
                           "entropy %.2f" % result.file_info["entropy"],
                           "High entropy means the dex file looks packed or "
                           "encrypted, which hides what the code does.",
                           "Treat a packed dex as suspicious unless you know "
                           "why it is packed.")
        all_strings.extend(_extract_strings(dex))

    lowered = [s.lower() for s in all_strings]
    for category, (patterns, severity, explanation) in DEX_CATEGORIES.items():
        hit = None
        for pattern in patterns:
            needle = pattern.lower()
            for original in all_strings:
                if needle in original.lower():
                    hit = original
                    break
            if hit:
                break
        if hit:
            result.add("DEX-01", "dex",
                       "Suspicious code pattern: %s" % category, severity,
                       hit,
                       "The app's code %s." % explanation,
                       "Do not install the app unless you understand why "
                       "it needs this.")
    # Obfuscation: a very long base64-looking blob.
    for s in all_strings:
        if BASE64_RE.search(s):
            result.add("DEX-01", "dex",
                       "Suspicious code pattern: obfuscation", "low", s,
                       "The code contains a very long base64 blob, which is "
                       "often used to hide strings or payloads — but "
                       "legitimate apps ship long encoded blobs too "
                       "(certificates, embedded assets), so on its own "
                       "this is a weak signal.",
                       "A long encoded blob on its own is not proof of "
                       "malware, but combined with other findings it matters.")
            break
    # URL-01: every distinct URL in the dex strings.
    seen = []
    for s in all_strings:
        for url in URL_RE.findall(s):
            if url not in seen:
                seen.append(url)
    result.urls = seen[:50]
    for url in seen[:20]:
        result.add("URL-01", "dex", "URL found in code", "info", url,
                   "The app's code mentions this URL.",
                   "Check that the domain belongs to the app's developer.")


def _check_signing(result, zf, names):
    meta = [n for n in names if n.startswith("META-INF/")]
    sig_files = [n for n in meta
                 if n.endswith((".RSA", ".DSA", ".EC"))]
    if not sig_files:
        result.app["signed"] = False
        result.add("CERT-01", "signing",
                   "APK has no signature file", "high",
                   "no META-INF/*.RSA, *.DSA or *.EC file",
                   "The APK is unsigned, or its signature was stripped. "
                   "Android refuses to install unsigned APKs, and a "
                   "stripped signature means the file was tampered with.",
                   "Do not install an unsigned APK.")
    else:
        result.app["signed"] = True
        for name in sig_files:
            try:
                blob = zf.read(name)
            except KeyError:
                continue
            text = blob.decode("utf-8", errors="ignore")
            if "Android Debug" in text:
                result.app["debug_signed"] = True
                result.add("CERT-01", "signing",
                           "APK is signed with a debug certificate", "high",
                           name,
                           "The app was signed with the Android debug key, "
                           "which anyone can generate. It is not a release "
                           "build from the real developer.",
                           "Only install apps signed with a release key.")
                break
    if "META-INF/MANIFEST.MF" not in names:
        result.add("CERT-01", "signing",
                   "MANIFEST.MF is missing", "medium",
                   "no META-INF/MANIFEST.MF",
                   "A signed APK normally ships a MANIFEST.MF listing the "
                   "signed files.",
                   "Treat a missing MANIFEST.MF as a sign the APK was "
                   "repacked.")
