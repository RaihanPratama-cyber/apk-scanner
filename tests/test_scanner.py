"""Tests for the APK Scanner: AXML round-trip, every rule, Flask API."""

import hashlib
import io
import os
import socket
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "data", "examples"))

import make_examples  # noqa: E402
from axml import AxmlError, AxmlParser, parse_manifest  # noqa: E402
from make_examples import AxmlWriter, build_apk_bytes  # noqa: E402
from scanner import (MAX_APK_SIZE, ApkScanResult, scan_bytes,  # noqa: E402
                     scan_file)

import app as app_module  # noqa: E402


# ------------------------------------------------------------------ helpers
def scan(kind, **kwargs):
    return scan_bytes(build_apk_bytes(kind, **kwargs), "%s.apk" % kind)


def finding_ids(result, rule=None):
    ids = [f["id"] for f in result["findings"]]
    if rule:
        return [f for f in result["findings"] if f["id"] == rule]
    return ids


def minimal_manifest_tree(permissions=(), components=(), target_sdk=34,
                          min_sdk=24, debuggable=False, allow_backup=False,
                          cleartext=False):
    children = [{"name": "uses-sdk",
                 "attrs": [("android:minSdkVersion", "int", min_sdk),
                           ("android:targetSdkVersion", "int", target_sdk)],
                 "children": []}]
    for perm in permissions:
        children.append({"name": "uses-permission",
                         "attrs": [("android:name", "string", perm)],
                         "children": []})
    children.append({"name": "application",
                     "attrs": [("android:debuggable", "bool", debuggable),
                               ("android:allowBackup", "bool", allow_backup),
                               ("android:usesCleartextTraffic", "bool",
                                cleartext)],
                     "children": list(components)})
    return {"name": "manifest",
            "attrs": [("package", "string", "com.test.app"),
                      ("versionCode", "int", 1),
                      ("versionName", "string", "1.0")],
            "children": children}


def custom_apk(manifest_tree=None, dex=None, extra=None, utf16=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if manifest_tree is not None:
            zf.writestr("AndroidManifest.xml",
                        AxmlWriter(manifest_tree, utf16=utf16).build())
        if dex is not None:
            zf.writestr("classes.dex", dex)
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def component(name, exported, permission=None, actions=()):
    attrs = [("android:name", "string", name),
             ("android:exported", "bool", exported)]
    if permission:
        attrs.append(("android:permission", "string", permission))
    children = []
    if actions:
        children.append({"name": "intent-filter", "attrs": [], "children": [
            {"name": "action",
             "attrs": [("android:name", "string", a)], "children": []}
            for a in actions]})
    return {"name": "activity", "attrs": attrs, "children": children}


# ------------------------------------------------------------- AXML round-trip
def test_axml_round_trip_benign_utf8():
    data = build_apk_bytes("benign")
    zf = zipfile.ZipFile(io.BytesIO(data))
    m = parse_manifest(zf.read("AndroidManifest.xml"))
    assert m["package"] == "com.example.benign"
    assert m["version_code"] == 1
    assert m["version_name"] == "1.0"
    assert (m["min_sdk"], m["target_sdk"]) == (24, 34)
    assert m["debuggable"] is False
    assert m["allow_backup"] is False
    assert m["uses_cleartext_traffic"] is False
    assert m["permissions"] == ["android.permission.INTERNET"]
    assert len(m["components"]) == 1
    assert m["components"][0]["exported"] is False


def test_axml_round_trip_malicious_utf8():
    data = build_apk_bytes("malicious")
    zf = zipfile.ZipFile(io.BytesIO(data))
    m = parse_manifest(zf.read("AndroidManifest.xml"))
    assert m["package"] == "com.evil.fakebank"
    assert (m["min_sdk"], m["target_sdk"]) == (21, 23)
    assert m["debuggable"] is True
    assert m["allow_backup"] is True
    assert m["uses_cleartext_traffic"] is True
    assert "android.permission.SEND_SMS" in m["permissions"]
    assert len(m["permissions"]) == 7
    receiver = [c for c in m["components"] if c["type"] == "receiver"][0]
    assert receiver["exported"] is True
    assert receiver["has_intent_filter"] is True
    assert "android.intent.action.BOOT_COMPLETED" in receiver["actions"]


def test_axml_round_trip_utf16_benign():
    data = build_apk_bytes("benign", utf16=True)
    zf = zipfile.ZipFile(io.BytesIO(data))
    m = parse_manifest(zf.read("AndroidManifest.xml"))
    assert m["package"] == "com.example.benign"
    assert m["permissions"] == ["android.permission.INTERNET"]
    assert m["target_sdk"] == 34


def test_axml_round_trip_utf16_malicious():
    data = build_apk_bytes("malicious", utf16=True)
    zf = zipfile.ZipFile(io.BytesIO(data))
    m = parse_manifest(zf.read("AndroidManifest.xml"))
    assert m["package"] == "com.evil.fakebank"
    assert "android.permission.BIND_DEVICE_ADMIN" in m["permissions"]
    assert m["debuggable"] is True


def test_axml_parser_rejects_garbage():
    with pytest.raises(AxmlError):
        AxmlParser(b"this is not an axml file at all").parse()


def test_axml_parser_rejects_short_file():
    with pytest.raises(AxmlError):
        AxmlParser(b"\x03\x00").parse()


def test_axml_parser_rejects_wrong_root():
    tree = {"name": "notmanifest", "attrs": [], "children": []}
    with pytest.raises(AxmlError):
        parse_manifest(AxmlWriter(tree).build())


# ------------------------------------------------------------- fixtures
def test_benign_is_safe():
    result = scan("benign")
    assert result["verdict"] == "Safe"
    assert result["score"] == 0
    assert result["findings"] == []


def test_malicious_is_malicious_capped():
    result = scan("malicious")
    assert result["verdict"] == "Malicious"
    assert result["score"] == 100
    assert len(result["findings"]) >= 15


def test_benign_app_identity():
    result = scan("benign")
    assert result["app"]["package"] == "com.example.benign"
    assert result["app"]["signed"] is True
    assert result["app"]["debug_signed"] is False
    assert result["app"]["exported_components"] == []


def test_malicious_app_identity():
    result = scan("malicious")
    assert result["app"]["package"] == "com.evil.fakebank"
    assert result["app"]["signed"] is False
    assert len(result["app"]["exported_components"]) == 2


# ------------------------------------------------------------- permissions
def test_perm_send_sms_is_high():
    result = scan("malicious")
    sms = [f for f in finding_ids(result, "PERM-01")
           if "SEND_SMS" in f["title"]]
    assert len(sms) == 1 and sms[0]["severity"] == "high"


def test_perm_read_contacts_is_low():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "PERM-01")
             if "READ_CONTACTS" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "low"


def test_perm_other_dangerous_permissions_are_low():
    # Only SEND_SMS, READ_SMS, BIND_DEVICE_ADMIN and
    # BIND_ACCESSIBILITY_SERVICE are high; every other dangerous
    # permission is low on its own.
    perms = ["android.permission.%s" % p for p in
             ("READ_CONTACTS", "CAMERA", "REQUEST_INSTALL_PACKAGES",
              "RECEIVE_SMS", "ACCESS_FINE_LOCATION")]
    data = custom_apk(minimal_manifest_tree(permissions=perms))
    result = scan_bytes(data, "test.apk")
    found = finding_ids(result, "PERM-01")
    assert len(found) == 5
    assert all(f["severity"] == "low" for f in found)


def test_perm_internet_not_flagged():
    result = scan("benign")
    assert finding_ids(result, "PERM-01") == []


def test_perm_count_low_at_16():
    perms = ["android.permission.TEST_%02d" % i for i in range(16)]
    data = custom_apk(minimal_manifest_tree(permissions=perms))
    result = scan_bytes(data, "test.apk")
    found = finding_ids(result, "PERM-02")
    assert len(found) == 1 and found[0]["severity"] == "low"


def test_perm_count_medium_at_26():
    perms = ["android.permission.TEST_%02d" % i for i in range(26)]
    data = custom_apk(minimal_manifest_tree(permissions=perms))
    result = scan_bytes(data, "test.apk")
    found = finding_ids(result, "PERM-02")
    assert len(found) == 1 and found[0]["severity"] == "medium"


def test_perm_count_not_flagged_at_15():
    perms = ["android.permission.TEST_%02d" % i for i in range(15)]
    data = custom_apk(minimal_manifest_tree(permissions=perms))
    result = scan_bytes(data, "test.apk")
    assert finding_ids(result, "PERM-02") == []


# ------------------------------------------------------------- components
def test_exported_without_permission_is_high():
    comp = component("com.test.app.Main", True)
    data = custom_apk(minimal_manifest_tree(components=[comp]))
    result = scan_bytes(data, "test.apk")
    found = finding_ids(result, "EXP-01")
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_exported_with_intent_filter_is_info():
    # Public by design (launcher activity, share target): listed,
    # but scores nothing — large legitimate apps have many of these.
    comp = component("com.test.app.Main", True,
                     actions=["android.intent.action.MAIN"])
    data = custom_apk(minimal_manifest_tree(components=[comp]))
    result = scan_bytes(data, "test.apk")
    found = finding_ids(result, "EXP-01")
    assert len(found) == 1 and found[0]["severity"] == "info"
    assert "public by design" in found[0]["title"]


def test_exported_with_permission_is_info():
    comp = component("com.test.app.Main", True,
                     permission="android.permission.BIND_JOB_SERVICE")
    data = custom_apk(minimal_manifest_tree(components=[comp]))
    result = scan_bytes(data, "test.apk")
    found = finding_ids(result, "EXP-01")
    assert len(found) == 1 and found[0]["severity"] == "info"


def test_non_exported_component_not_flagged():
    comp = component("com.test.app.Main", False)
    data = custom_apk(minimal_manifest_tree(components=[comp]))
    result = scan_bytes(data, "test.apk")
    assert finding_ids(result, "EXP-01") == []


def test_exported_boot_receiver_is_medium():
    comp = {"name": "receiver",
            "attrs": [("android:name", "string", "com.test.app.Boot"),
                      ("android:exported", "bool", True)],
            "children": [{"name": "intent-filter", "attrs": [], "children": [
                {"name": "action",
                 "attrs": [("android:name", "string",
                            "android.intent.action.BOOT_COMPLETED")],
                 "children": []}]}]}
    data = custom_apk(minimal_manifest_tree(components=[comp]))
    result = scan_bytes(data, "test.apk")
    boot = [f for f in finding_ids(result, "EXP-01") if "boot" in f["title"]]
    assert len(boot) == 1 and boot[0]["severity"] == "medium"
    # The receiver itself has an intent filter, so it is info, not high.
    comp_finding = [f for f in finding_ids(result, "EXP-01")
                    if "boot" not in f["title"]]
    assert len(comp_finding) == 1
    assert comp_finding[0]["severity"] == "info"


# ------------------------------------------------------------- build flags
def test_debuggable_is_high():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DBG-01")
             if "debuggable" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_allow_backup_is_low():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DBG-01")
             if "backups" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "low"


def test_cleartext_is_low():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DBG-01")
             if "cleartext" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "low"


def test_old_target_sdk_is_medium():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DBG-01")
             if "target SDK" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "medium"


def test_old_min_sdk_is_low():
    data = custom_apk(minimal_manifest_tree(min_sdk=16))
    result = scan_bytes(data, "test.apk")
    found = [f for f in finding_ids(result, "DBG-01")
             if "minimum SDK" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "low"


def test_benign_has_no_dbg_findings():
    result = scan("benign")
    assert finding_ids(result, "DBG-01") == []


# ------------------------------------------------------------- dex strings
def test_dex_sms_category():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DEX-01")
             if f["title"].endswith("sms")]
    assert len(found) == 1 and found[0]["severity"] == "high"
    assert "SmsManager" in found[0]["evidence"]


def test_dex_dynamic_loading_category():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DEX-01")
             if f["title"].endswith("dynamic_loading")]
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_dex_root_category():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DEX-01")
             if f["title"].endswith("root")]
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_dex_reflection_is_low():
    dex = (b"dex\n035\x00" + b"\x00" * 104
           + b"Class.forName\x00getDeclaredMethod\x00Method.invoke\x00")
    data = custom_apk(minimal_manifest_tree(), dex=dex)
    result = scan_bytes(data, "test.apk")
    found = [f for f in finding_ids(result, "DEX-01")
             if f["title"].endswith("reflection")]
    assert len(found) == 1 and found[0]["severity"] == "low"


def test_dex_exfiltration_category():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DEX-01")
             if f["title"].endswith("exfiltration")]
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_dex_obfuscation_category():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DEX-01")
             if f["title"].endswith("obfuscation")]
    assert len(found) == 1 and found[0]["severity"] == "low"


def test_dex_contacts_category():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "DEX-01")
             if f["title"].endswith("contacts")]
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_dex_benign_clean():
    result = scan("benign")
    assert finding_ids(result, "DEX-01") == []


def test_url_found_in_malicious_dex():
    result = scan("malicious")
    assert any("discord.com" in url for url in result["urls"])
    assert len(finding_ids(result, "URL-01")) >= 1


def test_url_benign_empty():
    result = scan("benign")
    assert result["urls"] == []


# ------------------------------------------------------------- signing
def test_unsigned_is_high():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "CERT-01")
             if "no signature" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_manifest_mf_missing_is_medium():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "CERT-01")
             if "MANIFEST.MF" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "medium"


def test_debug_certificate_detected():
    extra = {"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
             "META-INF/CERT.RSA": b"CN=Android Debug, O=Android\n"}
    data = custom_apk(minimal_manifest_tree(), extra=extra)
    result = scan_bytes(data, "test.apk")
    found = [f for f in finding_ids(result, "CERT-01")
             if "debug certificate" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "high"
    assert result["app"]["debug_signed"] is True
    assert result["app"]["signed"] is True


def test_signed_benign_has_no_cert_findings():
    result = scan("benign")
    assert finding_ids(result, "CERT-01") == []


# ------------------------------------------------------------- archive
def test_nested_apk_flagged():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "ZIP-01")
             if "Nested APK" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "medium"


def test_native_libs_listed_as_info():
    result = scan("malicious")
    found = [f for f in finding_ids(result, "ZIP-01")
             if "Native libraries" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "info"


def test_path_traversal_flagged():
    extra = {"../evil.sh": b"#!/bin/sh\n"}
    data = custom_apk(minimal_manifest_tree(), extra=extra)
    result = scan_bytes(data, "test.apk")
    found = [f for f in finding_ids(result, "ZIP-01")
             if "traversal" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_zip_bomb_flagged():
    extra = {"big.txt": b"\x00" * 2_000_000}
    data = custom_apk(minimal_manifest_tree(), extra=extra)
    result = scan_bytes(data, "test.apk")
    found = [f for f in finding_ids(result, "ZIP-01")
             if "zip bomb" in f["title"]]
    assert len(found) == 1 and found[0]["severity"] == "high"


# ------------------------------------------------------------- hashes / entropy
def test_hashes_match_hashlib():
    data = build_apk_bytes("benign")
    result = scan_bytes(data, "benign.apk")
    assert result["file"]["md5"] == hashlib.md5(data).hexdigest()
    assert result["file"]["sha1"] == hashlib.sha1(data).hexdigest()
    assert result["file"]["sha256"] == hashlib.sha256(data).hexdigest()


def test_dex_hash_present():
    result = scan("benign")
    assert result["file"]["dex_sha256"] is not None
    assert len(result["file"]["dex_sha256"]) == 64


def test_high_entropy_dex_flagged():
    dex = b"dex\n035\x00" + os.urandom(8192)
    data = custom_apk(minimal_manifest_tree(), dex=dex)
    result = scan_bytes(data, "test.apk")
    found = finding_ids(result, "ENT-01")
    assert len(found) == 1 and found[0]["severity"] == "medium"
    assert result["file"]["entropy"] > 7.5


def test_plain_dex_not_flagged_for_entropy():
    result = scan("benign")
    assert finding_ids(result, "ENT-01") == []
    assert result["file"]["entropy"] < 7.5


# ------------------------------------------------------------- malformed input
def test_non_zip_handled_gracefully():
    result = scan_bytes(b"hello world, not an apk", "fake.apk")
    found = finding_ids(result, "FILE-01")
    assert len(found) == 1 and found[0]["severity"] == "high"
    assert result["verdict"] == "Suspicious"


def test_corrupt_zip_handled_gracefully():
    result = scan_bytes(b"PK\x03\x04" + b"\x00" * 40, "broken.apk")
    assert finding_ids(result, "FILE-01")


def test_missing_manifest_handled_gracefully():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00hello")
    result = scan_bytes(buf.getvalue(), "nomanifest.apk")
    found = finding_ids(result, "MANI-01")
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_unparseable_manifest_handled_gracefully():
    extra = {"AndroidManifest.xml": b"this is not binary xml"}
    data = custom_apk(None, extra=extra)
    result = scan_bytes(data, "test.apk")
    found = finding_ids(result, "MANI-01")
    assert len(found) == 1 and found[0]["severity"] == "high"


def test_empty_file_handled_gracefully():
    result = scan_bytes(b"", "empty.apk")
    assert finding_ids(result, "FILE-01")


def test_oversize_rejected():
    with pytest.raises(ValueError):
        scan_bytes(b"x" * (MAX_APK_SIZE + 1), "huge.apk")


def test_scan_file(tmp_path):
    path = tmp_path / "benign.apk"
    path.write_bytes(build_apk_bytes("benign"))
    result = scan_file(str(path))
    assert result["verdict"] == "Safe"


# ------------------------------------------------------------- scoring
def _verdict_for(severities):
    result = ApkScanResult("test.apk", b"")
    for i, sev in enumerate(severities):
        result.add("T-%02d" % i, "test", "t", sev, "", "", "")
    return result.to_dict()


def test_scoring_safe():
    assert _verdict_for([])["verdict"] == "Safe"


def test_scoring_suspicious():
    assert _verdict_for(["medium", "medium"])["verdict"] == "Suspicious"


def test_scoring_high_risk():
    assert _verdict_for(["high", "high"])["verdict"] == "High Risk"


def test_scoring_malicious():
    assert _verdict_for(["critical", "critical"])["verdict"] == "Malicious"


def test_scoring_cap():
    d = _verdict_for(["critical"] * 10)
    assert d["score"] == 100


def test_single_critical_forces_high_risk():
    d = _verdict_for(["critical"])
    assert d["score"] == 25
    assert d["verdict"] == "High Risk"


# ------------------------------------------------------------- per-rule caps
def _verdict_for_rule(rule, severities):
    result = ApkScanResult("test.apk", b"")
    for sev in severities:
        result.add(rule, "test", "t", sev, "", "", "")
    return result.to_dict()


def test_perm_01_cap_24():
    # Ten high PERM-01 findings would be 150 uncapped; the rule
    # contributes at most 24.
    d = _verdict_for_rule("PERM-01", ["high"] * 10)
    assert d["score"] == 24
    assert d["verdict"] == "Suspicious"


def test_dex_01_cap_24():
    d = _verdict_for_rule("DEX-01", ["high"] * 10)
    assert d["score"] == 24
    assert d["verdict"] == "Suspicious"


def test_default_rule_cap_25():
    d = _verdict_for_rule("EXP-01", ["high"] * 10)
    assert d["score"] == 25
    assert d["verdict"] == "Suspicious"


def test_caps_prevent_malicious_on_volume_alone():
    # Two whole rules maxed out still cannot reach Malicious by
    # volume: 24 + 24 = 48, High Risk at most.
    result = ApkScanResult("test.apk", b"")
    for _ in range(10):
        result.add("PERM-01", "test", "t", "high", "", "", "")
        result.add("DEX-01", "test", "t", "high", "", "", "")
    d = result.to_dict()
    assert d["score"] == 48
    assert d["verdict"] == "High Risk"


def test_cap_does_not_hide_a_real_signal():
    # A capped rule plus one strong finding elsewhere still reaches
    # Malicious: the caps only stop volume, not real danger.
    result = ApkScanResult("test.apk", b"")
    for _ in range(10):
        result.add("PERM-01", "test", "t", "high", "", "", "")
    result.add("CERT-01", "test", "unsigned", "high", "", "", "")
    result.add("DBG-01", "test", "debuggable", "high", "", "", "")
    d = result.to_dict()
    assert d["score"] == 24 + 15 + 15
    assert d["verdict"] == "Malicious"


# ------------------------------------------------------------- safety
def test_scan_makes_no_network_requests(monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("network call attempted")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    result = scan("malicious")
    assert result["verdict"] == "Malicious"


def test_scan_writes_no_files(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    scan("malicious")
    scan("benign")
    assert list(tmp_path.iterdir()) == []


# ------------------------------------------------------------- Flask API
@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def test_health(client):
    assert client.get("/health").status_code == 200
    assert client.get("/health").get_json() == {"status": "ok"}


def test_index(client):
    assert client.get("/").status_code == 200


def test_examples_list(client):
    resp = client.get("/api/examples")
    assert resp.status_code == 200
    names = [e["name"] for e in resp.get_json()["examples"]]
    assert names == ["benign", "malicious"]


def test_api_example_benign(client):
    resp = client.get("/api/example/benign")
    assert resp.status_code == 200
    assert resp.get_json()["verdict"] == "Safe"


def test_api_example_malicious(client):
    resp = client.get("/api/example/malicious")
    assert resp.status_code == 200
    assert resp.get_json()["verdict"] == "Malicious"


def test_api_example_unknown_is_404(client):
    assert client.get("/api/example/evil").status_code == 404


def test_api_example_traversal_is_404(client):
    assert client.get("/api/example/..%2F..%2Fetc%2Fpasswd").status_code == 404


def test_api_scan_benign_upload(client):
    resp = client.post("/api/scan", data={
        "file": (io.BytesIO(build_apk_bytes("benign")), "benign.apk")})
    assert resp.status_code == 200
    assert resp.get_json()["verdict"] == "Safe"


def test_api_scan_malicious_upload(client):
    resp = client.post("/api/scan", data={
        "file": (io.BytesIO(build_apk_bytes("malicious")), "malicious.apk")})
    assert resp.status_code == 200
    assert resp.get_json()["verdict"] == "Malicious"


def test_api_scan_no_file_is_400(client):
    assert client.post("/api/scan", data={}).status_code == 400


def test_api_scan_wrong_extension_is_400(client):
    resp = client.post("/api/scan", data={
        "file": (io.BytesIO(b"hello"), "notes.txt")})
    assert resp.status_code == 400
