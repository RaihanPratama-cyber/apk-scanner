"""Build example APKs for the APK Scanner (benign and malicious).

No binary files are committed to the repo: this TEXT script builds the
APKs in memory. It includes a minimal binary AndroidManifest.xml
(AXML) writer — string pool, namespace chunks, start/end element
chunks — so the scanner's parser can be tested round-trip against
exactly what the writer wrote. Supports both UTF-8 and UTF-16
string pools.

Usage:
    python make_examples.py            # writes benign.apk / malicious.apk
    from make_examples import build_apk_bytes
    data = build_apk_bytes("malicious")  # bytes, nothing written to disk
"""

import io
import struct
import zipfile

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Typed value kinds used by the writer.
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT = 0x10
TYPE_BOOLEAN = 0x12


# ---------------------------------------------------------------- AXML writer
def _encode_length(value):
    """One AXML length varint."""
    if value < 0x80:
        return bytes([value])
    return bytes([0x80 | (value >> 8), value & 0xFF])


def _encode_utf8_string(text):
    raw = text.encode("utf-8")
    return (_encode_length(len(text)) + _encode_length(len(raw)) + raw
            + b"\x00")


def _encode_utf16_string(text):
    length = len(text)
    if length < 0x8000:
        prefix = struct.pack("<H", length)
    else:
        prefix = struct.pack("<HH", 0x8000 | (length >> 16), length & 0xFFFF)
    return prefix + text.encode("utf-16-le") + b"\x00\x00"


class AxmlWriter:
    """Write a binary AndroidManifest.xml from a nested element tree.

    Tree node: {"name": str, "attrs": [(name, kind, value), ...],
                "children": [node, ...]}
    Attribute kinds: "string", "int", "bool", "float". Attribute names
    starting with "android:" use the android namespace; anything else
    (e.g. "package") has no namespace.
    """

    def __init__(self, root, utf16=False):
        self.root = root
        self.utf16 = utf16
        self.strings = []
        self.index = {}

    def _add(self, text):
        if text not in self.index:
            self.index[text] = len(self.strings)
            self.strings.append(text)
        return self.index[text]

    def _collect(self, node):
        self._add(node["name"])
        for name, _kind, value in node.get("attrs", []):
            self._add(name.split(":", 1)[-1])
            if isinstance(value, str):
                self._add(value)
        for child in node.get("children", []):
            self._collect(child)

    def _string_pool(self):
        encode = _encode_utf16_string if self.utf16 else _encode_utf8_string
        flags = 0 if self.utf16 else 0x100
        blobs = [encode(s) for s in self.strings]
        offsets = []
        pos = 0
        for blob in blobs:
            offsets.append(pos)
            pos += len(blob)
            # Each string starts 4-byte aligned inside the pool.
            pos = (pos + 3) & ~3
        body = b"".join(
            struct.pack("<I", o) for o in offsets)
        data = bytearray()
        for blob in blobs:
            data += blob
            while len(data) % 4:
                data += b"\x00"
        strings_start = 28 + 4 * len(self.strings)
        size = strings_start + len(data)
        return (struct.pack("<HHI", 0x0001, 28, size)
                + struct.pack("<IIIII", len(self.strings), 0, flags,
                              strings_start, 0)
                + body + bytes(data))

    def _ns_chunk(self, chunk_type):
        prefix = self._add("android")
        uri = self._add(ANDROID_NS)
        return (struct.pack("<HHI", chunk_type, 16, 24)
                + struct.pack("<IIII", 0, 0xFFFFFFFF, prefix, uri))

    def _start_element(self, node):
        name_idx = self._add(node["name"])
        attrs = node.get("attrs", [])
        # attributeStart is relative to the attrExt struct (which starts
        # 16 bytes into the chunk), so it is 20, not 36. The chunk size,
        # though, is measured from the chunk start: 36 + attributes.
        attr_start = 20
        attr_size = 20
        chunk_size = 36 + len(attrs) * attr_size
        out = bytearray()
        out += struct.pack("<HHI", 0x0102, 16, chunk_size)
        out += struct.pack("<II", 0, 0xFFFFFFFF)      # line, comment
        out += struct.pack("<I", 0xFFFFFFFF)          # namespace
        out += struct.pack("<I", name_idx)
        out += struct.pack("<HHHHHH", attr_start, attr_size, len(attrs),
                           0xFFFF, 0xFFFF, 0xFFFF)
        for attr_name, kind, value in attrs:
            if attr_name.startswith("android:"):
                ns_idx = self._add(ANDROID_NS)
                short = attr_name.split(":", 1)[1]
            else:
                ns_idx = 0xFFFFFFFF
                short = attr_name
            name_i = self._add(short)
            if kind == "string":
                raw_value = self._add(value)
                data_type, data = TYPE_STRING, self._add(value)
            elif kind == "int":
                raw_value = 0xFFFFFFFF
                data_type, data = TYPE_INT, value & 0xFFFFFFFF
            elif kind == "bool":
                raw_value = 0xFFFFFFFF
                data_type = TYPE_BOOLEAN
                data = 0xFFFFFFFF if value else 0
            elif kind == "float":
                raw_value = 0xFFFFFFFF
                data_type = TYPE_FLOAT
                data = struct.unpack("<I", struct.pack("<f", value))[0]
            else:  # pragma: no cover - guarded by callers
                raise ValueError("unknown attribute kind %r" % kind)
            out += struct.pack("<III", ns_idx, name_i, raw_value)
            out += struct.pack("<HBBI", 8, 0, data_type, data)
        return bytes(out)

    def _end_element(self, node):
        name_idx = self._add(node["name"])
        return (struct.pack("<HHI", 0x0103, 16, 24)
                + struct.pack("<II", 0, 0xFFFFFFFF)
                + struct.pack("<I", 0xFFFFFFFF)
                + struct.pack("<I", name_idx))

    def _write_node(self, node):
        out = bytearray()
        out += self._start_element(node)
        for child in node.get("children", []):
            out += self._write_node(child)
        out += self._end_element(node)
        return bytes(out)

    def build(self):
        self._add(ANDROID_NS)
        self._add("android")
        self._collect(self.root)
        body = self._string_pool()
        body += self._ns_chunk(0x0100)  # namespace start
        body += self._write_node(self.root)
        body += self._ns_chunk(0x0101)  # namespace end
        total = 8 + len(body)
        return struct.pack("<II", 0x00080003, total) + body


# ---------------------------------------------------------------- APK builders
def _manifest_tree(kind):
    if kind == "benign":
        return {
            "name": "manifest",
            "attrs": [("package", "string", "com.example.benign"),
                      ("versionCode", "int", 1),
                      ("versionName", "string", "1.0")],
            "children": [
                {"name": "uses-sdk",
                 "attrs": [("android:minSdkVersion", "int", 24),
                           ("android:targetSdkVersion", "int", 34)],
                 "children": []},
                {"name": "uses-permission",
                 "attrs": [("android:name", "string",
                            "android.permission.INTERNET")],
                 "children": []},
                {"name": "application",
                 "attrs": [("android:debuggable", "bool", False),
                           ("android:allowBackup", "bool", False),
                           ("android:usesCleartextTraffic", "bool", False)],
                 "children": [
                     {"name": "activity",
                      "attrs": [("android:name", "string",
                                 "com.example.benign.MainActivity"),
                                ("android:exported", "bool", False)],
                      "children": []},
                 ]},
            ],
        }
    if kind == "malicious":
        return {
            "name": "manifest",
            "attrs": [("package", "string", "com.evil.fakebank"),
                      ("versionCode", "int", 1),
                      ("versionName", "string", "1.0")],
            "children": [
                {"name": "uses-sdk",
                 "attrs": [("android:minSdkVersion", "int", 21),
                           ("android:targetSdkVersion", "int", 23)],
                 "children": []},
                {"name": "uses-permission",
                 "attrs": [("android:name", "string",
                            "android.permission.SEND_SMS")],
                 "children": []},
                {"name": "uses-permission",
                 "attrs": [("android:name", "string",
                            "android.permission.READ_SMS")],
                 "children": []},
                {"name": "uses-permission",
                 "attrs": [("android:name", "string",
                            "android.permission.READ_CONTACTS")],
                 "children": []},
                {"name": "uses-permission",
                 "attrs": [("android:name", "string",
                            "android.permission.RECORD_AUDIO")],
                 "children": []},
                {"name": "uses-permission",
                 "attrs": [("android:name", "string",
                            "android.permission.BIND_DEVICE_ADMIN")],
                 "children": []},
                {"name": "uses-permission",
                 "attrs": [("android:name", "string",
                            "android.permission.REQUEST_INSTALL_PACKAGES")],
                 "children": []},
                {"name": "uses-permission",
                 "attrs": [("android:name", "string",
                            "android.permission.INTERNET")],
                 "children": []},
                {"name": "application",
                 "attrs": [("android:debuggable", "bool", True),
                           ("android:allowBackup", "bool", True),
                           ("android:usesCleartextTraffic", "bool", True)],
                 "children": [
                     {"name": "activity",
                      "attrs": [("android:name", "string",
                                 "com.evil.fakebank.MainActivity"),
                                ("android:exported", "bool", True)],
                      "children": [
                          {"name": "intent-filter", "attrs": [],
                           "children": [
                               {"name": "action",
                                "attrs": [("android:name", "string",
                                           "android.intent.action.MAIN")],
                                "children": []},
                               {"name": "category",
                                "attrs": [("android:name", "string",
                                           "android.intent.category.LAUNCHER")],
                                "children": []},
                           ]},
                      ]},
                     {"name": "receiver",
                      "attrs": [("android:name", "string",
                                 "com.evil.fakebank.BootReceiver"),
                                ("android:exported", "bool", True)],
                      "children": [
                          {"name": "intent-filter", "attrs": [],
                           "children": [
                               {"name": "action",
                                "attrs": [("android:name", "string",
                                           "android.intent.action.BOOT_COMPLETED")],
                                "children": []},
                           ]},
                      ]},
                     {"name": "service",
                      "attrs": [("android:name", "string",
                                 "com.evil.fakebank.EvilService"),
                                ("android:exported", "bool", False)],
                      "children": []},
                 ]},
            ],
        }
    raise ValueError("unknown example kind %r" % kind)


def _fake_dex(kind):
    """A synthetic classes.dex: real dex magic, harmless/malicious
    strings only. It is NOT real bytecode — the scanner only reads
    strings from it, which is exactly what the fixtures are for."""
    header = b"dex\n035\x00" + b"\x00" * 104
    if kind == "benign":
        strings = [
            b"Hello, world!",
            b"com.example.benign.MainActivity",
            b"android.app.Activity",
        ]
    else:
        strings = [
            b"android.telephony.SmsManager",
            b"sendTextMessage",
            b"android.provider.ContactsContract",
            b"dalvik.system.DexClassLoader",
            b"loadDex",
            b"/system/bin/su",
            b"https://discord.com/api/webhooks/123456789/abcdef",
            # Long base64-looking blob (obfuscation signal).
            b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrL2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSg==",
        ]
    return header + b"\x00".join(strings) + b"\x00"


def build_apk_bytes(kind, utf16=False):
    """Build one example APK in memory. kind is 'benign' or 'malicious'."""
    manifest = AxmlWriter(_manifest_tree(kind), utf16=utf16).build()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", _fake_dex(kind))
        zf.writestr("res/layout/main.xml", b"<layout/>")
        if kind == "benign":
            zf.writestr("META-INF/MANIFEST.MF",
                        b"Manifest-Version: 1.0\nCreated-By: Example\n")
            zf.writestr("META-INF/CERT.SF",
                        b"Signature-Version: 1.0\n")
            zf.writestr("META-INF/CERT.RSA",
                        b"CN=Example Developer, O=Example\n")
        else:
            # A native library and a nested APK: archive-risk signals.
            zf.writestr("lib/armeabi-v7a/libevil.so", b"\x7fELF" + b"\x00" * 64)
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w") as inner:
                inner.writestr("AndroidManifest.xml", b"fake")
            zf.writestr("assets/update.apk", nested.getvalue())
    return buf.getvalue()


def main():
    for kind in ("benign", "malicious"):
        data = build_apk_bytes(kind)
        with open("%s.apk" % kind, "wb") as fh:
            fh.write(data)
        print("%s.apk: %d bytes" % (kind, len(data)))


if __name__ == "__main__":
    main()
