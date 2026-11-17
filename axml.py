"""Minimal binary AndroidManifest.xml (AXML) parser — Python stdlib only.

Reads the string pool (UTF-8 and UTF-16), the resource map, namespace
chunks and start/end element chunks, and rebuilds the manifest as a
plain Python dict. Best-effort: malformed files raise AxmlError instead
of crashing the caller.

Reference layout (all integers little-endian):
  file:   u32 magic 0x00080003, u32 file size, then chunks
  chunk:  u16 type, u16 header size, u32 chunk size
  string pool (0x0001): u32 string count, u32 style count, u32 flags
          (0x100 = UTF-8), u32 strings start, u32 styles start,
          then u32 offsets, then the string data
  start element (0x0102): u32 line, u32 comment, u32 ns, u32 name,
          u16 attr start, u16 attr size, u16 attr count, u16 id idx,
          u16 class idx, u16 style idx, then attributes
  attribute: u32 ns, u32 name, u32 raw value (0xFFFFFFFF = none),
          u16 value size (8), u8 res0, u8 data type, u32 data
"""

import struct

CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_MAP = 0x0180
CHUNK_NS_START = 0x0100
CHUNK_NS_END = 0x0101
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103
CHUNK_TEXT = 0x0104

FLAG_UTF8 = 0x100

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT = 0x10
TYPE_BOOLEAN = 0x12

COMPONENT_TYPES = {"activity", "activity-alias", "service", "receiver", "provider"}


class AxmlError(Exception):
    """Raised when the binary manifest cannot be parsed."""


def _u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _i32(data, off):
    return struct.unpack_from("<i", data, off)[0]


def _read_varint(data, off):
    """One AXML length varint: 1 byte, or 2 bytes if the high bit is set."""
    first = data[off]
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[off + 1], off + 2
    return first, off + 1


def _read_utf8_string(data, off):
    # First varint is the UTF-16 length, second is the UTF-8 byte length.
    _, off = _read_varint(data, off)
    byte_len, off = _read_varint(data, off)
    raw = data[off:off + byte_len]
    return raw.decode("utf-8", errors="replace")


def _read_utf16_string(data, off):
    length = _u16(data, off)
    off += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | _u16(data, off)
        off += 2
    raw = data[off:off + length * 2]
    return raw.decode("utf-16-le", errors="replace")


class AxmlParser:
    """Parse a binary AndroidManifest.xml into a nested element tree."""

    def __init__(self, data: bytes):
        self.data = data
        self.strings = []
        self.utf8 = True
        self.root = None

    # -- string pool -----------------------------------------------------
    def _parse_string_pool(self, base):
        count = _u32(self.data, base + 8)
        flags = _u32(self.data, base + 16)
        strings_start = _u32(self.data, base + 20)
        self.utf8 = bool(flags & FLAG_UTF8)
        offsets_base = base + 28
        data_start = base + strings_start
        strings = []
        for i in range(count):
            if offsets_base + i * 4 + 4 > len(self.data):
                raise AxmlError("string pool offsets run past end of file")
            off = _u32(self.data, offsets_base + i * 4)
            pos = data_start + off
            if pos >= len(self.data):
                raise AxmlError("string pool entry runs past end of file")
            if self.utf8:
                strings.append(_read_utf8_string(self.data, pos))
            else:
                strings.append(_read_utf16_string(self.data, pos))
        self.strings = strings

    def _get_string(self, idx):
        if idx == 0xFFFFFFFF:
            return None
        if idx >= len(self.strings):
            raise AxmlError("string index %d out of range" % idx)
        return self.strings[idx]

    # -- typed values ----------------------------------------------------
    def _typed_value(self, off):
        size = _u16(self.data, off)
        if size < 8:
            raise AxmlError("typed value too small")
        data_type = self.data[off + 3]
        raw = _u32(self.data, off + 4)
        if data_type == TYPE_STRING:
            return self._get_string(raw)
        if data_type == TYPE_INT:
            return _i32(self.data, off + 4)
        if data_type == TYPE_BOOLEAN:
            return raw != 0
        if data_type == TYPE_FLOAT:
            return struct.unpack_from("<f", self.data, off + 4)[0]
        if data_type == TYPE_REFERENCE:
            return "@0x%08x" % raw
        return raw

    # -- main parse ------------------------------------------------------
    def parse(self):
        data = self.data
        if len(data) < 8:
            raise AxmlError("file too short for an AXML header")
        if _u32(data, 0) != 0x00080003:
            raise AxmlError("bad AXML magic (not a binary AndroidManifest.xml)")
        stack = []
        off = 8
        while off + 8 <= len(data):
            chunk_type = _u16(data, off)
            chunk_size = _u32(data, off + 4)
            if chunk_size < 8 or off + chunk_size > len(data):
                raise AxmlError("chunk size out of bounds at offset %d" % off)
            if chunk_type == CHUNK_STRING_POOL:
                self._parse_string_pool(off)
            elif chunk_type == CHUNK_START_ELEMENT:
                element = self._parse_start_element(off)
                if stack:
                    stack[-1]["children"].append(element)
                else:
                    self.root = element
                stack.append(element)
            elif chunk_type == CHUNK_END_ELEMENT:
                if stack:
                    stack.pop()
            elif chunk_type == CHUNK_TEXT:
                pass  # text content is not used in a manifest
            # namespace and resource-map chunks carry no element data
            off += chunk_size
        if self.root is None:
            raise AxmlError("no root element found")
        return self.root

    def _parse_start_element(self, base):
        ns_idx = _u32(self.data, base + 16)
        name_idx = _u32(self.data, base + 20)
        attr_start = _u16(self.data, base + 24)
        attr_size = _u16(self.data, base + 26)
        attr_count = _u16(self.data, base + 28)
        name = self._get_string(name_idx)
        attrs = {}
        # attributeStart is relative to the attrExt struct, which begins
        # 16 bytes into the chunk (after the chunk header, line number
        # and comment) — not relative to the chunk start.
        pos = base + 16 + attr_start
        for _ in range(attr_count):
            if attr_size < 20 or pos + 20 > len(self.data):
                raise AxmlError("attribute runs past end of chunk")
            attr_ns = _u32(self.data, pos)
            attr_name_idx = _u32(self.data, pos + 4)
            raw_value = _u32(self.data, pos + 8)
            attr_name = self._get_string(attr_name_idx)
            if raw_value != 0xFFFFFFFF:
                value = self._get_string(raw_value)
            else:
                value = self._typed_value(pos + 12)
            # Keep the plain name; the namespace URI is rarely needed
            # for a manifest, and attribute names are unique per element.
            attrs[attr_name] = value
            pos += attr_size
        return {"name": name, "ns": self._get_string(ns_idx),
                "attrs": attrs, "children": []}


def _walk(element, visit):
    visit(element)
    for child in element.get("children", []):
        _walk(child, visit)


def parse_manifest(data: bytes):
    """Parse binary AndroidManifest.xml bytes into a plain dict.

    Returns keys: package, version_code, version_name, min_sdk,
    target_sdk, debuggable, allow_backup, uses_cleartext_traffic,
    permissions (list of full names), components (list of dicts with
    type, name, exported, permission, has_intent_filter, actions).
    """
    root = AxmlParser(data).parse()
    if root["name"] != "manifest":
        raise AxmlError("root element is %r, not 'manifest'" % root["name"])

    out = {
        "package": root["attrs"].get("package"),
        "version_code": root["attrs"].get("versionCode"),
        "version_name": root["attrs"].get("versionName"),
        "min_sdk": None,
        "target_sdk": None,
        "debuggable": None,
        "allow_backup": None,
        "uses_cleartext_traffic": None,
        "permissions": [],
        "components": [],
    }

    def visit(el):
        name = el["name"]
        attrs = el["attrs"]
        if name == "uses-sdk":
            out["min_sdk"] = attrs.get("minSdkVersion")
            out["target_sdk"] = attrs.get("targetSdkVersion")
        elif name == "uses-permission":
            perm = attrs.get("name")
            if perm:
                out["permissions"].append(perm)
        elif name == "application":
            out["debuggable"] = attrs.get("debuggable")
            out["allow_backup"] = attrs.get("allowBackup")
            out["uses_cleartext_traffic"] = attrs.get("usesCleartextTraffic")

    _walk(root, visit)

    # Components need their intent-filter children, so walk with a stack.
    def walk_components(el, ancestors):
        if el["name"] in COMPONENT_TYPES:
            comp = {
                "type": el["name"],
                "name": el["attrs"].get("name"),
                "exported": el["attrs"].get("exported"),
                "permission": el["attrs"].get("permission"),
                "has_intent_filter": False,
                "actions": [],
            }
            for child in el["children"]:
                if child["name"] == "intent-filter":
                    comp["has_intent_filter"] = True
                    for grand in child["children"]:
                        if grand["name"] == "action":
                            action = grand["attrs"].get("name")
                            if action:
                                comp["actions"].append(action)
            out["components"].append(comp)
        for child in el["children"]:
            walk_components(child, ancestors + [el])

    walk_components(root, [])
    return out
