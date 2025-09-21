#!/usr/bin/env python3
"""Decode Photos .plj journal files without Apple private frameworks."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import plistlib
import struct
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional, Any, Tuple

MAGIC = b"bplist00"
PREFIX_SIZE = 5
HEADER_SENTINEL = 0x40
HEADER_SIZE_MAX = 255  # header length stored in single byte
MAX_VARINT_SHIFT = 63
MAX_PROTO_OBJECTS = 5_000_000


# ---------------------------------------------------------------------------
# Protobuf utilities
# ---------------------------------------------------------------------------

def read_varint(data: memoryview, offset: int) -> Tuple[Optional[int], int]:
    """Decode a protobuf-style unsigned varint."""
    result = 0
    shift = 0
    length = len(data)
    while offset < length and shift <= MAX_VARINT_SHIFT:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, offset
        shift += 7
    return None, offset


def skip_field(data: memoryview, offset: int, wire_type: int) -> Optional[int]:
    """Skip over an unknown protobuf field."""
    if wire_type == 0:  # varint
        _, offset = read_varint(data, offset)
        return offset
    if wire_type == 1:  # 64-bit
        return offset + 8 if offset + 8 <= len(data) else None
    if wire_type == 2:  # length-delimited
        length, offset = read_varint(data, offset)
        if length is None or offset + length > len(data):
            return None
        return offset + length
    if wire_type == 5:  # 32-bit
        return offset + 4 if offset + 4 <= len(data) else None
    if wire_type == 3:  # start group (deprecated but handle defensively)
        while offset < len(data):
            key, offset = read_varint(data, offset)
            if key is None:
                return None
            wt = key & 0x7
            if wt == 4:
                return offset
            offset = skip_field(data, offset, wt)
            if offset is None:
                return None
        return None
    return None


@dataclass
class JournalHeader:
    entry_type: int
    payload_uuid: Optional[uuid.UUID]
    payload_id: Optional[str]
    payload_version: int
    payload_length: int
    payload_crc: int
    nil_properties: list[str]


class HeaderParseError(RuntimeError):
    """Raised when the protobuf header cannot be decoded."""


def parse_header(raw: bytes) -> JournalHeader:
    """Parse the binary protobuf header attached to each journal entry."""
    data = memoryview(raw)
    offset = 0

    entry_type = 0
    payload_uuid: Optional[uuid.UUID] = None
    payload_id: Optional[str] = None
    payload_version = 0
    payload_length = 0
    payload_crc = 0
    nil_properties: list[str] = []

    while offset < len(data):
        key, offset = read_varint(data, offset)
        if key is None:
            raise HeaderParseError("failed to read header field key")
        field_number = key >> 3
        wire_type = key & 0x7

        if field_number == 1:  # entryType (varint)
            value, offset = read_varint(data, offset)
            if value is None:
                raise HeaderParseError("invalid entryType")
            entry_type = value
        elif field_number == 2:  # payloadUUID (length-delimited 16 bytes)
            length, offset = read_varint(data, offset)
            if length is None or offset + length > len(data):
                raise HeaderParseError("invalid payloadUUID length")
            uuid_bytes = data[offset:offset + length].tobytes()
            offset += length
            if len(uuid_bytes) == 16:
                payload_uuid = uuid.UUID(bytes=uuid_bytes)
        elif field_number == 3:  # payloadID string
            length, offset = read_varint(data, offset)
            if length is None or offset + length > len(data):
                raise HeaderParseError("invalid payloadID length")
            payload_id = data[offset:offset + length].tobytes().decode("utf-8")
            offset += length
        elif field_number == 4:  # payloadVersion (varint)
            value, offset = read_varint(data, offset)
            if value is None:
                raise HeaderParseError("invalid payloadVersion")
            payload_version = value
        elif field_number == 5:  # payloadLength (varint)
            value, offset = read_varint(data, offset)
            if value is None:
                raise HeaderParseError("invalid payloadLength")
            payload_length = value
        elif field_number == 6:  # payloadCRC (varint)
            value, offset = read_varint(data, offset)
            if value is None:
                raise HeaderParseError("invalid payloadCRC")
            payload_crc = value & 0xFFFFFFFF
        elif field_number == 7:  # nilProperties repeated string
            length, offset = read_varint(data, offset)
            if length is None or offset + length > len(data):
                raise HeaderParseError("invalid nil property entry")
            prop = data[offset:offset + length].tobytes().decode("utf-8")
            nil_properties.append(prop)
            offset += length
        else:
            offset = skip_field(data, offset, wire_type)
            if offset is None:
                raise HeaderParseError(f"unsupported header field {field_number}")

    return JournalHeader(
        entry_type=entry_type,
        payload_uuid=payload_uuid,
        payload_id=payload_id,
        payload_version=payload_version,
        payload_length=payload_length,
        payload_crc=payload_crc,
        nil_properties=nil_properties,
    )


# ---------------------------------------------------------------------------
# Payload decoding helpers
# ---------------------------------------------------------------------------

def _decode_bytes(data: bytes) -> Tuple[Any, str]:
    """Decode raw bytes into a richer Python object when possible."""
    if not data:
        return data, "empty"

    if data.startswith(MAGIC):
        try:
            obj = plistlib.loads(data)
            return obj, "plist"
        except Exception:
            pass

    if data.startswith((b"\x78\x9c", b"\x78\xda")):
        try:
            uncompressed = zlib.decompress(data)
            decoded, kind = _decode_bytes(uncompressed)
            return decoded, f"zlib+{kind}"
        except Exception:
            pass

    return data, "bytes"



def _normalize(obj: Any) -> Any:
    """Convert plistlib structures into JSON-friendly Python objects."""
    if isinstance(obj, dict):
        return {str(key): _normalize(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_normalize(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_normalize(item) for item in obj)
    if hasattr(plistlib, "Data") and isinstance(obj, plistlib.Data):
        return _normalize(obj.data)
    if isinstance(obj, bytes):
        decoded, kind = _decode_bytes(obj)
        if kind != "bytes":
            return _normalize(decoded)
        return {
            "__type__": "bytes",
            "encoding": "base64",
            "data": base64.b64encode(obj).decode("ascii"),
        }
    if isinstance(obj, dt.datetime):
        return obj.isoformat()
    return obj


@dataclass
class JournalRecord:
    index: int
    offset: int
    header_checksum: int
    header: JournalHeader
    crc_matches: bool
    payload_kind: str
    payload: Any
    raw_payload: bytes

    def summary(self, key_limit: int | None = 5) -> str:
        uuid_str = str(self.header.payload_uuid) if self.header.payload_uuid else "-"
        payload_id = self.header.payload_id or "-"
        bits = [
            f"#{self.index}",
            f"offset=0x{self.offset:08x}",
            f"entry={self.header.entry_type}",
            f"ver={self.header.payload_version}",
            f"len={self.header.payload_length}",
            f"crc={'ok' if self.crc_matches else 'FAIL'}",
            f"uuid={uuid_str}",
            f"id={payload_id}",
            f"kind={self.payload_kind}",
        ]
        if self.header.nil_properties:
            bits.append(f"nil={self.header.nil_properties}")
        if key_limit and isinstance(self.payload, dict):
            keys = list(self.payload.keys())[:key_limit]
            bits.append(f"keys={keys}")
        elif key_limit and isinstance(self.payload, list):
            bits.append(f"items={len(self.payload)}")
        return " ".join(bits)

    def to_json_obj(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "offset": self.offset,
            "headerChecksum": self.header_checksum,
            "entryType": self.header.entry_type,
            "payloadVersion": self.header.payload_version,
            "payloadLength": self.header.payload_length,
            "payloadCRC": self.header.payload_crc,
            "crcMatches": self.crc_matches,
            "payloadUUID": str(self.header.payload_uuid) if self.header.payload_uuid else None,
            "payloadID": self.header.payload_id,
            "nilProperties": self.header.nil_properties,
            "payloadKind": self.payload_kind,
            "payload": _normalize(self.payload) if self.payload is not None else None,
        }


# ---------------------------------------------------------------------------
# Record iterator
# ---------------------------------------------------------------------------

def iter_records(path: str | Path, *, decode_payload: bool = True) -> Iterator[JournalRecord]:
    data = memoryview(Path(path).read_bytes())
    offset = 0
    index = 0
    length = len(data)

    while offset + PREFIX_SIZE <= length:
        sentinel = data[offset]
        if sentinel != HEADER_SENTINEL:
            raise RuntimeError(f"unexpected sentinel 0x{sentinel:02x} at offset 0x{offset:x}")

        header_checksum = struct.unpack_from("<I", data, offset + 1)[0]
        header_length = data[offset + 4]
        if header_length == 0 or header_length > HEADER_SIZE_MAX:
            raise RuntimeError(f"invalid header length {header_length} at offset 0x{offset:x}")

        header_start = offset + PREFIX_SIZE
        header_end = header_start + header_length
        if header_end > length:
            raise RuntimeError("truncated header towards end of file")

        header_bytes = data[header_start:header_end].tobytes()
        header = parse_header(header_bytes)

        payload_start = header_end
        payload_end = payload_start + header.payload_length
        if payload_end > length:
            raise RuntimeError("truncated payload towards end of file")

        payload_bytes = data[payload_start:payload_end].tobytes()
        computed_crc = zlib.crc32(payload_bytes) & 0xFFFFFFFF
        crc_matches = (header.payload_length == 0) or (computed_crc == header.payload_crc)

        if decode_payload and payload_bytes:
            decoded, payload_kind = _decode_bytes(payload_bytes)
        else:
            decoded, payload_kind = (payload_bytes, "bytes" if payload_bytes else "empty")

        record = JournalRecord(
            index=index,
            offset=offset,
            header_checksum=header_checksum,
            header=header,
            crc_matches=crc_matches,
            payload_kind=payload_kind,
            payload=decoded,
            raw_payload=payload_bytes,
        )
        yield record

        offset = payload_end
        index += 1

    if offset != length:
        raise RuntimeError(f"trailing {length - offset} bytes at end of file")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Decode Photos PLJ journal files")
    parser.add_argument("path", help="Path to the .plj file")
    parser.add_argument("--limit", type=int, default=None, help="Stop after N records")
    parser.add_argument("--no-payload", action="store_true", help="Do not decode payload contents")
    parser.add_argument("--json", action="store_true", help="Emit one JSON object per record")
    parser.add_argument("--keys", type=int, metavar="N", default=5, help="Show up to N top-level keys in summary mode")

    args = parser.parse_args()

    try:
        iterator = iter_records(args.path, decode_payload=not args.no_payload)
        for record in iterator:
            if args.json:
                print(json.dumps(record.to_json_obj(), ensure_ascii=False))
            else:
                print(record.summary(key_limit=None if args.no_payload else args.keys))
            if args.limit is not None and record.index + 1 >= args.limit:
                break
    except Exception as exc:  # pragma: no cover
        raise SystemExit(f"error: {exc}")


if __name__ == "__main__":
    main()
