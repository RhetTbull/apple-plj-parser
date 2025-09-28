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
from typing import Any, Iterator, Optional, Tuple

from google.protobuf.message import DecodeError

from pljournal_pb2 import JournalEntryHeader as JournalEntryHeaderPB

MAGIC = b"bplist00"
PREFIX_SIZE = 5
HEADER_SENTINEL = 0x40
HEADER_SIZE_MAX = 255  # header length stored in single byte


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
    header_pb = JournalEntryHeaderPB()
    try:
        header_pb.ParseFromString(raw)
    except DecodeError as exc:  # pragma: no cover - corrupted headers are rare
        raise HeaderParseError(str(exc)) from exc

    payload_uuid = None
    if header_pb.HasField("payload_uuid") and len(header_pb.payload_uuid) == 16:
        payload_uuid = uuid.UUID(bytes=header_pb.payload_uuid)

    payload_id = header_pb.payload_id if header_pb.HasField("payload_id") else None

    return JournalHeader(
        entry_type=header_pb.entry_type if header_pb.HasField("entry_type") else 0,
        payload_uuid=payload_uuid,
        payload_id=payload_id,
        payload_version=(
            header_pb.payload_version if header_pb.HasField("payload_version") else 0
        ),
        payload_length=(
            header_pb.payload_length if header_pb.HasField("payload_length") else 0
        ),
        payload_crc=header_pb.payload_crc if header_pb.HasField("payload_crc") else 0,
        nil_properties=list(header_pb.nil_properties),
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
            "payloadUUID": (
                str(self.header.payload_uuid) if self.header.payload_uuid else None
            ),
            "payloadID": self.header.payload_id,
            "nilProperties": self.header.nil_properties,
            "payloadKind": self.payload_kind,
            "payload": _normalize(self.payload) if self.payload is not None else None,
        }


# ---------------------------------------------------------------------------
# Record iterator
# ---------------------------------------------------------------------------


def iter_records(
    path: str | Path, *, decode_payload: bool = True
) -> Iterator[JournalRecord]:
    data = memoryview(Path(path).read_bytes())
    offset = 0
    index = 0
    length = len(data)

    while offset + PREFIX_SIZE <= length:
        sentinel = data[offset]
        if sentinel != HEADER_SENTINEL:
            raise RuntimeError(
                f"unexpected sentinel 0x{sentinel:02x} at offset 0x{offset:x}"
            )

        header_checksum = struct.unpack_from("<I", data, offset + 1)[0]
        header_length = data[offset + 4]
        if header_length == 0 or header_length > HEADER_SIZE_MAX:
            raise RuntimeError(
                f"invalid header length {header_length} at offset 0x{offset:x}"
            )

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
        crc_matches = (header.payload_length == 0) or (
            computed_crc == header.payload_crc
        )

        if decode_payload and payload_bytes:
            decoded, payload_kind = _decode_bytes(payload_bytes)
        else:
            decoded, payload_kind = (
                payload_bytes,
                "bytes" if payload_bytes else "empty",
            )

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
    parser.add_argument(
        "--no-payload", action="store_true", help="Do not decode payload contents"
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit one JSON object per record"
    )
    parser.add_argument(
        "--keys",
        type=int,
        metavar="N",
        default=5,
        help="Show up to N top-level keys in summary mode",
    )

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
