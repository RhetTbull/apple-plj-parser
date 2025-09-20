#!/usr/bin/env python3
"""Command-line helper to iterate over records in a .plj container."""
from __future__ import annotations

import argparse
import plistlib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional, Any

MAGIC = b"bplist00"
HEADER_SIZE = 37
MAX_OBJECTS = 5_000_000


@dataclass
class PLJRecord:
    """Single record extracted from a PLJ file."""
    index: int
    offset: int
    uuid_a: uuid.UUID
    uuid_b: uuid.UUID
    attr: int
    record_type: int
    missing_prefix: int
    payload_length: int
    payload_bytes: bytes
    plist: Optional[Any]


def _combined_slice(data: memoryview, payload_start: int, missing_len: int, start: int, length: int) -> Optional[bytes]:
    """Return `length` bytes from the logical plist stream starting at `start`."""
    buf = bytearray(length)
    for i in range(length):
        idx = start + i
        if idx < missing_len:
            buf[i] = MAGIC[idx]
        else:
            real_idx = payload_start + (idx - missing_len)
            if real_idx >= len(data):
                return None
            buf[i] = data[real_idx]
    return bytes(buf)


def _find_plist_length(data: memoryview, payload_start: int, missing_len: int) -> Optional[int]:
    """Locate the plist trailer and return the total logical length including prefix."""
    available = len(data) - payload_start + missing_len
    limit = available - 32
    if limit <= 8:
        return None
    for pos in range(8, limit + 1):
        tail = _combined_slice(data, payload_start, missing_len, pos, 32)
        if tail is None:
            return None
        offset_size = tail[6]
        ref_size = tail[7]
        if not (1 <= offset_size <= 8 and 1 <= ref_size <= 8):
            continue
        num_objects = int.from_bytes(tail[8:16], "big")
        if not (0 < num_objects < MAX_OBJECTS):
            continue
        top_object = int.from_bytes(tail[16:24], "big")
        if top_object >= num_objects:
            continue
        table_offset = int.from_bytes(tail[24:32], "big")
        if table_offset < 8:
            continue
        table_end = table_offset + num_objects * offset_size
        if table_end != pos:
            continue
        if table_end > available:
            continue
        return pos + 32
    return None


def _detect_missing_prefix(data: memoryview, magic_pos: int) -> Optional[int]:
    """Determine how many leading bytes of MAGIC were trimmed before the payload."""
    for missing_len in range(len(MAGIC) + 1):
        suffix = MAGIC[missing_len:]
        end = magic_pos + len(suffix)
        if end > len(data):
            continue
        if data[magic_pos:end].tobytes() == suffix:
            return missing_len
    return None


def iter_records(path: str | Path, *, decode_plist: bool = True) -> Iterator[PLJRecord]:
    """Yield PLJ records in order."""
    blob = Path(path).read_bytes()
    data = memoryview(blob)
    offset = 0
    index = 0
    while offset + HEADER_SIZE <= len(data):
        header = data[offset:offset + HEADER_SIZE]
        uuid_a = uuid.UUID(bytes=header[:16].tobytes())
        uuid_b = uuid.UUID(bytes=header[16:32].tobytes())
        attr = int.from_bytes(header[32:36], "big")
        record_type = header[36]

        magic_pos = offset + HEADER_SIZE
        missing_len = _detect_missing_prefix(data, magic_pos)
        if missing_len is None:
            raise ValueError(f"Unable to locate plist magic near offset {offset}")
        payload_start = magic_pos + missing_len
        if payload_start > len(data):
            raise ValueError(f"Payload offset beyond end of file at record {index}")

        logical_length = _find_plist_length(data, payload_start, missing_len)
        if logical_length is None:
            raise ValueError(f"Unable to determine plist length for record at offset {offset}")
        payload_length = logical_length - missing_len
        payload_end = payload_start + payload_length
        if payload_end > len(data):
            raise ValueError(f"Truncated payload for record at offset {offset}")

        payload = MAGIC[:missing_len] + data[payload_start:payload_end].tobytes()
        plist_obj = plistlib.loads(payload) if decode_plist else None

        yield PLJRecord(
            index=index,
            offset=offset,
            uuid_a=uuid_a,
            uuid_b=uuid_b,
            attr=attr,
            record_type=record_type,
            missing_prefix=missing_len,
            payload_length=payload_length,
            payload_bytes=payload,
            plist=plist_obj,
        )
        index += 1
        offset = payload_end


def _summarise(record: PLJRecord, *, key_limit: int | None) -> str:
    parts = [
        f"#{record.index} offset=0x{record.offset:08x}",
        f"type={record.record_type}",
        f"missing={record.missing_prefix}",
        f"len={record.payload_length}",
        f"attr=0x{record.attr:08x}",
        f"uuid_a={record.uuid_a}",
        f"uuid_b={record.uuid_b}",
    ]
    if record.plist is not None and key_limit:
        keys = list(record.plist.keys())[:key_limit]
        parts.append(f"keys={keys}")
    return " " + " | ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Iterate over PLJ records and display summaries.")
    parser.add_argument("path", help="Path to the .plj file")
    parser.add_argument("--limit", type=int, default=None, help="Stop after N records")
    parser.add_argument("--no-decode", action="store_true", help="Skip plist parsing; faster, but keys unavailable")
    parser.add_argument("--keys", type=int, metavar="N", default=5, help="Show up to N top-level plist keys (default: 5)")
    args = parser.parse_args()

    try:
        for record in iter_records(args.path, decode_plist=not args.no_decode):
            print(_summarise(record, key_limit=None if args.no_decode else args.keys))
            if args.limit is not None and record.index + 1 >= args.limit:
                break
    except Exception as exc:  # pragma: no cover
        raise SystemExit(f"error: {exc}")


if __name__ == "__main__":
    main()
