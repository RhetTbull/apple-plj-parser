#!/usr/bin/env python3
"""
PLJ Reader - Parse .plj files and extract binary plists

A .plj file contains a header of indeterminate length followed by one or more
serialized binary plist files. Each binary plist begins with the magic bytes
'bplist00' (hex: 62 70 6C 69 73 74 30 30).
"""

from typing import Generator, BinaryIO
import plistlib
import struct
from bpylist2 import archiver

BPLIST_MAGIC = b'bplist00'


def read_plj_file(file_path: str) -> Generator[bytes, None, None]:
    """
    Read a .plj file and yield each binary plist as bytes.

    Args:
        file_path: Path to the .plj file to read

    Yields:
        bytes: Each binary plist found in the file
    """
    with open(file_path, 'rb') as f:
        yield from parse_plj_stream(f)


def parse_plj_stream(stream: BinaryIO) -> Generator[bytes, None, None]:
    """
    Parse a binary stream and yield each binary plist found.

    Args:
        stream: Binary stream to read from

    Yields:
        bytes: Each binary plist found in the stream
    """
    # Read the entire file into memory for simplicity
    # For very large files, this could be optimized to read in chunks
    data = stream.read()

    # Pattern observed: plists end with bytes 4f 11 02 de followed by next bplist00
    END_PATTERN = b'\x4f\x11\x02\xde'

    # Find all occurrences of the bplist magic bytes
    offset = 0
    while True:
        # Find the next bplist magic bytes
        magic_pos = data.find(BPLIST_MAGIC, offset)
        if magic_pos == -1:
            break

        # Find the end pattern that precedes the next bplist
        search_start = magic_pos + len(BPLIST_MAGIC)
        next_magic_pos = data.find(BPLIST_MAGIC, search_start)

        if next_magic_pos == -1:
            # This is the last plist - take everything to end of file
            plist_data = data[magic_pos:]
            yield plist_data
            break
        else:
            # take everything to the next magic position
            plist_data = data[magic_pos:next_magic_pos]
            offset = magic_pos + len(BPLIST_MAGIC)
            yield plist_data




def parse_plist(plist_data):
    # Parse the plist data using plistlib
    try:
        plist = plistlib.loads(plist_data, fmt=plistlib.FMT_BINARY)
    except Exception as e:
        print(f"Failed to parse plist data using plistlib: {e}")
        try:
            plist = archiver.unarchive(plist_data)
        except Exception as e:
            raise ValueError(f"Failed to parse plist data: {e}")
    return plist


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python pljreader.py <file.plj>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        plist_count = 0
        for plist_data in read_plj_file(file_path):
            plist_count += 1
            print(f"Found binary plist #{plist_count}, size: {len(plist_data)} bytes")
            pldata =parse_plist(plist_data)
            print(f"{plist_data=}")
        print(f"\nTotal binary plists found: {plist_count}")
        print(f"\nNote: The binary plists in PLJ format may not be standard plistlib-compatible")
        print("They appear to be embedded in a custom format and may require additional processing.")

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
