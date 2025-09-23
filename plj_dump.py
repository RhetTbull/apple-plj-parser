#!/usr/bin/env python3

"""
PLJ (Plist Journal) File Parser

A comprehensive tool for parsing Apple Photos .plj (plist journal) files
with full binary data decoding support.

Supports:
- JSON output format
- Binary plist decoding (mediaMetadata, photosGraphData)
- UUID decoding (representativeAssets, curatedAssets, assets)
- Command-line options (--head, --tail, --payload-class, --help)
- Dynamic framework loading with fallback

Author: Claude Code
Version: 2.0
"""

import argparse
import base64
import json
import os
import plistlib
import struct
import sys
import uuid
import zlib
from typing import Any, Dict, List, Optional, Tuple, Union

# PyObjC imports with error handling
try:
    from Foundation import (
        NSURL,
        NSUUID,
        NSData,
        NSError,
        NSMutableArray,
        NSPropertyListImmutable,
        NSPropertyListSerialization,
        NSSet,
        NSString,
    )

    import objc

    PYOBJC_AVAILABLE = True
except ImportError:
    print(
        "Warning: PyObjC not available. Framework features will be disabled.",
        file=sys.stderr,
    )
    PYOBJC_AVAILABLE = False


class PLJDumpError(Exception):
    """Custom exception for PLJ parsing errors."""

    pass


class PLJEntry:
    """Represents a single PLJ entry."""

    def __init__(self):
        self.entry_type: int = 0
        self.payload_version: int = 0
        self.payload_length: int = 0
        self.payload_crc: int = 0
        self.header_checksum: int = 0
        self.crc_matches: bool = False
        self.attributes: Dict[str, Any] = {}
        self.nil_properties: List[str] = []
        self.payload_identifier: Optional[str] = None


class FrameworkLoader:
    """Handles dynamic loading of PhotoLibraryServices framework."""

    def __init__(self):
        self.framework_loaded = False
        self.payload_classes = {}

        if PYOBJC_AVAILABLE:
            self._try_load_framework()

    def _try_load_framework(self):
        """Attempt to load PhotoLibraryServices framework."""
        framework_paths = [
            "/System/Library/PrivateFrameworks/PhotoLibraryServices.framework",
            "/Applications/Photos.app/Contents/Frameworks/PhotoLibraryServices.framework",
        ]

        for path in framework_paths:
            try:
                if os.path.exists(path):
                    objc.loadBundle(
                        "PhotoLibraryServices",
                        bundle_path=path,
                        module_globals=globals(),
                    )
                    self.framework_loaded = True
                    print(
                        f"Successfully loaded PhotoLibraryServices from {path}",
                        file=sys.stderr,
                    )
                    break
            except Exception as e:
                continue

        if not self.framework_loaded:
            print(
                "Warning: PhotoLibraryServices framework not available. Payload decoding will be limited.",
                file=sys.stderr,
            )

    def get_payload_class(self, class_name: str):
        """Get a payload class by name."""
        if not self.framework_loaded or not PYOBJC_AVAILABLE:
            return None

        if class_name not in self.payload_classes:
            try:
                self.payload_classes[class_name] = objc.lookUpClass(class_name)
            except objc.nosuchclass_error:
                print(
                    f"Warning: Payload class {class_name} is unavailable (private API not loaded).",
                    file=sys.stderr,
                )
                self.payload_classes[class_name] = None

        return self.payload_classes[class_name]


class PLJParser:
    """Main PLJ file parser with comprehensive binary data decoding."""

    def __init__(self):
        self.framework_loader = FrameworkLoader()
        self.payload_class_map = {
            "Asset": "PLAssetJournalEntryPayload",
            "Album": "PLAlbumJournalEntryPayload",
            "DeferredRebuildFace": "PLDeferredRebuildFaceJournalEntryPayload",
            "DetectedFace": "PLDetectedFaceJournalEntryPayload",
            "FetchingAlbum": "PLFetchingAlbumJournalEntryPayload",
            "FileSystemVolume": "PLFileSystemVolumeJournalEntryPayload",
            "Folder": "PLFolderJournalEntryPayload",
            "ImportSession": "PLImportSessionJournalEntryPayload",
            "Keyword": "PLKeywordJournalEntryPayload",
            "Memory": "PLMemoryJournalEntryPayload",
            "MigrationHistory": "PLMigrationHistoryJournalEntryPayload",
            "Person": "PLPersonJournalEntryPayload",
            "ProjectAlbum": "PLProjectAlbumJournalEntryPayload",
            "SocialGroup": "PLSocialGroupJournalEntryPayload",
        }

    def read_varint(self, data: bytes, offset: int) -> Tuple[Optional[int], int]:
        """Read a protobuf varint from data starting at offset."""
        result = 0
        shift = 0

        while offset < len(data) and shift <= 63:
            b = data[offset]
            offset += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result, offset
            shift += 7

        return None, offset

    def skip_field(self, data: bytes, offset: int, wire_type: int) -> Optional[int]:
        """Skip a protobuf field based on wire type."""
        if wire_type == 0:  # Varint
            _, new_offset = self.read_varint(data, offset)
            return new_offset if _ is not None else None

        elif wire_type == 1:  # 64-bit
            return offset + 8 if offset + 8 <= len(data) else None

        elif wire_type == 2:  # Length-delimited
            length, new_offset = self.read_varint(data, offset)
            if length is None or new_offset + length > len(data):
                return None
            return new_offset + length

        elif wire_type == 5:  # 32-bit
            return offset + 4 if offset + 4 <= len(data) else None

        elif wire_type == 3:  # Start group
            while offset < len(data):
                key, offset = self.read_varint(data, offset)
                if key is None:
                    return None
                wt = key & 0x7
                if wt == 4:  # End group
                    return offset
                offset = self.skip_field(data, offset, wt)
                if offset is None:
                    return None
            return None

        return None

    def parse_header(self, header_data: bytes) -> Dict[str, Any]:
        """Parse protobuf header data."""
        offset = 0
        result = {
            "entry_type": 0,
            "payload_uuid": None,
            "payload_id_string": None,
            "payload_version": 0,
            "payload_length": 0,
            "payload_crc": 0,
            "nil_properties": [],
        }

        while offset < len(header_data):
            key, offset = self.read_varint(header_data, offset)
            if key is None:
                raise PLJDumpError("Failed to read header key")

            field_number = key >> 3
            wire_type = key & 0x7

            if field_number == 1:  # entryType
                if wire_type != 0:
                    offset = self.skip_field(header_data, offset, wire_type)
                    continue
                value, offset = self.read_varint(header_data, offset)
                if value is None:
                    raise PLJDumpError("Failed to read entryType")
                result["entry_type"] = value

            elif field_number == 2:  # payloadUUID
                if wire_type != 2:
                    offset = self.skip_field(header_data, offset, wire_type)
                    continue
                length, offset = self.read_varint(header_data, offset)
                if length is None or offset + length > len(header_data):
                    raise PLJDumpError("Invalid payloadUUID")
                result["payload_uuid"] = header_data[offset : offset + length]
                offset += length

            elif field_number == 3:  # payloadID string
                if wire_type != 2:
                    offset = self.skip_field(header_data, offset, wire_type)
                    continue
                length, offset = self.read_varint(header_data, offset)
                if length is None or offset + length > len(header_data):
                    raise PLJDumpError("Invalid payloadID")
                result["payload_id_string"] = header_data[
                    offset : offset + length
                ].decode("utf-8")
                offset += length

            elif field_number == 4:  # payloadVersion
                if wire_type != 0:
                    offset = self.skip_field(header_data, offset, wire_type)
                    continue
                value, offset = self.read_varint(header_data, offset)
                if value is None:
                    raise PLJDumpError("Failed to read payloadVersion")
                result["payload_version"] = value

            elif field_number == 5:  # payloadLength
                if wire_type != 0:
                    offset = self.skip_field(header_data, offset, wire_type)
                    continue
                value, offset = self.read_varint(header_data, offset)
                if value is None:
                    raise PLJDumpError("Failed to read payloadLength")
                result["payload_length"] = value

            elif field_number == 6:  # payloadCRC
                if wire_type != 0:
                    offset = self.skip_field(header_data, offset, wire_type)
                    continue
                value, offset = self.read_varint(header_data, offset)
                if value is None:
                    raise PLJDumpError("Failed to read payloadCRC")
                result["payload_crc"] = value & 0xFFFFFFFF

            elif field_number == 7:  # nil property name
                if wire_type != 2:
                    offset = self.skip_field(header_data, offset, wire_type)
                    continue
                length, offset = self.read_varint(header_data, offset)
                if length is None or offset + length > len(header_data):
                    raise PLJDumpError("Invalid nil property")
                prop_name = header_data[offset : offset + length].decode("utf-8")
                result["nil_properties"].append(prop_name)
                offset += length

            else:  # Unknown field
                offset = self.skip_field(header_data, offset, wire_type)
                if offset is None:
                    raise PLJDumpError(f"Unsupported field {field_number}")

        return result

    def build_payload_identifier(
        self, uuid_data: Optional[bytes], string_id: Optional[str]
    ):
        """Build a payload identifier using PhotoLibraryServices classes."""
        if not self.framework_loader.framework_loaded or not PYOBJC_AVAILABLE:
            # Fallback: use string representation
            if uuid_data and len(uuid_data) == 16:
                return str(uuid.UUID(bytes=uuid_data))
            elif string_id:
                return string_id
            return None

        try:
            if uuid_data and len(uuid_data) == 16:
                nsuuid = NSUUID.alloc().initWithUUIDBytes_(uuid_data)
                return PLJournalEntryPayloadIDFactory.payloadIDWithUUIDString_(
                    nsuuid.UUIDString()
                )
            elif string_id:
                return PLJournalEntryPayloadIDFactory.payloadIDWithString_(string_id)
        except (NameError, AttributeError):
            # Fallback if classes not available
            if uuid_data and len(uuid_data) == 16:
                return str(uuid.UUID(bytes=uuid_data))
            elif string_id:
                return string_id

        return None

    def decode_binary_plist(self, data: bytes) -> Optional[Any]:
        """Decode binary plist data using Python's plistlib."""
        try:
            return plistlib.loads(data)
        except Exception:
            return None

    def decode_packed_uuids(self, data: bytes) -> Optional[List[str]]:
        """Decode packed UUID data into an array of UUID strings."""
        if len(data) % 16 != 0:
            return None

        uuid_count = len(data) // 16
        uuids = []

        for i in range(uuid_count):
            uuid_bytes = data[i * 16 : (i + 1) * 16]
            try:
                uuid_obj = uuid.UUID(bytes=uuid_bytes)
                uuids.append(str(uuid_obj).upper())
            except ValueError:
                return None

        return uuids

    def convert_to_json_serializable(self, obj: Any) -> Any:
        """Convert objects to JSON-serializable format."""
        if obj is None:
            return None
        elif isinstance(obj, (str, int, float, bool)):
            return obj
        elif isinstance(obj, bytes):
            return base64.b64encode(obj).decode("ascii")
        elif isinstance(obj, (list, tuple)):
            return [self.convert_to_json_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {
                str(k): self.convert_to_json_serializable(v) for k, v in obj.items()
            }
        elif hasattr(obj, "__dict__"):
            return self.convert_to_json_serializable(obj.__dict__)
        else:
            return str(obj)

    def process_binary_fields(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Process binary fields for decoding (mediaMetadata, photosGraphData, UUID fields)."""
        display_attributes = attributes.copy()

        # Debug lines removed for clean output

        # Handle mediaMetadata binary plist decoding
        if "mediaMetadata" in display_attributes:
            media_metadata = display_attributes["mediaMetadata"]
            binary_data = None

            if isinstance(media_metadata, bytes):
                binary_data = media_metadata
            elif hasattr(media_metadata, "bytes") and hasattr(media_metadata, "length"):
                # This is likely an NSData object from PyObjC
                binary_data = bytes(media_metadata)
            elif isinstance(media_metadata, str):
                # PyObjC might convert NSData to string representation like "b'bplist00...'"
                if media_metadata.startswith("b'") and media_metadata.endswith("'"):
                    try:
                        # Remove b' and ' wrapper and decode escape sequences
                        raw_string = media_metadata[2:-1]
                        # Python's literal_eval is safer for parsing string literals
                        import ast

                        binary_data = ast.literal_eval(f"b'{raw_string}'")
                    except Exception:
                        # Fallback: manual parsing of escape sequences
                        try:
                            raw_string = media_metadata[2:-1]
                            binary_data = (
                                raw_string.encode("utf-8")
                                .decode("unicode_escape")
                                .encode("latin1")
                            )
                        except Exception:
                            # Try base64 decoding as fallback
                            try:
                                binary_data = base64.b64decode(media_metadata)
                            except Exception:
                                pass
                else:
                    # Try base64 decoding
                    try:
                        binary_data = base64.b64decode(media_metadata)
                    except Exception:
                        pass

            if binary_data:
                decoded_metadata = self.decode_binary_plist(binary_data)
                if decoded_metadata:
                    display_attributes["mediaMetadata_decoded"] = decoded_metadata
                    display_attributes["mediaMetadata_base64"] = base64.b64encode(
                        binary_data
                    ).decode("ascii")
                    del display_attributes["mediaMetadata"]

        # Handle photosGraphData binary plist decoding
        if "photosGraphData" in display_attributes:
            photos_graph_data = display_attributes["photosGraphData"]
            # Debug line removed
            binary_data = None

            if isinstance(photos_graph_data, bytes):
                binary_data = photos_graph_data
            elif hasattr(photos_graph_data, "bytes") and hasattr(
                photos_graph_data, "length"
            ):
                # This is likely an NSData object from PyObjC
                binary_data = bytes(photos_graph_data)
            # Debug line removed
            elif isinstance(photos_graph_data, str):
                # PyObjC might convert NSData to string representation like "b'bplist00...'"
                if photos_graph_data.startswith("b'") and photos_graph_data.endswith(
                    "'"
                ):
                    try:
                        # Remove b' and ' wrapper and decode escape sequences
                        raw_string = photos_graph_data[2:-1]
                        # Python's literal_eval is safer for parsing string literals
                        import ast

                        binary_data = ast.literal_eval(f"b'{raw_string}'")
                    # Debug line removed
                    except Exception:
                        # Fallback: manual parsing of escape sequences
                        try:
                            raw_string = photos_graph_data[2:-1]
                            binary_data = (
                                raw_string.encode("utf-8")
                                .decode("unicode_escape")
                                .encode("latin1")
                            )
                        except Exception:
                            # Try base64 decoding as fallback
                            try:
                                binary_data = base64.b64decode(photos_graph_data)
                            except Exception:
                                pass
                else:
                    # Try base64 decoding
                    try:
                        binary_data = base64.b64decode(photos_graph_data)
                    except Exception:
                        pass

            if binary_data:
                decoded_graph_data = self.decode_binary_plist(binary_data)
                if decoded_graph_data:
                    display_attributes["photosGraphData_decoded"] = decoded_graph_data
                    display_attributes["photosGraphData_base64"] = base64.b64encode(
                        binary_data
                    ).decode("ascii")
                    del display_attributes["photosGraphData"]

        # Handle UUID fields (representativeAssets, curatedAssets, assets)
        uuid_fields = [
            "representativeAssets",
            "curatedAssets",
            "assets",
            "extendedCuratedAssets",
        ]
        for field_name in uuid_fields:
            if field_name in display_attributes:
                field_data = display_attributes[field_name]
                binary_data = None

                if isinstance(field_data, bytes):
                    binary_data = field_data
                elif hasattr(field_data, "bytes") and hasattr(field_data, "length"):
                    # This is likely an NSData object from PyObjC
                    binary_data = bytes(field_data)
                elif isinstance(field_data, str):
                    # PyObjC might convert NSData to string representation like "b'...'"
                    if field_data.startswith("b'") and field_data.endswith("'"):
                        try:
                            # Remove b' and ' wrapper and decode escape sequences
                            raw_string = field_data[2:-1]
                            # Python's literal_eval is safer for parsing string literals
                            import ast

                            binary_data = ast.literal_eval(f"b'{raw_string}'")
                        except Exception:
                            # Fallback: manual parsing of escape sequences
                            try:
                                raw_string = field_data[2:-1]
                                binary_data = (
                                    raw_string.encode("utf-8")
                                    .decode("unicode_escape")
                                    .encode("latin1")
                                )
                            except Exception:
                                # Try base64 decoding as fallback
                                try:
                                    binary_data = base64.b64decode(field_data)
                                except Exception:
                                    pass
                    else:
                        # Try base64 decoding
                        try:
                            binary_data = base64.b64decode(field_data)
                        except Exception:
                            pass

                if binary_data:
                    decoded_uuids = self.decode_packed_uuids(binary_data)
                    if decoded_uuids:
                        display_attributes[f"{field_name}_decoded"] = decoded_uuids
                        display_attributes[f"{field_name}_base64"] = base64.b64encode(
                            binary_data
                        ).decode("ascii")
                        del display_attributes[field_name]

        return display_attributes

    def get_raw_payload_attributes(self, payload) -> Optional[Dict[str, Any]]:
        """Extract raw payload attributes from a payload object."""
        if not PYOBJC_AVAILABLE or not payload:
            return None

        try:
            if hasattr(payload, "rawPayloadAttributes"):
                attrs = payload.rawPayloadAttributes()
            elif hasattr(payload, "payloadAttributes"):
                attrs = payload.payloadAttributes()
            else:
                return None

            # Convert Foundation objects to Python objects
            if attrs:
                # Simple conversion without special NSData handling for now
                return dict(attrs)
        except Exception:
            pass

        return None

    def infer_payload_class_name(self, file_path: str) -> Optional[str]:
        """Infer payload class name from file path."""
        basename = os.path.basename(file_path)
        stem = os.path.splitext(basename)[0]

        if stem.endswith("-change"):
            stem = stem[:-7]
        elif stem.endswith("-snapshot"):
            stem = stem[:-9]

        return self.payload_class_map.get(stem)

    def parse_file(
        self, file_path: str, payload_class_name: Optional[str] = None
    ) -> List[PLJEntry]:
        """Parse a PLJ file and return list of entries."""
        if not payload_class_name:
            payload_class_name = self.infer_payload_class_name(file_path)

        if not payload_class_name:
            raise PLJDumpError(
                f"Unable to infer payload class for {file_path}. Use --payload-class to specify it explicitly."
            )

        payload_class = self.framework_loader.get_payload_class(payload_class_name)
        entries = []

        try:
            with open(file_path, "rb") as f:
                entry_index = 0

                while True:
                    # Read entry prefix (5 bytes)
                    prefix = f.read(5)
                    if len(prefix) == 0:
                        break  # EOF
                    if len(prefix) < 5:
                        raise PLJDumpError(
                            f"Truncated entry prefix at entry {entry_index}"
                        )

                    # Parse prefix
                    sentinel = prefix[0]
                    if sentinel != 0x40:
                        raise PLJDumpError(
                            f"Unexpected sentinel 0x{sentinel:02x} at entry {entry_index}"
                        )

                    header_checksum = struct.unpack("<I", prefix[1:5])[0]
                    header_length = prefix[4]

                    # Read header
                    header_data = f.read(header_length)
                    if len(header_data) < header_length:
                        raise PLJDumpError(f"Truncated header at entry {entry_index}")

                    # Parse header
                    parsed_header = self.parse_header(header_data)

                    # Read payload
                    payload_length = parsed_header["payload_length"]
                    payload_data = f.read(payload_length) if payload_length > 0 else b""
                    if len(payload_data) < payload_length:
                        raise PLJDumpError(f"Truncated payload at entry {entry_index}")

                    # Verify CRC
                    computed_crc = (
                        zlib.crc32(payload_data) & 0xFFFFFFFF
                        if payload_length > 0
                        else 0
                    )
                    crc_matches = (payload_length == 0) or (
                        computed_crc == parsed_header["payload_crc"]
                    )

                    # Create entry
                    entry = PLJEntry()
                    entry.entry_type = parsed_header["entry_type"]
                    entry.payload_version = parsed_header["payload_version"]
                    entry.payload_length = payload_length
                    entry.payload_crc = parsed_header["payload_crc"]
                    entry.header_checksum = header_checksum
                    entry.crc_matches = crc_matches
                    entry.nil_properties = parsed_header["nil_properties"]

                    # Build payload identifier
                    entry.payload_identifier = self.build_payload_identifier(
                        parsed_header["payload_uuid"],
                        parsed_header["payload_id_string"],
                    )

                    # Try to decode payload
                    if (
                        payload_length > 0
                        and payload_class
                        and self.framework_loader.framework_loaded
                    ):
                        try:
                            nil_props_set = (
                                NSSet.setWithArray_(parsed_header["nil_properties"])
                                if parsed_header["nil_properties"]
                                else None
                            )
                            payload_nsdata = NSData.dataWithBytes_length_(
                                payload_data, len(payload_data)
                            )

                            payload = payload_class.payloadWithData_forPayloadID_version_andNilProperties_error_(
                                payload_nsdata,
                                entry.payload_identifier,
                                parsed_header["payload_version"],
                                nil_props_set,
                                None,
                            )

                            if payload:
                                raw_attributes = self.get_raw_payload_attributes(
                                    payload
                                )
                                if raw_attributes:
                                    # Process binary fields for decoding
                                    entry.attributes = self.process_binary_fields(
                                        raw_attributes
                                    )

                        except Exception as e:
                            # Payload decoding failed, but continue
                            entry.attributes = {
                                "_error": f"Payload decoding failed: {str(e)}"
                            }
                            pass

                    entries.append(entry)
                    entry_index += 1

        except IOError as e:
            raise PLJDumpError(f"Failed to open {file_path}: {e}")

        return entries


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Parse Apple Photos .plj (plist journal) files with comprehensive binary data decoding",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.plj                          # Parse all entries
  %(prog)s example.plj --head 5                 # Show first 5 entries
  %(prog)s example.plj --tail 3                 # Show last 3 entries
  %(prog)s example.plj --payload-class PLAssetJournalEntryPayload  # Explicit class

Supported binary data decoding:
  - mediaMetadata: EXIF and technical metadata (binary plist)
  - photosGraphData: Memory graph data (binary plist)
  - assets/representativeAssets/curatedAssets: Asset UUID lists (packed UUIDs)
""",
    )

    parser.add_argument("file_path", help="Path to .plj file to parse")
    parser.add_argument(
        "--head", type=int, metavar="N", help="Output only the first N entries"
    )
    parser.add_argument(
        "--tail", type=int, metavar="N", help="Output only the last N entries"
    )
    parser.add_argument(
        "--payload-class",
        metavar="CLASS",
        help="Explicit payload class name (auto-detected from filename if not specified)",
    )

    return parser


def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Validate arguments
    if args.head is not None and args.tail is not None:
        print("Error: Cannot specify both --head and --tail", file=sys.stderr)
        return 1

    if args.head is not None and args.head < 1:
        print("Error: --head value must be positive", file=sys.stderr)
        return 1

    if args.tail is not None and args.tail < 1:
        print("Error: --tail value must be positive", file=sys.stderr)
        return 1

    try:
        # Parse the PLJ file
        parser_obj = PLJParser()
        entries = parser_obj.parse_file(args.file_path, args.payload_class)

        # Apply head/tail filtering
        if args.head is not None:
            entries = entries[: args.head]
        elif args.tail is not None:
            entries = entries[-args.tail :]

        # Convert to JSON output
        output_data = {"entries": []}

        for entry in entries:
            entry_data = {
                "entry_type": entry.entry_type,
                "payload_version": entry.payload_version,
                "payload_length": entry.payload_length,
                "payload_crc": f"0x{entry.payload_crc:x}",
                "header_checksum": f"0x{entry.header_checksum:x}",
                "crc_matches": entry.crc_matches,
                "attributes": parser_obj.convert_to_json_serializable(entry.attributes),
            }

            if entry.nil_properties:
                entry_data["nil_properties"] = entry.nil_properties

            if entry.payload_identifier:
                entry_data["payload_identifier"] = str(entry.payload_identifier)

            output_data["entries"].append(entry_data)

        # Output JSON
        print(json.dumps(output_data, indent=2, ensure_ascii=False))

    except PLJDumpError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
