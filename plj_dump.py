#!/usr/bin/env python3

import sys
import zlib
import struct
from typing import Optional, Tuple, List, Dict, Any
import objc
from Foundation import NSData, NSString, NSURL, NSError, NSSet, NSMutableArray, NSUUID

# Load PhotoLibraryServices framework
try:
    framework_path = "/System/Library/PrivateFrameworks/PhotoLibraryServices.framework"
    objc.loadBundle("PhotoLibraryServices", bundle_path=framework_path, module_globals=globals())
except:
    print("Warning: Could not load PhotoLibraryServices framework", file=sys.stderr)


def read_varint(data: bytes, offset: int) -> Tuple[Optional[int], int]:
    """
    Read a varint from bytes starting at offset.
    Returns (value, new_offset) or (None, offset) on error.
    """
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


def skip_field(data: bytes, offset: int, wire_type: int) -> Optional[int]:
    """
    Skip a protobuf field based on wire type.
    Returns new offset or None on error.
    """
    if wire_type == 0:  # Varint
        _, new_offset = read_varint(data, offset)
        return new_offset if _ is not None else None

    elif wire_type == 1:  # 64-bit
        if offset + 8 > len(data):
            return None
        return offset + 8

    elif wire_type == 2:  # Length-delimited
        length, new_offset = read_varint(data, offset)
        if length is None or new_offset + length > len(data):
            return None
        return new_offset + length

    elif wire_type == 5:  # 32-bit
        if offset + 4 > len(data):
            return None
        return offset + 4

    elif wire_type == 3:  # Start group
        # Skip group recursively until matching end-group (wire type 4)
        while offset < len(data):
            key, offset = read_varint(data, offset)
            if key is None:
                return None
            wt = key & 0x7
            if wt == 4:  # End group
                return offset
            offset = skip_field(data, offset, wt)
            if offset is None:
                return None
        return None

    else:
        return None


def get_payload_class_map() -> Dict[str, str]:
    """Return mapping of entity names to payload class names."""
    return {
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
        "SocialGroup": "PLSocialGroupJournalEntryPayload"
    }


def default_payload_class_name_for_url(url: str) -> Optional[str]:
    """Infer payload class name from file URL."""
    import os
    stem = os.path.splitext(os.path.basename(url))[0]

    if stem.endswith("-change"):
        stem = stem[:-7]
    elif stem.endswith("-snapshot"):
        stem = stem[:-9]

    return get_payload_class_map().get(stem)


def parse_header(header_data: bytes) -> Tuple[bool, Dict[str, Any]]:
    """
    Parse protobuf header data.
    Returns (success, parsed_data_dict).
    """
    offset = 0
    result = {
        'entry_type': 0,
        'payload_uuid': None,
        'payload_id_string': None,
        'payload_version': 0,
        'payload_length': 0,
        'payload_crc': 0,
        'nil_properties': []
    }

    while offset < len(header_data):
        key, offset = read_varint(header_data, offset)
        if key is None:
            return False, {"error": "Failed to read header key"}

        field_number = key >> 3
        wire_type = key & 0x7

        if field_number == 1:  # entryType
            if wire_type != 0:
                offset = skip_field(header_data, offset, wire_type)
                if offset is None:
                    return False, {"error": "Failed to skip entryType field"}
                continue

            value, offset = read_varint(header_data, offset)
            if value is None:
                return False, {"error": "Failed to read entryType"}
            result['entry_type'] = value

        elif field_number == 2:  # payloadUUID
            if wire_type != 2:
                offset = skip_field(header_data, offset, wire_type)
                if offset is None:
                    return False, {"error": "Failed to skip payloadUUID field"}
                continue

            length, offset = read_varint(header_data, offset)
            if length is None or offset + length > len(header_data):
                return False, {"error": "Invalid payloadUUID"}

            result['payload_uuid'] = header_data[offset:offset + length]
            offset += length

        elif field_number == 3:  # payloadID string
            if wire_type != 2:
                offset = skip_field(header_data, offset, wire_type)
                if offset is None:
                    return False, {"error": "Failed to skip payloadID field"}
                continue

            length, offset = read_varint(header_data, offset)
            if length is None or offset + length > len(header_data):
                return False, {"error": "Invalid payloadID"}

            result['payload_id_string'] = header_data[offset:offset + length].decode('utf-8')
            offset += length

        elif field_number == 4:  # payloadVersion
            if wire_type != 0:
                offset = skip_field(header_data, offset, wire_type)
                if offset is None:
                    return False, {"error": "Failed to skip payloadVersion field"}
                continue

            value, offset = read_varint(header_data, offset)
            if value is None:
                return False, {"error": "Failed to read payloadVersion"}
            result['payload_version'] = value

        elif field_number == 5:  # payloadLength
            if wire_type != 0:
                offset = skip_field(header_data, offset, wire_type)
                if offset is None:
                    return False, {"error": "Failed to skip payloadLength field"}
                continue

            value, offset = read_varint(header_data, offset)
            if value is None:
                return False, {"error": "Failed to read payloadLength"}
            result['payload_length'] = value

        elif field_number == 6:  # payloadCRC
            if wire_type != 0:
                offset = skip_field(header_data, offset, wire_type)
                if offset is None:
                    return False, {"error": "Failed to skip payloadCRC field"}
                continue

            value, offset = read_varint(header_data, offset)
            if value is None:
                return False, {"error": "Failed to read payloadCRC"}
            result['payload_crc'] = value & 0xFFFFFFFF

        elif field_number == 7:  # nil property name
            if wire_type != 2:
                offset = skip_field(header_data, offset, wire_type)
                if offset is None:
                    return False, {"error": "Failed to skip nil property field"}
                continue

            length, offset = read_varint(header_data, offset)
            if length is None or offset + length > len(header_data):
                return False, {"error": "Invalid nil property"}

            prop_name = header_data[offset:offset + length].decode('utf-8')
            result['nil_properties'].append(prop_name)
            offset += length

        else:  # Unknown field
            offset = skip_field(header_data, offset, wire_type)
            if offset is None:
                return False, {"error": f"Unsupported field {field_number}"}

    return True, result


def build_payload_identifier(uuid_data: Optional[bytes], string_id: Optional[str]):
    """Build a payload identifier using PhotoLibraryServices classes."""
    try:
        if uuid_data and len(uuid_data) == 16:
            # Convert bytes to NSUUID
            uuid_nsdata = NSData.dataWithBytes_length_(uuid_data, len(uuid_data))
            nsuuid = NSUUID.alloc().initWithUUIDBytes_(uuid_data)
            return PLJournalEntryPayloadIDFactory.payloadIDWithUUIDString_(nsuuid.UUIDString())
        elif string_id:
            return PLJournalEntryPayloadIDFactory.payloadIDWithString_(string_id)
    except NameError:
        # PhotoLibraryServices not available
        pass

    return None


def get_raw_payload_attributes(payload):
    """Extract raw payload attributes from a payload object."""
    try:
        if hasattr(payload, 'rawPayloadAttributes'):
            return payload.rawPayloadAttributes()
        elif hasattr(payload, 'payloadAttributes'):
            return payload.payloadAttributes()
    except:
        pass
    return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path to .plj> [PayloadClassName]", file=sys.stderr)
        return 1

    file_path = sys.argv[1]

    if len(sys.argv) >= 3:
        class_name = sys.argv[2]
    else:
        class_name = default_payload_class_name_for_url(file_path)

    if not class_name:
        print(f"Unable to infer payload class for {file_path}. Provide it explicitly.", file=sys.stderr)
        return 1

    # Try to get the payload class
    payload_class = None
    try:
        payload_class = objc.lookUpClass(class_name)
    except objc.nosuchclass_error:
        print(f"Payload class {class_name} is unavailable.", file=sys.stderr)
        return 1

    try:
        with open(file_path, 'rb') as f:
            entry_index = 0

            while True:
                # Read entry prefix (5 bytes)
                prefix = f.read(5)
                if len(prefix) == 0:
                    break  # EOF
                if len(prefix) < 5:
                    print(f"Truncated entry prefix at entry {entry_index}", file=sys.stderr)
                    break

                # Parse prefix
                sentinel, checksum_bytes = prefix[0], prefix[1:5]
                if sentinel != 0x40:
                    print(f"Unexpected sentinel 0x{sentinel:02x} at entry {entry_index}", file=sys.stderr)
                    break

                header_checksum = struct.unpack('<I', checksum_bytes)[0]
                header_length = prefix[4]

                # Read header
                header_data = f.read(header_length)
                if len(header_data) < header_length:
                    print(f"Truncated header at entry {entry_index}", file=sys.stderr)
                    break

                # Parse header
                success, parsed = parse_header(header_data)
                if not success:
                    print(f"Failed to parse header for entry {entry_index}: {parsed.get('error', 'Unknown error')}", file=sys.stderr)
                    break

                # Read payload
                payload_length = parsed['payload_length']
                payload_data = f.read(payload_length)
                if len(payload_data) < payload_length:
                    print(f"Truncated payload at entry {entry_index}", file=sys.stderr)
                    break

                # Verify CRC
                computed_crc = zlib.crc32(payload_data) & 0xFFFFFFFF
                crc_matches = (payload_length == 0) or (computed_crc == parsed['payload_crc'])

                # Build payload identifier and try to decode payload
                payload_identifier = build_payload_identifier(parsed['payload_uuid'], parsed['payload_id_string'])

                payload = None
                payload_error = None

                if payload_length > 0 and payload_identifier and payload_class:
                    try:
                        nil_props_set = NSSet.setWithArray_(parsed['nil_properties']) if parsed['nil_properties'] else None
                        payload_nsdata = NSData.dataWithBytes_length_(payload_data, len(payload_data))

                        payload = payload_class.payloadWithData_forPayloadID_version_andNilProperties_error_(
                            payload_nsdata,
                            payload_identifier,
                            parsed['payload_version'],
                            nil_props_set,
                            None
                        )
                    except Exception as e:
                        payload_error = str(e)

                # Output entry information
                print(f"Entry {entry_index} -- type:{parsed['entry_type']} version:{parsed['payload_version']} "
                      f"payloadLength:{payload_length} crc:{parsed['payload_crc']:#x} checksum:{header_checksum:#x} "
                      f"matches:{'YES' if crc_matches else 'NO'}")

                if parsed['nil_properties']:
                    print(f"  nilProperties: {parsed['nil_properties']}")

                if payload_error:
                    print(f"  payload decode error: {payload_error}")
                elif payload:
                    attributes = get_raw_payload_attributes(payload)
                    if attributes:
                        print(f"  attributes: {attributes}")
                    else:
                        print(f"  payload: {payload}")

                entry_index += 1

    except IOError as e:
        print(f"Failed to open {file_path}: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())