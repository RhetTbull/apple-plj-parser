file example_data/Album-change.plj
example_data/Album-change.plj: data

hexdump -C example_data/Album-change.plj | head
00000000  40 b8 6c 00 1f 08 00 12  10 48 3d 65 10 bd 05 42  |@.l......H=e...B|
00000010  b3 b5 28 09 66 94 c9 c0  75 20 01 28 fc 02 30 f1  |..(.f...u .(..0.|
00000020  8f c5 a9 04 62 70 6c 69  73 74 30 30 dc 01 02 03  |....bplist00....|
00000030  04 05 06 07 08 09 0a 0b  0c 0d 0e 0f 10 11 12 13  |................|
00000040  14 15 12 16 17 5f 10 13  63 75 73 74 6f 6d 53 6f  |....._..customSo|
00000050  72 74 41 73 63 65 6e 64  69 6e 67 5f 10 1a 69 6d  |rtAscending_..im|
00000060  70 6f 72 74 65 64 42 79  42 75 6e 64 6c 65 49 64  |portedByBundleId|
00000070  65 6e 74 69 66 69 65 72  56 61 73 73 65 74 73 5f  |entifierVassets_|
00000080  10 10 6c 61 73 74 4d 6f  64 69 66 69 65 64 44 61  |..lastModifiedDa|
00000090  74 65 59 63 6c 6f 75 64  47 55 49 44 59 70 72 6f  |teYcloudGUIDYpro|

Searched headers for Journal

`OS18-Runtime-Headers/PrivateFrameworks/PhotoLibraryServices.framework`

`PLJournalEntryHeader.h`

```objc
This contains a hint at the header:
@interface PLJournalEntryHeader : PBCodable <NSCopying> {
    int  _entryType;
    struct {
        unsigned int payloadLength : 1;
        unsigned int entryType : 1;
        unsigned int payloadCRC : 1;
        unsigned int payloadVersion : 1;
    }  _has;
    NSMutableArray * _nilProperties;
    unsigned int  _payloadCRC;
    NSString * _payloadID;
    unsigned long long  _payloadLength;
    NSData * _payloadUUID;
    unsigned int  _payloadVersion;
}
```

Hmmm.. what is PBCodable?  Could it a protocol buffer?

A little searching through private frameworks finds this: ProtocolBuffer.framework/PBCodable.h

So now we know that PBCodable is a protocol buffer, and we can use it to decode the data in the header.

Use [protoscope](https://github.com/protocolbuffers/protoscope)

Turning this into a protocol buffer spec:

```
message JournalEntryHeader {
  optional uint64 entry_type = 1;
  optional bytes payload_uuid = 2;
  optional string payload_id = 3;
  optional uint64 payload_version = 4;
  optional uint64 payload_length = 5;
  optional uint32 payload_crc = 6;
  repeated string nil_properties = 7;
}
```

```
$ protoscope -explicit-wire-types -all-fields-are-messages example_data/Asset-snapshot.plj | head
8:VARINT 15024
0:VARINT 32
1:VARINT 0
2:LEN {`c721de0280524b4f9187f10fae92b33b`}
4:VARINT 300
5:VARINT 3273
6:VARINT 1667790900
12:LEN {
  13:EGROUP
  13:I64 2.634414439881681e-302   # 0x15210df30307473i64
```

For album assets, curatedAssets, and representativeAssets, these were binary data with no indication what they were. I looked at albums and noticed the length was always 16 bytes * number of assets. They are packed UUIDs into a single NSData object.


```bash
xcrun clang -fobjc-arc -ObjC \
    -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
    -framework Foundation -lz \
    objc/plj_dump.m -o objc/plj_dump
```
