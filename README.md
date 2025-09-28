# PList Journal (plj) File Description

This project contains a description of `.plj` files (plist journal files) that are created by Apple Photos. It also contains implementations of utilities for reading these files in both Objective-C and python.

## What are .plj files?

Apple Photos creates `.plj` files in `Photos Library.photoslibrary/resources/journals`. These appear to contain all the data required to rebuild the Apple Photos database. Apple Photos stores data about the assets in the library in `Photos Library.photoslibrary/database/Photos.sqlite`. As indicated by the file extension, this is a sqlite database. For a Photos library with many thousands of images, the databse can be quite large; for my personal library of about 40,000 assets, the `Photos.sqlite` is 1.4GB. A large file that changes frequently doesn't work well with Apple's Time Machine backup scheme which backs up all changed files hourly. Backing up the entire sqlite database regularly could quickly fill the backup volume. Apple appears to have created plist journal files to enable more efficient backup of the Photos library. The journal files were first introduced in macOS 10.15. Since the journal files were introduced, Time Machine no longer backs up the `Photos.sqlite` file but instead backs up the plist journals.

Backup up only the plist journal files is more efficient because incremental changes are stored to a small journal file (for example, `Asset-change.plj` which is periodically consolidated into a snapshot file (`Asset-snapshot.plj`). The small changes file doesn't take a lot of space on the backup volume. For example, on my Macbook, as of September 2025, the snapshot was created in April 2025:

```
.rw-r--r-- user staff  20 MB Thu Sep 25 18:40:18 2025 Asset-change.plj
.rw-r--r-- user staff 196 MB Sat Apr  5 05:59:53 2025 Asset-snapshot.plj
```

The full contents of the `journals` folder in a Photos library looks like this:

```
.rw-r--r-- user staff  42 KB Wed Sep 24 07:20:41 2025 Album-change.plj
.rw-r--r-- user staff 772 KB Sun Jun  8 08:29:26 2025 Album-snapshot.plj
.rw-r--r-- user staff 526 B  Wed Sep 24 07:20:41 2025 Album.plist
.rw-r--r-- user staff  20 MB Thu Sep 25 18:40:18 2025 Asset-change.plj
.rw-r--r-- user staff 196 MB Sat Apr  5 05:59:53 2025 Asset-snapshot.plj
.rw-r--r-- user staff 532 B  Thu Sep 25 18:40:18 2025 Asset.plist
.rw-r--r-- user staff   0 B  Fri Apr  4 16:44:53 2025 DeferredRebuildFace-change.plj
.rw-r--r-- user staff 361 B  Fri Apr  4 16:44:59 2025 DeferredRebuildFace.plist
.rw-r--r-- user staff 4.2 KB Sat Sep 20 10:47:45 2025 DetectedFace-change.plj
.rw-r--r-- user staff  36 KB Sat Aug 16 01:01:04 2025 DetectedFace-snapshot.plj
.rw-r--r-- user staff 526 B  Sat Sep 20 10:47:45 2025 DetectedFace.plist
.rw-r--r-- user staff 936 B  Tue Sep 23 11:00:27 2025 FetchingAlbum-change.plj
.rw-r--r-- user staff 8.2 KB Sat Apr  5 05:59:24 2025 FetchingAlbum-snapshot.plj
.rw-r--r-- user staff 526 B  Tue Sep 23 11:00:27 2025 FetchingAlbum.plist
.rw-r--r-- user staff   0 B  Fri Apr  4 16:45:00 2025 FileSystemVolume-change.plj
.rw-r--r-- user staff 361 B  Fri Apr  4 16:45:00 2025 FileSystemVolume.plist
.rw-r--r-- user staff  15 KB Wed Sep 24 07:20:41 2025 Folder-change.plj
.rw-r--r-- user staff  11 KB Sun Sep 14 07:36:15 2025 Folder-snapshot.plj
.rw-r--r-- user staff 526 B  Wed Sep 24 07:20:41 2025 Folder.plist
.rw-r--r-- user staff 555 B  Thu Sep 25 18:46:34 2025 HistoryToken.plist
.rw-r--r-- user staff 2.0 KB Sun Aug 17 16:52:16 2025 ImportSession-change.plj
.rw-r--r-- user staff 435 KB Sat Apr  5 05:59:25 2025 ImportSession-snapshot.plj
.rw-r--r-- user staff 526 B  Sun Aug 17 16:52:16 2025 ImportSession.plist
.rw-r--r-- user staff 2.2 KB Wed Sep 24 05:45:06 2025 Keyword-change.plj
.rw-r--r-- user staff 4.6 KB Sat Apr  5 05:59:24 2025 Keyword-snapshot.plj
.rw-r--r-- user staff 526 B  Wed Sep 24 05:45:06 2025 Keyword.plist
.rw-r--r-- user staff 679 KB Tue Sep 23 04:17:12 2025 Memory-change.plj
.rw-r--r-- user staff 5.5 MB Sat Apr  5 05:59:24 2025 Memory-snapshot.plj
.rw-r--r-- user staff 526 B  Tue Sep 23 04:17:12 2025 Memory.plist
.rw-r--r-- user staff 5.2 KB Fri Aug  8 13:04:24 2025 MigrationHistory-change.plj
.rw-r--r-- user staff 244 B  Fri Aug  8 13:04:24 2025 MigrationHistory.plist
.rw-r--r-- user staff 2.4 KB Sat Sep 20 10:47:45 2025 Person-change.plj
.rw-r--r-- user staff  41 KB Sat Aug 16 01:01:04 2025 Person-snapshot.plj
.rw-r--r-- user staff 526 B  Sat Sep 20 10:47:45 2025 Person.plist
.rw-r--r-- user staff  35 B  Sun Sep  7 22:06:00 2025 ProjectAlbum-change.plj
.rw-r--r-- user staff 4.7 KB Mon Aug 11 17:35:06 2025 ProjectAlbum-snapshot.plj
.rw-r--r-- user staff 526 B  Sun Sep  7 22:06:00 2025 ProjectAlbum.plist
.rw-r--r-- user staff   0 B  Sat Sep 20 10:39:39 2025 SocialGroup-snapshot.plj
.rw-r--r-- user staff 526 B  Sat Sep 20 10:39:39 2025 SocialGroup.plist
```

There are 3 files for each type of entity in the Photos database (for example, Assets, Albums, etc.): a `-snapshot.plj` file, `-change.plj` file, and a `.plist` file. The `.plist` file contains the following information which shows the date of the snapshot and the date data was coalesced, presumably from the `-change.plj` file.

```
$ plutil -p Asset.plist
{
  "coalesceDate" => 2025-04-05 10:59:55 +0000
  "coalescePayloadVersion" => 300
  "currentPayloadVersion" => 300
  "snapshotChecksum" => ""
  "snapshotDate" => 2025-04-04 21:45:00 +0000
  "snapshotPayloadVersion" => 300
}
```

Interestingly, the total size of the journal files is much less than the sqlite database though the journals appear to contain enough data to rebuild the database:

```
$ du -ch resources/journals
224M	resources/journals
224M	total

$ du -ch database/Photos.*
1.4G	database/Photos.sqlite
 64K	database/Photos.sqlite-shm
3.0M	database/Photos.sqlite-wal
4.0K	database/Photos.sqlite.lock
1.4G	total
```

If you delete the Photos.sqlite database from a Photos library then open it, Photos will display an error indicating that the library cannot be opened. However, if you repair the library by holding down Option+Command while opening Photos, the database will be rebuilt from the journal files.

## Contents of .plj files

I wanted to be able to read the contents of the `.plj` files. There is no public documentation of these files so I turned to reverse engineering. After spending a few hours reverse engineering the files, I've determined the format consists of a proprietary header, followed by a protobuf header, then a binary plist (bplist) payload.

- Magic Byte: 0x40
- Unknown: 3 bytes <-- I've not yet determined what these bytes represent
- Protobuf Message Length: 1 byte
- Protobuf Message: variable length containing metadata
- Payload Data: variable length bplist

The protobuf message schema is:

```proto
syntax = "proto2";

package plj;

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

The protobuf message schema can be found in [pljournal.proto](proto/pljournal.proto)

These can be read with the script [plj_dump.py](python/plj_dump.py):

```
$ python plj_dump.py ~/Pictures/Photos\ Library.photoslibrary/resources/journals/Keyword-snapshot.plj
{
  "entries": [
  ...
    {
      "entry_type": 0,
      "payload_version": 1,
      "payload_length": 59,
      "payload_crc": "0xe986ddb9",
      "header_checksum": "0x1e003f65",
      "crc_matches": true,
      "attributes": {
        "title": "1 Star"
      },
      "payload_identifier": "3C7F6FFE-3954-45F0-86D6-B32C61D9C2B6"
    }
  ]
}
```

There is also an Objective-C implementation [plj_dump.m](objc/plj_dump.m).

## Building and running the tools

### Python tools

I use [uv](https://docs.astral.sh/uv/) for building and running the python tools.

Create a virtual environment and activate it:
```bash
uv venv
source .venv/bin/activate
```

Install the required dependencies:

```bash
uv pip install -r pyproject.toml --extra dev
```

To use the python version of the tool, run the following command to first build the python code that implements the protobuf spec:

```bash
python -m grpc_tools.protoc --proto_path=. --python_out=. pljournal.proto
```

Note: this is not necessary if you have not changed the protobuf spec as the `pljournal_pb2.py` file generated by the previous command is included in the repository.

Run the python tool:
```bash
python plj_dump.py /path/to/file.plj [--head N] [--tail N]
```

### Objective-C tools

```bash
xcrun clang -fobjc-arc -ObjC \
    -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
    -framework Foundation -lz \
    plj_dump.m -o plj_dump
```

Then run `plj_dump`:

```bash
./plj_dump /path/to/file.plj
```

To see help,
```bash
./plj_dump --help
```

```
Usage: ./plj_dump <path_to_plj_file> [options]

Options:
  --head N             Output only the first N records
  --tail N             Output only the last N records
  --payload-class C    Specify payload class explicitly
  --help               Show this help message

Examples:
  ./plj_dump Album-snapshot.plj
  ./plj_dump Asset-change.plj --head 10
  ./plj_dump Person-snapshot.plj --payload-class PLPersonJournalEntryPayload
```

## Reverse engineering .plj files

The following is a description of the process I used to reverse engineer the contents of the `.plj` files.

First, I tried to see if the file was a known format. The `file` command is useful for identifying file types:

```
$ file Album-change.plj
Album-change.plj: data
```

That wasn't very helpful. The files identify only as binary data.

Next I checked to see if there was an associated uniform type identifier (UTI) for the `.plj` extension. MacOS uses UTIs internally to associate file types to applications and my [utitools](https://github.com/rhettbull/utitools) python package contains functions to call the native API:


```
$ uvx --python 3.13 --with utitools ipython
In [1]: import utitools
In [2]: utitools.uti_for_suffix(".plj")

In [3]:
```

As `uti_for_suffix()` returned `None`, there doesn't  appear to be an associated UTI on macOS describing what the files are. I would have expected these to have a UTI of something like `com.apple.property-list-journal` they have no public UTI registered with the OS.

Next, I used a hex dump of the file to see what the data looked like.

```
$ hexdump -C example*data/Album-change.plj | head
00000000 40 b8 6c 00 1f 08 00 12 10 48 3d 65 10 bd 05 42 |@.l......H=e...B|
00000010 b3 b5 28 09 66 94 c9 c0 75 20 01 28 fc 02 30 f1 |..(.f...u .(..0.|
00000020 8f c5 a9 04 62 70 6c 69 73 74 30 30 dc 01 02 03 |....bplist00....|
00000030 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 |................|
00000040 14 15 12 16 17 5f 10 13 63 75 73 74 6f 6d 53 6f |.....*..customSo|
00000050 72 74 41 73 63 65 6e 64 69 6e 67 5f 10 1a 69 6d |rtAscending*..im|
00000060 70 6f 72 74 65 64 42 79 42 75 6e 64 6c 65 49 64 |portedByBundleId|
00000070 65 6e 74 69 66 69 65 72 56 61 73 73 65 74 73 5f |entifierVassets*|
00000080 10 10 6c 61 73 74 4d 6f 64 69 66 69 65 64 44 61 |..lastModifiedDa|
00000090 74 65 59 63 6c 6f 75 64 47 55 49 44 59 70 72 6f |teYcloudGUIDYpro|
```

This is promising. The `bplist00` is a marker indicating the contect is a serialized binary property list (plist). I am familiar with these from my work on other macOS projects such as [osxphotos](https://github.com/rhettbull/osxphotos) and use python code to deserialize the raw data showing that indeed at least part of the file is a binary plist that can be decoded. However, the `.plj` files contain many binary plists and I was not able to easily separate the individual payloads into separate records because I wasn't able to find a consistent header or record separator. Additionally, some of the fields in the binary plist are themselves binary plists so it was not possible to easily extract the records without a recursive parser.

At this point, I decided to see if I could find a native API call for working with these files. I have a collection of iOS and macOS headers that include class and function signatures for Apple frameworks including private frameworks. For example, see [iOS18-Runtime-Headers](https://github.com/qingralf/iOS18-Runtime-Headers).

I assumed that because these files were created by Photos, the Photos private frameworks might have a clue so I started my search in `PrivateFrameworks/PhotoLibraryServices.framework`. This turned out a good place to start.

Running:

```bash
rg -i journal
```

turned up several candidates including `PLJournalEntryHeader.h` and `PLJournalEntry.h`:

Taking a look in `PLJournalEntryHeader.h` showed:

```objc
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

which provides clues as to the structure of the header.

`PLJournalEntry.h` shows the structure of each entry:

```objc
@interface PLJournalEntry : NSObject {
    PLJournalEntryHeader * _header;
    NSPersistentHistoryToken * _historyToken;
    <PLJournalEntryPayload> * _payload;
    Class  _payloadClass;
    <PLJournalEntryPayloadID> * _payloadID;
}
```

Now I have some clues as to the contents of the header that is apparent in each record before the binary plist payload. `NSPersistentHistoryToken` is mentioned in the Core Data documentation and described as "A bookmark for keeping track the most recent history that you’ve processed."  Looking at the other header files, we can see there is `PLDetectedFaceJournalEntryPayload.h`, `PLGenericAlbumJournalEntryPayload.h`, and so on for every type of `.plj` file that is present in the `resources/journals` folder.

The `PLJournalEntryHeader` class inherits from `PBCodable`. This piqued my interest and I wondered if the "PB" in `PBCodable` stood for [protocol buffer](https://protobuf.dev/overview/). I knew Apple used protocol buffers in other apps such as [Apple Notes](https://github.com/RhetTbull/apple-notes-parser) so it wouldn't be out of place here.

A little more searching through private frameworks turned up `ProtocolBuffer.framework/PBCodable.h`. So now we know that `PBCodable` represents a protocol buffer, and we can use it to decode the data in the header.

I used [protoscope](https://github.com/protocolbuffers/protoscope) to inspect the files. From the `PLJournalEntryHeader` interface, I expected at least 7 protocol buffer tags to represent the contents:

```objc
    int  _entryType;
    NSMutableArray * _nilProperties;
    unsigned int  _payloadCRC;
    NSString * _payloadID;
    unsigned long long  _payloadLength;
    NSData * _payloadUUID;
    unsigned int  _payloadVersion;
```

Running protoscope against the data:

```bash
protoscope -all-fields-are-messages -explicit-wire-types example_data/Asset-change.plj | head
8:VARINT 63
`ae0020080112106817b3aff5174badad0419ce162e52f020ac0228fc0430a2b9fac40862706c6973`
`743030d10102597265736f7572636573a4031f272dde0405060708090a0b0c0d0e0f101112131415`
```

This doesn't match what I expected as I don't see the 7 expected tags. In looking at hex dump output of the `.plj` files I noticed the file always started with 0x40 and this value appeared to repeat in the header for each bplist payload. There must be some sort of custom header *before* the protocol buffer header. I then used `dd` to skip one byte at a time to see if I could find the correct start of the protbuf header and it looks like the custom header is 5 bytes long:

```
$ dd if=example_data/Album-change.plj bs=1 skip=5 count=500 status=none | protoscope -all-fields-are-messages -explicit-wire-types
1:VARINT 0
2:LEN {
  9:VARINT 61
  12:I32 33.43463i32  # 0x4205bd10i32
  82774:SGRSGROUP
  `096694c9c075`
}
4:VARINT 1
5:VARINT 380
6:VARINT 1160857585
12:LEN {
  13:EGROUP
  13:I64 3.524374304638213e-294   # 0x30201dc30307473i64
  0:EGROUP
  0:I32 1.6373707e-33i32  # 0x9080706i32
  1:LEN {
    1:EGROUP
    1:I32 1.1364236e-28i32  # 0x11100f0ei32
    `1213141512`
  }
  `16175f1013637573746f6d536f7274417363656e64696e675f101a696d706f72746564427942756e`
  `646c654964656e746966696572566173736574735f10106c6173744d6f6469666965644461746559`
  `636c6f`
}
14:I32 873590.25i32   # 0x49554764i32
8:EGROUP
11:I64 6.323052381170846e233  # 0x7079746f746f7270i64
12:I32 7.398466e31i32         # 0x74697455i32
13:EGROUP
12:I32 4.095878e12i32   # 0x546e6957i32
14:LEN {
  14:SGRSGROUP
  13:VARINT 93
  12:SGRSGROUP
  14:I32 4.631731e27i32   # 0x6d6f7473i32
  10:SGRSGROUP
  `6f72744b65795670696e6e6564546b696e645c6372656174696f6e4461746510015f1013636f6d2e`
  `627572626e2e696e7374616772616d4f101013d4be64b05e4852958a60bc661d8a823341c6fe7628`
  `3a40295f102443`
}
7:I64 4.299747047486346e-38   # 0x382d433744383341i64
8:LEN {
  6:I32 0.00017090207i32  # 0x3933342di32
  `462d383835422d464132363736463233413538100059496e7374616772616d08100010023341c6fe`
  `7648156aa50008`
}
```

It looks like all the tags with the execption of tag 3 is present. The additional tags are a result of `protoscope` decoding non-protobuf data as a protobuf.

Looks like there's 5 bytes at beginning of protobuf data, always starts with 0x40 then 4 bytes

The next step was to map the protobuf tags to the expected data from the `PLJournalEntryHeader` so I could create a protobuf message spec. This involved some trial and error. For example, tag 5 (`5:VARINT 380`) looked like it might be the payload length and this was easily verifiable by looking at the bplist data that followed in a hex editor, which was indeed 380 bytes long. For hex editors, I like [Hex Fiend](ZZZ) which is a nice light weight open source editor. [ImHex](ZZZ) is another more powerful editor designed for reverse engineering but with a steeper learning curve.

Additional trial and error was used to map the other tags, for example, tag 6 (`6:VARINT 1160857585`) is the CRC and this could be verified by computing the CRC of the payload to see that it matched the value in the tag.

This allowed me to create a protobuf spec (I used Claude Code to help with this once I'd mapped the basic structure):

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

This [pljournal.proto](pljournal.proto) message spec can be compiled using the Google grpc tools to produce python code to read the data:

```bash
python -m grpc_tools.protoc --proto_path=. --python_out=. pbjournal.proto
```

The resuling [pljournal_pb2.py](pljournal_pb2.py) can be used in a python script, [plj_reader.py](plj_reader.py) to parse the data.

For example,

```bash
python plj_reader.py example_data/Album-snapshot.plj --limit 1 --json
```

produces:

```
{
    "index": 0,
    "offset": 0,
    "headerChecksum": 520105627,
    "entryType": 0,
    "payloadVersion": 1,
    "payloadLength": 454,
    "payloadCRC": 4077552798,
    "crcMatches": true,
    "payloadUUID": "0dbba15e-c14b-4c22-9f5d-9858917057d5",
    "payloadID": null,
    "nilProperties": [],
    "payloadKind": "plist",
    "payload": {
        "customSortAscending": 1,
        "importedByBundleIdentifier": "com.apple.Photos",
        "assets": [
            "B0A31F74-1BE5-49E9-9BED-2CDD7D2086ED",
            "4884C569-0D65-45B1-AADD-11F7B6E3686E",
            "851A2833-C6AD-407A-947E-D10040C183C3",
            "69EFEF83-59E2-4295-9CCE-F4C0E5161D41",
            "07927DD7-4996-4A51-A7B3-2947EA300784",
            "013F40A5-F742-41E6-80F5-40E2456145CD",
            "8B416ACD-1234-47B2-800E-30B92EAF4EC2"
        ],
        "lastModifiedDate": "2025-04-04T22:25:32.070169",
        "cloudGUID": "C67381CF-72B9-4D9B-939C-4AFBB64BA34D",
        "prototype": 0,
        "title": "test2",
        "inTrash": false,
        "customSortKey": 1,
        "pinned": 0,
        "kind": 2,
        "creationDate": "2025-04-04T22:25:32.070169"
    }
}
```

Some keys in the decoded data for some of the file types contain binary data, represented as an NSData object. For example, album assets as shown above. The curatedAssets and representativeAssets keys also contain binary data. For those related to albums, I looked at the albums in Photos and noticed the length was always 16 bytes \* number of assets. These turned out to be packed UUIDs. The example utilities account for this and unpack the UUIDs.

### Using the native framework to parse `.plj` files
