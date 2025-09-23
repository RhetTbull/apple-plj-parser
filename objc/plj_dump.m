/**
 * PLJ Dump Tool - JSON Edition
 *
 * A command-line utility for reading and parsing Apple Photos .plj (plist journal) files.
 * This tool uses private PhotoLibraryServices framework methods to decode journal entries
 * and outputs the results in JSON format.
 *
 * Usage:
 *   plj_dump_new <path_to_plj_file> [options]
 *
 * Options:
 *   --head N         Output only the first N records
 *   --tail N         Output only the last N records
 *   --payload-class  Specify payload class explicitly (overrides auto-detection)
 *   --help           Show usage information
 *
 * Compilation:
 *   xcrun clang -fobjc-arc -ObjC \
 *     -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
 *     -framework Foundation \
 *     plj_dump_new.m -o plj_dump_new
 */

#import <Foundation/Foundation.h>
#import <zlib.h>
#include <uuid/uuid.h>
#include <string.h>
#include <getopt.h>
#include <dlfcn.h>

#pragma mark - Private Framework Interfaces

/**
 * Private interface for creating payload identifiers from UUIDs or strings
 * Note: These are private APIs that may not be available at compile time
 */
@interface PLJournalEntryPayloadIDFactory : NSObject
+ (nullable id)payloadIDWithUUIDString:(nonnull NSString *)uuidString;
+ (nullable id)payloadIDWithString:(nonnull NSString *)string;
@end

/**
 * Private interface for creating managed object journal entry payloads
 * Note: These are private APIs that may not be available at compile time
 */
@interface PLManagedObjectJournalEntryPayload : NSObject
+ (nullable id)payloadWithData:(nonnull NSData *)data
                  forPayloadID:(nonnull id)payloadID
                       version:(unsigned int)version
              andNilProperties:(nullable NSSet<NSString *> *)nilProperties
                         error:(NSError *_Nullable *_Nullable)error;
- (nullable NSDictionary *)rawPayloadAttributes;
- (nullable NSDictionary *)payloadAttributes;
@end

/**
 * Loads the PhotoLibraryServices private framework
 * @return YES if framework was loaded successfully, NO otherwise
 */
static BOOL LoadPhotoLibraryServicesFramework(void) {
    static dispatch_once_t onceToken;
    static BOOL frameworkLoaded = NO;

    dispatch_once(&onceToken, ^{
        // Try different possible paths for PhotoLibraryServices framework
        NSArray<NSString *> *possiblePaths = @[
            @"/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/PhotoLibraryServices",
            @"/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/Versions/A/PhotoLibraryServices",
            @"/Applications/Photos.app/Contents/Frameworks/PhotoLibraryServices.framework/PhotoLibraryServices",
            @"/Applications/Photos.app/Contents/Frameworks/PhotoLibraryServices.framework/Versions/A/PhotoLibraryServices"
        ];

        for (NSString *path in possiblePaths) {
            void *handle = dlopen(path.UTF8String, RTLD_LAZY);
            if (handle) {
                frameworkLoaded = YES;
                break;
            }
        }

        // Also try using NSBundle to load the framework
        if (!frameworkLoaded) {
            NSArray<NSString *> *bundlePaths = @[
                @"/System/Library/PrivateFrameworks/PhotoLibraryServices.framework",
                @"/Applications/Photos.app/Contents/Frameworks/PhotoLibraryServices.framework"
            ];

            for (NSString *bundlePath in bundlePaths) {
                NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
                if (bundle && [bundle load]) {
                    frameworkLoaded = YES;
                    break;
                }
            }
        }
    });

    return frameworkLoaded;
}

/**
 * Runtime check for private framework availability
 * @param className Name of the class to check
 * @return YES if class is available, NO otherwise
 */
static BOOL IsPrivateClassAvailable(NSString *_Nonnull className) {
    return NSClassFromString(className) != nil;
}

#pragma mark - Constants

/// Domain for PLJ-specific errors
static NSString *const kPLJDumpErrorDomain = @"PLJDump";

/// Error codes for PLJ parsing
typedef NS_ENUM(NSInteger, PLJDumpErrorCode) {
    PLJDumpErrorCodeHeaderKeyReadFailed = 1,
    PLJDumpErrorCodeEntryTypeReadFailed = 2,
    PLJDumpErrorCodeInvalidPayloadUUID = 3,
    PLJDumpErrorCodeInvalidPayloadID = 4,
    PLJDumpErrorCodePayloadVersionReadFailed = 5,
    PLJDumpErrorCodePayloadLengthReadFailed = 6,
    PLJDumpErrorCodePayloadCRCReadFailed = 7,
    PLJDumpErrorCodeInvalidNilProperty = 8,
    PLJDumpErrorCodeUnsupportedField = 9
};

#pragma mark - Configuration Structure

/**
 * Configuration structure for the PLJ dump operation
 */
typedef struct {
    NSString *_Nonnull filePath;
    NSString *_Nullable payloadClassName;
    NSInteger headCount;
    NSInteger tailCount;
    BOOL showHelp;
} PLJDumpConfig;

#pragma mark - Protobuf Utilities

/**
 * Reads a varint from a byte buffer
 * @param bytes The byte buffer to read from
 * @param length The length of the buffer
 * @param offset Pointer to the current offset (will be updated)
 * @param value Pointer to store the decoded value
 * @return YES if successful, NO otherwise
 */
static BOOL ReadVarint(const uint8_t *_Nonnull bytes, NSUInteger length, NSUInteger *_Nonnull offset, uint64_t *_Nonnull value) {
    uint64_t result = 0;
    NSUInteger shift = 0;

    while (*offset < length && shift <= 63) {
        uint8_t byte = bytes[(*offset)++];
        result |= (uint64_t)(byte & 0x7F) << shift;

        if ((byte & 0x80) == 0) {
            *value = result;
            return YES;
        }
        shift += 7;
    }
    return NO;
}

/**
 * Skips a protobuf field based on its wire type
 * @param bytes The byte buffer
 * @param length The length of the buffer
 * @param offset Pointer to the current offset (will be updated)
 * @param wireType The wire type of the field to skip
 * @return YES if successful, NO otherwise
 */
static BOOL SkipField(const uint8_t *_Nonnull bytes, NSUInteger length, NSUInteger *_Nonnull offset, uint32_t wireType) {
    switch (wireType) {
        case 0: { // Varint
            uint64_t ignored = 0;
            return ReadVarint(bytes, length, offset, &ignored);
        }
        case 1: { // 64-bit
            if (*offset + 8 > length) return NO;
            *offset += 8;
            return YES;
        }
        case 2: { // Length-delimited
            uint64_t len = 0;
            if (!ReadVarint(bytes, length, offset, &len)) return NO;
            if (*offset + len > length) return NO;
            *offset += (NSUInteger)len;
            return YES;
        }
        case 5: { // 32-bit
            if (*offset + 4 > length) return NO;
            *offset += 4;
            return YES;
        }
        case 3: { // Start group (deprecated)
            while (*offset < length) {
                uint64_t key = 0;
                if (!ReadVarint(bytes, length, offset, &key)) return NO;
                uint32_t wt = (uint32_t)(key & 0x7);
                if (wt == 4) return YES; // End group
                if (!SkipField(bytes, length, offset, wt)) return NO;
            }
            return NO;
        }
        default:
            return NO;
    }
}

#pragma mark - Payload Class Mapping

/**
 * Returns a mapping of entity names to their corresponding payload class names
 * @return Dictionary mapping entity names to payload class names
 */
static NSDictionary<NSString *, NSString *> *_Nonnull PayloadClassMap(void) {
    static NSDictionary<NSString *, NSString *> *map;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        map = @{
            @"Asset": @"PLAssetJournalEntryPayload",
            @"Album": @"PLAlbumJournalEntryPayload",
            @"DeferredRebuildFace": @"PLDeferredRebuildFaceJournalEntryPayload",
            @"DetectedFace": @"PLDetectedFaceJournalEntryPayload",
            @"FetchingAlbum": @"PLFetchingAlbumJournalEntryPayload",
            @"FileSystemVolume": @"PLFileSystemVolumeJournalEntryPayload",
            @"Folder": @"PLFolderJournalEntryPayload",
            @"ImportSession": @"PLImportSessionJournalEntryPayload",
            @"Keyword": @"PLKeywordJournalEntryPayload",
            @"Memory": @"PLMemoryJournalEntryPayload",
            @"MigrationHistory": @"PLMigrationHistoryJournalEntryPayload",
            @"Person": @"PLPersonJournalEntryPayload",
            @"ProjectAlbum": @"PLProjectAlbumJournalEntryPayload",
            @"SocialGroup": @"PLSocialGroupJournalEntryPayload"
        };
    });
    return map;
}

/**
 * Determines the default payload class name from a file URL
 * @param url The URL of the .plj file
 * @return The payload class name, or nil if not found
 */
static NSString *_Nullable DefaultPayloadClassNameForURL(NSURL *_Nonnull url) {
    NSString *stem = [[url lastPathComponent] stringByDeletingPathExtension];

    // Remove common suffixes
    if ([stem hasSuffix:@"-change"]) {
        stem = [stem substringToIndex:stem.length - 7];
    } else if ([stem hasSuffix:@"-snapshot"]) {
        stem = [stem substringToIndex:stem.length - 9];
    }

    return PayloadClassMap()[stem];
}

#pragma mark - Header Parsing

/**
 * Parses the protobuf header of a journal entry
 * @param headerData The header data to parse
 * @param entryType Output parameter for entry type
 * @param payloadUUID Output parameter for payload UUID
 * @param payloadIDString Output parameter for payload ID string
 * @param payloadVersion Output parameter for payload version
 * @param payloadLength Output parameter for payload length
 * @param payloadCRC Output parameter for payload CRC
 * @param nilProperties Mutable array to collect nil property names
 * @param error Output parameter for any parsing errors
 * @return YES if parsing succeeded, NO otherwise
 */
static BOOL ParseHeader(NSData *_Nonnull headerData,
                       uint64_t *_Nullable entryType,
                       NSData *_Nullable *_Nullable payloadUUID,
                       NSString *_Nullable *_Nullable payloadIDString,
                       uint64_t *_Nullable payloadVersion,
                       uint64_t *_Nullable payloadLength,
                       uint32_t *_Nullable payloadCRC,
                       NSMutableArray<NSString *> *_Nullable nilProperties,
                       NSError *_Nullable *_Nullable error) {

    const uint8_t *bytes = headerData.bytes;
    NSUInteger length = headerData.length;
    NSUInteger offset = 0;

    while (offset < length) {
        uint64_t key = 0;
        if (!ReadVarint(bytes, length, &offset, &key)) {
            if (error) {
                *error = [NSError errorWithDomain:kPLJDumpErrorDomain
                                             code:PLJDumpErrorCodeHeaderKeyReadFailed
                                         userInfo:@{NSLocalizedDescriptionKey: @"Failed to read header key"}];
            }
            return NO;
        }

        uint32_t fieldNumber = (uint32_t)(key >> 3);
        uint32_t wireType = (uint32_t)(key & 0x7);

        switch (fieldNumber) {
            case 1: { // entryType
                if (wireType != 0) {
                    if (!SkipField(bytes, length, &offset, wireType)) return NO;
                    break;
                }
                uint64_t value = 0;
                if (!ReadVarint(bytes, length, &offset, &value)) {
                    if (error) {
                        *error = [NSError errorWithDomain:kPLJDumpErrorDomain
                                                     code:PLJDumpErrorCodeEntryTypeReadFailed
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Failed to read entryType"}];
                    }
                    return NO;
                }
                if (entryType) *entryType = value;
                break;
            }
            case 2: { // payloadUUID
                if (wireType != 2) {
                    if (!SkipField(bytes, length, &offset, wireType)) return NO;
                    break;
                }
                uint64_t len = 0;
                if (!ReadVarint(bytes, length, &offset, &len) || offset + len > length) {
                    if (error) {
                        *error = [NSError errorWithDomain:kPLJDumpErrorDomain
                                                     code:PLJDumpErrorCodeInvalidPayloadUUID
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Invalid payloadUUID"}];
                    }
                    return NO;
                }
                if (payloadUUID) {
                    *payloadUUID = [NSData dataWithBytes:&bytes[offset] length:(NSUInteger)len];
                }
                offset += (NSUInteger)len;
                break;
            }
            case 3: { // payloadID string
                if (wireType != 2) {
                    if (!SkipField(bytes, length, &offset, wireType)) return NO;
                    break;
                }
                uint64_t len = 0;
                if (!ReadVarint(bytes, length, &offset, &len) || offset + len > length) {
                    if (error) {
                        *error = [NSError errorWithDomain:kPLJDumpErrorDomain
                                                     code:PLJDumpErrorCodeInvalidPayloadID
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Invalid payloadID"}];
                    }
                    return NO;
                }
                if (payloadIDString) {
                    NSString *string = [[NSString alloc] initWithBytes:&bytes[offset]
                                                                length:(NSUInteger)len
                                                              encoding:NSUTF8StringEncoding];
                    *payloadIDString = string;
                }
                offset += (NSUInteger)len;
                break;
            }
            case 4: { // payloadVersion
                if (wireType != 0) {
                    if (!SkipField(bytes, length, &offset, wireType)) return NO;
                    break;
                }
                uint64_t value = 0;
                if (!ReadVarint(bytes, length, &offset, &value)) {
                    if (error) {
                        *error = [NSError errorWithDomain:kPLJDumpErrorDomain
                                                     code:PLJDumpErrorCodePayloadVersionReadFailed
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Failed to read payloadVersion"}];
                    }
                    return NO;
                }
                if (payloadVersion) *payloadVersion = value;
                break;
            }
            case 5: { // payloadLength
                if (wireType != 0) {
                    if (!SkipField(bytes, length, &offset, wireType)) return NO;
                    break;
                }
                uint64_t value = 0;
                if (!ReadVarint(bytes, length, &offset, &value)) {
                    if (error) {
                        *error = [NSError errorWithDomain:kPLJDumpErrorDomain
                                                     code:PLJDumpErrorCodePayloadLengthReadFailed
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Failed to read payloadLength"}];
                    }
                    return NO;
                }
                if (payloadLength) *payloadLength = value;
                break;
            }
            case 6: { // payloadCRC
                if (wireType != 0) {
                    if (!SkipField(bytes, length, &offset, wireType)) return NO;
                    break;
                }
                uint64_t value = 0;
                if (!ReadVarint(bytes, length, &offset, &value)) {
                    if (error) {
                        *error = [NSError errorWithDomain:kPLJDumpErrorDomain
                                                     code:PLJDumpErrorCodePayloadCRCReadFailed
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Failed to read payloadCRC"}];
                    }
                    return NO;
                }
                if (payloadCRC) *payloadCRC = (uint32_t)value;
                break;
            }
            case 7: { // nil property name
                if (wireType != 2) {
                    if (!SkipField(bytes, length, &offset, wireType)) return NO;
                    break;
                }
                uint64_t len = 0;
                if (!ReadVarint(bytes, length, &offset, &len) || offset + len > length) {
                    if (error) {
                        *error = [NSError errorWithDomain:kPLJDumpErrorDomain
                                                     code:PLJDumpErrorCodeInvalidNilProperty
                                                 userInfo:@{NSLocalizedDescriptionKey: @"Invalid nil property"}];
                    }
                    return NO;
                }
                if (nilProperties) {
                    NSString *string = [[NSString alloc] initWithBytes:&bytes[offset]
                                                                length:(NSUInteger)len
                                                              encoding:NSUTF8StringEncoding];
                    if (string) {
                        [nilProperties addObject:string];
                    }
                }
                offset += (NSUInteger)len;
                break;
            }
            default: {
                if (!SkipField(bytes, length, &offset, wireType)) {
                    if (error) {
                        NSString *message = [NSString stringWithFormat:@"Unsupported field %u", fieldNumber];
                        *error = [NSError errorWithDomain:kPLJDumpErrorDomain
                                                     code:PLJDumpErrorCodeUnsupportedField
                                                 userInfo:@{NSLocalizedDescriptionKey: message}];
                    }
                    return NO;
                }
                break;
            }
        }
    }

    return YES;
}

#pragma mark - Payload Processing

/**
 * Builds a payload identifier from UUID data or string ID
 * @param uuidData UUID data (16 bytes)
 * @param stringID String identifier
 * @return Payload identifier object, or nil if neither is valid or private API unavailable
 */
static id _Nullable BuildPayloadIdentifier(NSData *_Nullable uuidData, NSString *_Nullable stringID) {
    Class factoryClass = NSClassFromString(@"PLJournalEntryPayloadIDFactory");
    if (!factoryClass) {
        return nil; // Private API not available
    }

    if (uuidData.length == 16) {
        uuid_t uuidBytes;
        [uuidData getBytes:uuidBytes length:sizeof(uuidBytes)];
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDBytes:uuidBytes];
        return [factoryClass payloadIDWithUUIDString:uuid.UUIDString];
    } else if (stringID.length > 0) {
        return [factoryClass payloadIDWithString:stringID];
    }
    return nil;
}

/**
 * Decodes asset UUIDs from raw data (for Album payloads)
 * @param assetsData Raw data containing packed UUIDs
 * @return Array of UUID strings, or nil if invalid
 */
static NSArray<NSString *> *_Nullable DecodeAssetUUIDs(NSData *_Nullable assetsData) {
    if (!assetsData || assetsData.length == 0 || assetsData.length % 16 != 0) {
        return nil;
    }

    NSMutableArray<NSString *> *uuids = [NSMutableArray array];
    const uint8_t *bytes = assetsData.bytes;
    NSUInteger count = assetsData.length / 16;

    for (NSUInteger i = 0; i < count; i++) {
        uuid_t uuidBytes;
        memcpy(uuidBytes, &bytes[i * 16], 16);
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDBytes:uuidBytes];
        [uuids addObject:uuid.UUIDString];
    }

    return [uuids copy];
}

/**
 * Extracts raw payload attributes from a payload object
 * @param payload The payload object
 * @return Dictionary of attributes, or nil if not available
 */
static NSDictionary *_Nullable RawPayloadAttributes(id _Nullable payload) {
    if ([payload respondsToSelector:@selector(rawPayloadAttributes)]) {
        return [payload valueForKey:@"rawPayloadAttributes"];
    }
    if ([payload respondsToSelector:@selector(payloadAttributes)]) {
        return [payload valueForKey:@"payloadAttributes"];
    }
    return nil;
}

#pragma mark - JSON Conversion

/**
 * Converts an object to a JSON-serializable representation
 * @param object The object to convert
 * @return JSON-serializable object
 */
static id _Nonnull ConvertToJSONSerializable(id _Nullable object) {
    if (!object || [object isKindOfClass:[NSNull class]]) {
        return [NSNull null];
    }

    if ([object isKindOfClass:[NSString class]] ||
        [object isKindOfClass:[NSNumber class]]) {
        return object;
    }

    if ([object isKindOfClass:[NSData class]]) {
        NSData *data = (NSData *)object;
        return [data base64EncodedStringWithOptions:0];
    }

    if ([object isKindOfClass:[NSDate class]]) {
        NSDate *date = (NSDate *)object;
        return @(date.timeIntervalSince1970);
    }

    if ([object isKindOfClass:[NSUUID class]]) {
        NSUUID *uuid = (NSUUID *)object;
        return uuid.UUIDString;
    }

    if ([object isKindOfClass:[NSArray class]]) {
        NSArray *array = (NSArray *)object;
        NSMutableArray *jsonArray = [NSMutableArray arrayWithCapacity:array.count];
        for (id item in array) {
            [jsonArray addObject:ConvertToJSONSerializable(item)];
        }
        return [jsonArray copy];
    }

    if ([object isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)object;
        NSMutableDictionary *jsonDict = [NSMutableDictionary dictionaryWithCapacity:dict.count];
        for (id key in dict) {
            NSString *jsonKey = [key isKindOfClass:[NSString class]] ? key : [key description];
            jsonDict[jsonKey] = ConvertToJSONSerializable(dict[key]);
        }
        return [jsonDict copy];
    }

    // Fallback to string representation
    return [object description];
}

#pragma mark - Command Line Parsing

/**
 * Displays usage information
 * @param programName The name of the program
 */
static void ShowUsage(const char *_Nonnull programName) {
    printf("PLJ Dump Tool - JSON Edition\n\n");
    printf("Usage: %s <path_to_plj_file> [options]\n\n", programName);
    printf("Options:\n");
    printf("  --head N             Output only the first N records\n");
    printf("  --tail N             Output only the last N records\n");
    printf("  --payload-class C    Specify payload class explicitly\n");
    printf("  --help               Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s Album-snapshot.plj\n", programName);
    printf("  %s Asset-change.plj --head 10\n", programName);
    printf("  %s Person-snapshot.plj --payload-class PLPersonJournalEntryPayload\n", programName);
}

/**
 * Parses command line arguments
 * @param argc Argument count
 * @param argv Argument vector
 * @return Configuration structure
 */
static PLJDumpConfig ParseCommandLine(int argc, const char *_Nonnull *_Nonnull argv) {
    PLJDumpConfig config = {
        .filePath = nil,
        .payloadClassName = nil,
        .headCount = -1,
        .tailCount = -1,
        .showHelp = NO
    };

    static struct option long_options[] = {
        {"head", required_argument, 0, 'h'},
        {"tail", required_argument, 0, 't'},
        {"payload-class", required_argument, 0, 'p'},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, (char *const *)argv, "h:t:p:?", long_options, &option_index)) != -1) {
        switch (c) {
            case 'h':
                config.headCount = atoi(optarg);
                break;
            case 't':
                config.tailCount = atoi(optarg);
                break;
            case 'p':
                config.payloadClassName = [NSString stringWithUTF8String:optarg];
                break;
            case '?':
            default:
                config.showHelp = YES;
                return config;
        }
    }

    if (optind < argc) {
        config.filePath = [NSString stringWithUTF8String:argv[optind]];
    } else if (!config.showHelp) {
        config.showHelp = YES;
    }

    return config;
}

#pragma mark - Entry Processing

/**
 * Represents a single journal entry
 */
@interface PLJEntry : NSObject
@property (nonatomic, assign) uint64_t index;
@property (nonatomic, assign) uint64_t entryType;
@property (nonatomic, assign) uint64_t payloadVersion;
@property (nonatomic, assign) uint64_t payloadLength;
@property (nonatomic, assign) uint32_t payloadCRC;
@property (nonatomic, assign) uint32_t headerChecksum;
@property (nonatomic, assign) BOOL crcMatches;
@property (nonatomic, strong, nullable) NSArray<NSString *> *nilProperties;
@property (nonatomic, strong, nullable) NSError *payloadError;
@property (nonatomic, strong, nullable) NSDictionary *attributes;
@end

@implementation PLJEntry
@end

/**
 * Processes all entries from a PLJ file
 * @param handle File handle for the PLJ file
 * @param payloadClass The payload class to use for decoding
 * @param config Configuration for processing
 * @return Array of PLJEntry objects
 */
static NSArray<PLJEntry *> *_Nullable ProcessAllEntries(NSFileHandle *_Nonnull handle,
                                                        Class _Nonnull payloadClass,
                                                        PLJDumpConfig config) {
    NSMutableArray<PLJEntry *> *entries = [NSMutableArray array];
    uint64_t entryIndex = 0;

    while (YES) {
        NSData *prefix = [handle readDataOfLength:5];
        if (prefix.length == 0) break; // EOF

        if (prefix.length < 5) {
            fprintf(stderr, "Truncated entry prefix at entry %llu\n", entryIndex);
            break;
        }

        const uint8_t *prefixBytes = prefix.bytes;
        if (prefixBytes[0] != 0x40) {
            fprintf(stderr, "Unexpected sentinel 0x%02x at entry %llu\n", prefixBytes[0], entryIndex);
            break;
        }

        uint32_t headerChecksum = (uint32_t)prefixBytes[0] | ((uint32_t)prefixBytes[1] << 8) |
                                 ((uint32_t)prefixBytes[2] << 16) | ((uint32_t)prefixBytes[3] << 24);
        uint8_t headerLength = prefixBytes[4];

        NSData *headerData = [handle readDataOfLength:headerLength];
        if (headerData.length < headerLength) {
            fprintf(stderr, "Truncated header at entry %llu\n", entryIndex);
            break;
        }

        PLJEntry *entry = [[PLJEntry alloc] init];
        entry.index = entryIndex;
        entry.headerChecksum = headerChecksum;

        uint64_t entryType = 0, payloadVersion = 0, payloadLength = 0;
        uint32_t payloadCRC = 0;
        NSData *payloadUUID = nil;
        NSString *payloadIDString = nil;
        NSMutableArray<NSString *> *nilProperties = [NSMutableArray array];
        NSError *error = nil;

        if (!ParseHeader(headerData, &entryType, &payloadUUID, &payloadIDString,
                        &payloadVersion, &payloadLength, &payloadCRC, nilProperties, &error)) {
            fprintf(stderr, "Failed to parse header for entry %llu: %s\n",
                   entryIndex, error.localizedDescription.UTF8String);
            break;
        }

        entry.entryType = entryType;
        entry.payloadVersion = payloadVersion;
        entry.payloadLength = payloadLength;
        entry.payloadCRC = payloadCRC;
        entry.nilProperties = nilProperties.count > 0 ? [nilProperties copy] : nil;

        NSData *payloadData = [handle readDataOfLength:(NSUInteger)payloadLength];
        if (payloadData.length < payloadLength) {
            fprintf(stderr, "Truncated payload at entry %llu\n", entryIndex);
            break;
        }

        uint32_t computedCRC = (uint32_t)crc32(0L, payloadData.bytes, (uInt)payloadData.length);
        entry.crcMatches = (payloadData.length == 0) || (computedCRC == payloadCRC);

        // Process payload if valid and private API is available
        if (payloadData.length > 0 && payloadClass) {
            id payloadIdentifier = BuildPayloadIdentifier(payloadUUID, payloadIDString);
            if (payloadIdentifier) {
                NSSet<NSString *> *nilPropsSet = nilProperties.count ? [NSSet setWithArray:nilProperties] : nil;
                NSError *payloadError = nil;
                id payload = [payloadClass payloadWithData:payloadData
                                              forPayloadID:payloadIdentifier
                                                   version:(unsigned int)payloadVersion
                                          andNilProperties:nilPropsSet
                                                     error:&payloadError];

                if (payloadError) {
                    entry.payloadError = payloadError;
                } else if (payload) {
                    NSDictionary *attributes = RawPayloadAttributes(payload);
                    if (attributes.count > 0) {
                        NSMutableDictionary *displayAttributes = [attributes mutableCopy];

                        // Special handling for Album payloads
                        NSData *assetsData = attributes[@"assets"];
                        if (assetsData && [assetsData isKindOfClass:[NSData class]] &&
                            ([config.payloadClassName isEqualToString:@"PLAlbumJournalEntryPayload"] ||
                             [config.filePath.lastPathComponent.stringByDeletingPathExtension hasPrefix:@"Album"])) {
                            NSArray<NSString *> *assetUUIDs = DecodeAssetUUIDs(assetsData);
                            if (assetUUIDs) {
                                displayAttributes[@"assets_decoded"] = assetUUIDs;
                                displayAttributes[@"asset_count"] = @(assetUUIDs.count);
                            }
                        }

                        entry.attributes = [displayAttributes copy];
                    }
                }
            }
        } else if (payloadData.length > 0 && !payloadClass) {
            // No private API available - include raw payload data as base64
            NSMutableDictionary *rawInfo = [NSMutableDictionary dictionary];
            rawInfo[@"raw_payload_base64"] = [payloadData base64EncodedStringWithOptions:0];
            rawInfo[@"raw_payload_size"] = @(payloadData.length);
            entry.attributes = [rawInfo copy];
        }

        [entries addObject:entry];
        entryIndex++;
    }

    return [entries copy];
}

/**
 * Filters entries based on head/tail configuration
 * @param entries All entries
 * @param config Configuration specifying head/tail limits
 * @return Filtered array of entries
 */
static NSArray<PLJEntry *> *_Nonnull FilterEntries(NSArray<PLJEntry *> *_Nonnull entries, PLJDumpConfig config) {
    if (config.headCount > 0 && config.tailCount > 0) {
        // Both head and tail specified - this is ambiguous, prefer head
        NSInteger count = MIN(config.headCount, (NSInteger)entries.count);
        return [entries subarrayWithRange:NSMakeRange(0, count)];
    } else if (config.headCount > 0) {
        NSInteger count = MIN(config.headCount, (NSInteger)entries.count);
        return [entries subarrayWithRange:NSMakeRange(0, count)];
    } else if (config.tailCount > 0) {
        NSInteger count = MIN(config.tailCount, (NSInteger)entries.count);
        NSInteger start = MAX(0, (NSInteger)entries.count - count);
        return [entries subarrayWithRange:NSMakeRange(start, count)];
    }

    return entries;
}

/**
 * Converts a PLJEntry to a JSON-serializable dictionary
 * @param entry The entry to convert
 * @return Dictionary representation
 */
static NSDictionary *_Nonnull EntryToJSON(PLJEntry *_Nonnull entry) {
    NSMutableDictionary *json = [NSMutableDictionary dictionary];

    json[@"index"] = @(entry.index);
    json[@"entry_type"] = @(entry.entryType);
    json[@"payload_version"] = @(entry.payloadVersion);
    json[@"payload_length"] = @(entry.payloadLength);
    json[@"payload_crc"] = [NSString stringWithFormat:@"0x%x", entry.payloadCRC];
    json[@"header_checksum"] = [NSString stringWithFormat:@"0x%x", entry.headerChecksum];
    json[@"crc_matches"] = @(entry.crcMatches);

    if (entry.nilProperties) {
        json[@"nil_properties"] = entry.nilProperties;
    }

    if (entry.payloadError) {
        json[@"payload_error"] = entry.payloadError.localizedDescription;
    }

    if (entry.attributes) {
        json[@"attributes"] = ConvertToJSONSerializable(entry.attributes);
    }

    return [json copy];
}

#pragma mark - Main Function

int main(int argc, const char *_Nonnull argv[]) {
    @autoreleasepool {
        PLJDumpConfig config = ParseCommandLine(argc, argv);

        if (config.showHelp) {
            ShowUsage(argv[0]);
            return EXIT_SUCCESS;
        }

        if (!config.filePath) {
            fprintf(stderr, "Error: No input file specified\n\n");
            ShowUsage(argv[0]);
            return EXIT_FAILURE;
        }

        NSURL *url = [NSURL fileURLWithPath:config.filePath];

        // Load PhotoLibraryServices framework to access private APIs
        BOOL frameworkLoaded = LoadPhotoLibraryServicesFramework();
        if (!frameworkLoaded) {
            fprintf(stderr, "Warning: Could not load PhotoLibraryServices framework.\n");
            fprintf(stderr, "The tool will still parse headers and structure but cannot decode payloads.\n");
        }

        // Determine payload class
        NSString *className = config.payloadClassName;
        if (!className) {
            className = DefaultPayloadClassNameForURL(url);
        }

        if (className.length == 0) {
            fprintf(stderr, "Error: Unable to infer payload class for %s. Use --payload-class to specify it explicitly.\n",
                   config.filePath.UTF8String);
            return EXIT_FAILURE;
        }

        Class payloadClass = NSClassFromString(className);
        if (!payloadClass && frameworkLoaded) {
            fprintf(stderr, "Warning: Payload class %s is unavailable even though framework was loaded.\n", className.UTF8String);
            fprintf(stderr, "The tool will still parse headers and structure but cannot decode payloads.\n");
        } else if (!payloadClass && !frameworkLoaded) {
            // Framework not loaded, so this is expected
        }

        // Open file
        NSError *error = nil;
        NSFileHandle *handle = [NSFileHandle fileHandleForReadingFromURL:url error:&error];
        if (!handle) {
            fprintf(stderr, "Error: Failed to open %s: %s\n",
                   config.filePath.UTF8String, error.localizedDescription.UTF8String);
            return EXIT_FAILURE;
        }

        // Process all entries
        NSArray<PLJEntry *> *allEntries = ProcessAllEntries(handle, payloadClass, config);
        [handle closeFile];

        if (!allEntries) {
            fprintf(stderr, "Error: Failed to process entries\n");
            return EXIT_FAILURE;
        }

        // Filter entries based on head/tail options
        NSArray<PLJEntry *> *filteredEntries = FilterEntries(allEntries, config);

        // Convert to JSON
        NSMutableArray *jsonEntries = [NSMutableArray arrayWithCapacity:filteredEntries.count];
        for (PLJEntry *entry in filteredEntries) {
            [jsonEntries addObject:EntryToJSON(entry)];
        }

        NSDictionary *output = @{
            @"file_path": config.filePath,
            @"payload_class": className,
            @"total_entries": @(allEntries.count),
            @"returned_entries": @(filteredEntries.count),
            @"entries": jsonEntries
        };

        // Output JSON
        NSError *jsonError = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:output
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:&jsonError];

        if (jsonError) {
            fprintf(stderr, "Error: Failed to serialize JSON: %s\n", jsonError.localizedDescription.UTF8String);
            return EXIT_FAILURE;
        }

        NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
        printf("%s\n", jsonString.UTF8String);
    }

    return EXIT_SUCCESS;
}