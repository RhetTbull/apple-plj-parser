#import <Foundation/Foundation.h>
#import <zlib.h>

@interface PLJournalEntryPayloadIDFactory : NSObject
+ (id)payloadIDWithUUIDString:(NSString *)uuidString;
+ (id)payloadIDWithString:(NSString *)string;
@end

@interface PLManagedObjectJournalEntryPayload : NSObject
+ (id)payloadWithData:(NSData *)data
         forPayloadID:(id)payloadID
              version:(unsigned int)version
     andNilProperties:(NSSet *)nilProperties
                error:(NSError **)error;
- (NSDictionary *)rawPayloadAttributes;
- (NSDictionary *)payloadAttributes;
@end

static BOOL ReadVarint(const uint8_t *bytes, NSUInteger length, NSUInteger *offset, uint64_t *value) {
    uint64_t result = 0;
    NSUInteger shift = 0;
    while (*offset < length && shift <= 63) {
        uint8_t b = bytes[(*offset)++];
        result |= (uint64_t)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            *value = result;
            return YES;
        }
        shift += 7;
    }
    return NO;
}

static BOOL SkipField(const uint8_t *bytes, NSUInteger length, NSUInteger *offset, uint32_t wireType) {
    switch (wireType) {
        case 0: {
            uint64_t ignored = 0;
            return ReadVarint(bytes, length, offset, &ignored);
        }
        case 1: {
            if (*offset + 8 > length) {
                return NO;
            }
            *offset += 8;
            return YES;
        }
        case 2: {
            uint64_t len = 0;
            if (!ReadVarint(bytes, length, offset, &len)) {
                return NO;
            }
            if (*offset + len > length) {
                return NO;
            }
            *offset += (NSUInteger)len;
            return YES;
        }
        case 5: {
            if (*offset + 4 > length) {
                return NO;
            }
            *offset += 4;
            return YES;
        }
        case 3: {
            // Skip group recursively until matching end-group (wire type 4)
            while (*offset < length) {
                uint64_t key = 0;
                if (!ReadVarint(bytes, length, offset, &key)) {
                    return NO;
                }
                uint32_t wt = (uint32_t)(key & 0x7);
                if (wt == 4) {
                    return YES;
                }
                if (!SkipField(bytes, length, offset, wt)) {
                    return NO;
                }
            }
            return NO;
        }
        default:
            return NO;
    }
}

static NSDictionary<NSString *, NSString *> *PayloadClassMap(void) {
    static NSDictionary<NSString *, NSString *> *map;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        map = @{ @"Asset" : @"PLAssetJournalEntryPayload",
                 @"Album" : @"PLAlbumJournalEntryPayload",
                 @"DeferredRebuildFace" : @"PLDeferredRebuildFaceJournalEntryPayload",
                 @"DetectedFace" : @"PLDetectedFaceJournalEntryPayload",
                 @"FetchingAlbum" : @"PLFetchingAlbumJournalEntryPayload",
                 @"FileSystemVolume" : @"PLFileSystemVolumeJournalEntryPayload",
                 @"Folder" : @"PLFolderJournalEntryPayload",
                 @"ImportSession" : @"PLImportSessionJournalEntryPayload",
                 @"Keyword" : @"PLKeywordJournalEntryPayload",
                 @"Memory" : @"PLMemoryJournalEntryPayload",
                 @"MigrationHistory" : @"PLMigrationHistoryJournalEntryPayload",
                 @"Person" : @"PLPersonJournalEntryPayload",
                 @"ProjectAlbum" : @"PLProjectAlbumJournalEntryPayload",
                 @"SocialGroup" : @"PLSocialGroupJournalEntryPayload" };
    });
    return map;
}

static NSString *DefaultPayloadClassNameForURL(NSURL *url) {
    NSString *stem = [[url lastPathComponent] stringByDeletingPathExtension];
    if ([stem hasSuffix:@"-change"]) {
        stem = [stem substringToIndex:stem.length - 7];
    } else if ([stem hasSuffix:@"-snapshot"]) {
        stem = [stem substringToIndex:stem.length - 9];
    }
    return PayloadClassMap()[stem];
}

static BOOL ParseHeader(NSData *headerData,
                        uint64_t *entryType,
                        NSData *__autoreleasing *payloadUUID,
                        NSString *__autoreleasing *payloadIDString,
                        uint64_t *payloadVersion,
                        uint64_t *payloadLength,
                        uint32_t *payloadCRC,
                        NSMutableArray<NSString *> *nilProperties,
                        NSError **error) {
    const uint8_t *bytes = headerData.bytes;
    NSUInteger length = headerData.length;
    NSUInteger offset = 0;

    while (offset < length) {
        uint64_t key = 0;
        if (!ReadVarint(bytes, length, &offset, &key)) {
            if (error) {
                *error = [NSError errorWithDomain:@"PLJDump" code:1 userInfo:@{NSLocalizedDescriptionKey : @"Failed to read header key"}];
            }
            return NO;
        }
        uint32_t fieldNumber = (uint32_t)(key >> 3);
        uint32_t wireType = (uint32_t)(key & 0x7);

        switch (fieldNumber) {
            case 1: { // entryType
                if (wireType != 0) {
                    if (!SkipField(bytes, length, &offset, wireType)) {
                        return NO;
                    }
                    break;
                }
                uint64_t value = 0;
                if (!ReadVarint(bytes, length, &offset, &value)) {
                    if (error) {
                        *error = [NSError errorWithDomain:@"PLJDump" code:2 userInfo:@{NSLocalizedDescriptionKey : @"Failed to read entryType"}];
                    }
                    return NO;
                }
                if (entryType) {
                    *entryType = value;
                }
                break;
            }
            case 2: { // payloadUUID
                if (wireType != 2) {
                    if (!SkipField(bytes, length, &offset, wireType)) {
                        return NO;
                    }
                    break;
                }
                uint64_t len = 0;
                if (!ReadVarint(bytes, length, &offset, &len) || offset + len > length) {
                    if (error) {
                        *error = [NSError errorWithDomain:@"PLJDump" code:3 userInfo:@{NSLocalizedDescriptionKey : @"Invalid payloadUUID"}];
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
                    if (!SkipField(bytes, length, &offset, wireType)) {
                        return NO;
                    }
                    break;
                }
                uint64_t len = 0;
                if (!ReadVarint(bytes, length, &offset, &len) || offset + len > length) {
                    if (error) {
                        *error = [NSError errorWithDomain:@"PLJDump" code:4 userInfo:@{NSLocalizedDescriptionKey : @"Invalid payloadID"}];
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
                    if (!SkipField(bytes, length, &offset, wireType)) {
                        return NO;
                    }
                    break;
                }
                uint64_t value = 0;
                if (!ReadVarint(bytes, length, &offset, &value)) {
                    if (error) {
                        *error = [NSError errorWithDomain:@"PLJDump" code:5 userInfo:@{NSLocalizedDescriptionKey : @"Failed to read payloadVersion"}];
                    }
                    return NO;
                }
                if (payloadVersion) {
                    *payloadVersion = value;
                }
                break;
            }
            case 5: { // payloadLength
                if (wireType != 0) {
                    if (!SkipField(bytes, length, &offset, wireType)) {
                        return NO;
                    }
                    break;
                }
                uint64_t value = 0;
                if (!ReadVarint(bytes, length, &offset, &value)) {
                    if (error) {
                        *error = [NSError errorWithDomain:@"PLJDump" code:6 userInfo:@{NSLocalizedDescriptionKey : @"Failed to read payloadLength"}];
                    }
                    return NO;
                }
                if (payloadLength) {
                    *payloadLength = value;
                }
                break;
            }
            case 6: { // payloadCRC
                if (wireType != 0) {
                    if (!SkipField(bytes, length, &offset, wireType)) {
                        return NO;
                    }
                    break;
                }
                uint64_t value = 0;
                if (!ReadVarint(bytes, length, &offset, &value)) {
                    if (error) {
                        *error = [NSError errorWithDomain:@"PLJDump" code:7 userInfo:@{NSLocalizedDescriptionKey : @"Failed to read payloadCRC"}];
                    }
                    return NO;
                }
                if (payloadCRC) {
                    *payloadCRC = (uint32_t)value;
                }
                break;
            }
            case 7: { // nil property name
                if (wireType != 2) {
                    if (!SkipField(bytes, length, &offset, wireType)) {
                        return NO;
                    }
                    break;
                }
                uint64_t len = 0;
                if (!ReadVarint(bytes, length, &offset, &len) || offset + len > length) {
                    if (error) {
                        *error = [NSError errorWithDomain:@"PLJDump" code:8 userInfo:@{NSLocalizedDescriptionKey : @"Invalid nil property"}];
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
                        *error = [NSError errorWithDomain:@"PLJDump" code:9 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Unsupported field %u", fieldNumber]}];
                    }
                    return NO;
                }
            }
        }
    }

    return YES;
}

static id BuildPayloadIdentifier(NSData *uuidData, NSString *stringID) {
    if (uuidData.length == 16) {
        uuid_t uuidBytes;
        [uuidData getBytes:uuidBytes length:sizeof(uuidBytes)];
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDBytes:uuidBytes];
        return [PLJournalEntryPayloadIDFactory payloadIDWithUUIDString:uuid.UUIDString];
    } else if (stringID.length > 0) {
        return [PLJournalEntryPayloadIDFactory payloadIDWithString:stringID];
    }
    return nil;
}

static NSDictionary *RawPayloadAttributes(id payload) {
    if ([payload respondsToSelector:@selector(rawPayloadAttributes)]) {
        return [payload valueForKey:@"rawPayloadAttributes"];
    }
    if ([payload respondsToSelector:@selector(payloadAttributes)]) {
        return [payload valueForKey:@"payloadAttributes"];
    }
    return nil;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            fprintf(stderr, "Usage: %s <path to .plj> [PayloadClassName]\n", argv[0]);
            return EXIT_FAILURE;
        }

        NSString *path = [NSString stringWithUTF8String:argv[1]];
        NSURL *url = [NSURL fileURLWithPath:path];

        NSString *className = nil;
        if (argc >= 3) {
            className = [NSString stringWithUTF8String:argv[2]];
        } else {
            className = DefaultPayloadClassNameForURL(url);
        }

        if (className.length == 0) {
            fprintf(stderr, "Unable to infer payload class for %s. Provide it explicitly.\n", argv[1]);
            return EXIT_FAILURE;
        }

        Class payloadClass = NSClassFromString(className);
        if (!payloadClass) {
            fprintf(stderr, "Payload class %s is unavailable.\n", className.UTF8String);
            return EXIT_FAILURE;
        }

        NSError *error = nil;
        NSFileHandle *handle = [NSFileHandle fileHandleForReadingFromURL:url error:&error];
        if (!handle) {
            fprintf(stderr, "Failed to open %s: %s\n", argv[1], error.localizedDescription.UTF8String);
            return EXIT_FAILURE;
        }

        uint64_t entryIndex = 0;
        while (true) {
            NSData *prefix = [handle readDataOfLength:5];
            if (prefix.length == 0) {
                break; // EOF
            }
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

            uint64_t entryType = 0;
            uint64_t payloadVersion = 0;
            uint64_t payloadLength = 0;
            uint32_t payloadCRC = 0;
            NSData *payloadUUID = nil;
            NSString *payloadIDString = nil;
            NSMutableArray<NSString *> *nilProperties = [NSMutableArray array];

            if (!ParseHeader(headerData,
                              &entryType,
                              &payloadUUID,
                              &payloadIDString,
                              &payloadVersion,
                              &payloadLength,
                              &payloadCRC,
                              nilProperties,
                              &error)) {
                fprintf(stderr, "Failed to parse header for entry %llu: %s\n",
                        entryIndex,
                        error.localizedDescription.UTF8String);
                break;
            }

            NSData *payloadData = [handle readDataOfLength:(NSUInteger)payloadLength];
            if (payloadData.length < payloadLength) {
                fprintf(stderr, "Truncated payload at entry %llu\n", entryIndex);
                break;
            }

            uint32_t computedCRC = (uint32_t)crc32(0L, payloadData.bytes, (uInt)payloadData.length);
            BOOL crcMatches = (payloadData.length == 0) || (computedCRC == payloadCRC);

            id payloadIdentifier = BuildPayloadIdentifier(payloadUUID, payloadIDString);
            NSSet<NSString *> *nilPropsSet = nilProperties.count ? [NSSet setWithArray:nilProperties] : nil;
            NSError *payloadError = nil;
            id payload = nil;
            if (payloadData.length > 0 && payloadIdentifier) {
                payload = [payloadClass payloadWithData:payloadData
                                            forPayloadID:payloadIdentifier
                                                 version:(unsigned int)payloadVersion
                                       andNilProperties:nilPropsSet
                                                   error:&payloadError];
            }

            NSLog(@"Entry %llu -- type:%llu version:%llu payloadLength:%llu crc:%#x checksum:%#x matches:%@",
                  entryIndex,
                  entryType,
                  payloadVersion,
                  payloadLength,
                  payloadCRC,
                  headerChecksum,
                  crcMatches ? @"YES" : @"NO");

            if (nilProperties.count > 0) {
                NSLog(@"  nilProperties: %@", nilProperties);
            }
            if (payloadError) {
                NSLog(@"  payload decode error: %@", payloadError);
            } else if (payload) {
                NSDictionary *attributes = RawPayloadAttributes(payload);
                if (attributes.count > 0) {
                    NSLog(@"  attributes: %@", attributes);
                } else {
                    NSLog(@"  payload: %@", payload);
                }
            }

            entryIndex++;
        }

        [handle closeFile];
    }

    return EXIT_SUCCESS;
}
