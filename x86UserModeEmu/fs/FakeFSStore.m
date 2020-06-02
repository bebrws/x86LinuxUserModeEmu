//
//  FakeFSStore.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/20/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "FakeFSStore.h"
#import "NSArray+Blocks.h"
#import "NSDictionary+Blocks.h"
#import "NSData+Base16.h"
#import "log.h"

@implementation FakeFSStore

static NSMutableDictionary *_pathToInode;
static NSMutableDictionary *_inodeToStat;

+ (void)setPathToInode:(NSMutableDictionary *)newPathToInode {
    _pathToInode = newPathToInode;
}

+ (void)setInodeToStat:(NSMutableDictionary *)newInodeToStat {
    _inodeToStat = newInodeToStat;
}

+ (NSMutableDictionary *)pathToInode {
    if (!_pathToInode) {
//        die("Should probably call load here. FakeFSStore had class properties accessed before load.");
        _pathToInode = [NSMutableDictionary new];
    }
    return _pathToInode;
}

+ (NSMutableDictionary *)inodeToStat {
    if (!_inodeToStat) {
//        die("Should probably call load here. FakeFSStore had class properties accessed before load.");
        _inodeToStat = [NSMutableDictionary new];
    }
    return _inodeToStat;
}

- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    [self load];
    
    return self;
}

- (NSArray *)getPathInodesAsNumbers {
    return [_pathToInode allValues];
}

- (NSArray *)getStatInodesAsNumbers {
    return [[_inodeToStat allValues] map:^(NSString *inodeString) {
     return [NSNumber numberWithLongLong:[inodeString longLongValue]];
    }];
}

- (NSArray *)getPaths {
    return [_pathToInode allKeys];
}

- (void)removeStatAndInodeForInode:(NSNumber *)inode {
    [[FakeFSStore inodeToStat] removeObjectForKey:[inode stringValue]];
}

- (void)updateStatDataForPath:(NSString *)path stat:(NSData *)stat {
    NSNumber *inode = [self getInodeForPath:path];
    NSString *statString = [stat base16EncodedStringWithOptions:NSDataBase16EncodingOptionsDefault];
    [self updateStatStringForInode:inode stat:statString];
}

- (void)updateStatDataForInode:(NSNumber *)inode stat:(NSData *)stat {
    NSString *statString = [stat base16EncodedStringWithOptions:NSDataBase16EncodingOptionsDefault];
    [[FakeFSStore inodeToStat] setValue:statString forKey:[inode stringValue]];
}

- (void)updateStatStringForPath:(NSString *)path stat:(NSString *)stat {
    NSNumber *inode = [self getInodeForPath:path];
    [self updateStatStringForInode:inode stat:stat];
}

- (void)updateStatStringForInode:(NSNumber *)inode stat:(NSString *)stat {
    [[FakeFSStore inodeToStat] setValue:stat forKey:[inode stringValue]];
}

- (void)updateInodeForPath:(NSString *)path inode:(NSNumber *)inode {
    [[FakeFSStore pathToInode] setValue:inode forKey:path];
}

- (NSNumber *)getNewInodeNumber {
    NSMutableSet *allInodes = [NSMutableSet setWithArray:[self getPathInodesAsNumbers]];
    [allInodes unionSet:[NSSet setWithArray:[self getStatInodesAsNumbers]]];
    
    NSNumber *last = [NSNumber numberWithInt:0];
    for (NSNumber *currentNumber in allInodes) {
        if ([currentNumber compare:last] == 1) {
            last = currentNumber;
        }
    }
    return [NSNumber numberWithLongLong:[last longLongValue] + 1];
}

- (NSNumber *)getInodeForPath:(NSString *)path {
    return [[FakeFSStore pathToInode] valueForKey:path];
}

- (NSArray *)getPathsForInode:(NSNumber *)inode {
    // If a file is hardlinked you could get multiple paths
    return [[FakeFSStore pathToInode] allKeysForObject:inode];
}


- (NSData *)getStatDataForPath:(NSString *)path {
    return [self getStatDataForInode:[self getInodeForPath:path]];
}

- (NSString *)getStatStringForPath:(NSString *)path {
    return [self getStatStringForInode:[self getInodeForPath:path]];
}

- (NSData *)getStatDataForInode:(NSNumber *)inode {
    NSString *statString = [[FakeFSStore inodeToStat] valueForKey:[inode stringValue]];
    if (!statString) {
        FFLog(@"Error: Missing inode and stat data for inode %@", [inode stringValue]);
        return nil;
    }
    return [[NSData alloc] initWithBase16EncodedString:statString options:NSDataBase16DecodingOptionsDefault];
}

- (NSString *)getStatStringForInode:(NSNumber *)inode {
    NSString *statString = [[FakeFSStore inodeToStat] valueForKey:[inode stringValue]];
    if (!statString) {
        FFLog(@"Error: Missing inode and stat data for inode %@", [inode stringValue]);
        return nil;
    }
    return statString;
}

- (NSString *)getJSON {
    NSError *writeError = nil;
    NSArray *pathToInodeArray = [[FakeFSStore pathToInode] map:^(NSString *key, NSNumber *value) {
        return [NSDictionary dictionaryWithObjectsAndKeys:key, @"path", value, @"inode", nil];
    }];
    
    NSArray *inodeToStatArray = [[FakeFSStore inodeToStat] map:^(NSString *key, NSString *value) {
        return [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithLongLong:[key longLongValue]], @"inode", value, @"stat", nil];
    }];
    
    NSDictionary *outDictionary = [NSDictionary dictionaryWithObjectsAndKeys:pathToInodeArray, @"pathInode", inodeToStatArray, @"inodeStat", nil];
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:outDictionary options:NSJSONWritingPrettyPrinted error:&writeError];
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
#if FSDEBBUG
    FFLog(@"JSON data for Fake FS DB:\n%@", jsonString);
#endif
    return jsonString;
}

- (void)save {
    NSString* alpineDataPath = [FakeFSStore getFakeFSFilePath];
    NSError *writeFileError;
    BOOL succeeded = [[self getJSON] writeToFile:alpineDataPath atomically:YES encoding:NSUTF8StringEncoding error:&writeFileError];
    if (writeFileError) {
        FFLog(@"Error: error occurred writing file for FakeFS JSON DB");
        die("File write error");
    }
#if FSDEBBUG
    if (succeeded) {
        FFLog(@"Successfully saved the FakeFS DB JSON file: %@", alpineDataPath);
    }
#endif
}

+ (NSString *)getFakeFSFilePath {
    NSArray *alpineDataPathArray = [NSArray arrayWithObjects:[NSBundle mainBundle].resourcePath, @"fakefs.json", nil];
    NSString* alpineDataPath = [NSString pathWithComponents:alpineDataPathArray];
    return alpineDataPath;
}

- (void)load {
    
    if (![[FakeFSStore pathToInode] count] && ![[FakeFSStore inodeToStat] count]) {
        NSString* alpineDataPath = [FakeFSStore getFakeFSFilePath];
//        NSURL *fakeFSJSONURL = [[NSURL alloc] initFileURLWithPath:alpineDataPath];
        NSError *fileLoadError;

        NSString *jsonForFakeFS = [NSString stringWithContentsOfFile:alpineDataPath encoding:NSUTF8StringEncoding error:&fileLoadError];
        
        if (!fileLoadError) {
            NSError *jsonError;
            NSDictionary *fakeFSDictioniary = [NSJSONSerialization JSONObjectWithData:[jsonForFakeFS dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:&jsonError];
            if (!jsonError)
            {
                FFLog(@"Successfully parsed JSON for the FakeFS DB from file: %@", alpineDataPath);
                NSArray *pathInodes = [fakeFSDictioniary valueForKey:@"pathInode"];
                for (NSDictionary *aPathInode in pathInodes) {
                    [[FakeFSStore pathToInode] setValue:[aPathInode valueForKey:@"inode"] forKey:[aPathInode valueForKey:@"path"]];
                }
                
                NSArray *inodeStats = [fakeFSDictioniary valueForKey:@"inodeStat"];
                for (NSDictionary *aInodeStat in inodeStats) {
                    NSNumber *inode = [aInodeStat valueForKey:@"inode"];
                    //                NSString *inodeKey = [NSString stringWithFormat:@"%@", inode];
                    NSString *statString = [aInodeStat valueForKey:@"stat"];
                    [[FakeFSStore inodeToStat] setValue:statString forKey:[inode stringValue]];
                    // NSData *statData = [[NSData alloc] initWithBase16EncodedString:statString options:NSDataBase16DecodingOptionsDefault];
                    // NSString *t = [statData base16EncodedStringWithOptions:NSDataBase16EncodingOptionsDefault];
                    // e ((const char*)statData.bytes)[2]
                    // [[FakeFSStore inodeToStat] setValue:statData forKey:[inode stringValue]];
                }
            }
            else {
                FFLog(@"Not dict");
            }
        }
    }
    
}

@end
