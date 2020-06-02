//
//  FakeFSStore.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/20/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface FakeFSStore : NSObject

@property (class) NSMutableDictionary *pathToInode;
@property (class) NSMutableDictionary *inodeToStat;

- (NSNumber *)getNewInodeNumber;
- (NSData *)getStatDataForPath:(NSString *)path;
- (NSString *)getStatStringForPath:(NSString *)path;
- (void)save;
- (NSString *)getJSON;
- (void)removeStatAndInodeForInode:(NSNumber *)inode;
- (NSArray *)getPathInodesAsNumbers;
- (NSArray *)getStatInodesAsNumbers;
- (NSArray *)getPaths;
+ (void)setPathToInode:(NSMutableDictionary *)newPathToInode;
+ (void)setInodeToStat:(NSMutableDictionary *)newInodeToStat;
+ (NSMutableDictionary *)pathToInode;
+ (NSMutableDictionary *)inodeToStat;

- (void)updateStatDataForPath:(NSString *)path stat:(NSData *)stat;
- (void)updateStatDataForInode:(NSNumber *)inode stat:(NSData *)stat;
- (void)updateStatStringForPath:(NSString *)path stat:(NSString *)stat;
- (void)updateStatStringForInode:(NSNumber *)inode stat:(NSString *)stat;
- (void)updateInodeForPath:(NSString *)path inode:(NSNumber *)inode;
- (NSNumber *)getInodeForPath:(NSString *)path;

- (NSArray *)getPathsForInode:(NSNumber *)inode;

- (NSData *)getStatDataForInode:(NSNumber *)inode;
- (NSString *)getStatStringForInode:(NSNumber *)inode;
- (void)load;
- (id)init;

@end
