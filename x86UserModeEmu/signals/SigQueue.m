//
//  SigQueue.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

// Each Task will have a SigQueue which will be a list of signals queued up for a task
// The list that the SigQueue contains is of the SigInfo Struct/Class type

#import "SigQueue.h"
#import "SigInfo.h"

@implementation SigQueue

- (id)init {
    self = [super init];
    if (self) {
        self.queue = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void)add:(SigInfo *)sigInfo {
    [self.queue addObject:sigInfo];
}

- (void)remove:(SigInfo *)sigInfo {
    [self.queue removeObject:sigInfo];
}

- (void)removeAtIndex:(int)index {
    [self.queue removeObjectAtIndex:index];
}

-(NSString *)description {
    NSMutableString *ms = [@"" mutableCopy];
    int i = 0;
    for (SigInfo *si in self.queue) {
        [ms appendFormat:@"%d - %@ ", i, si];
        i++;
    }
    return ms;
}


@end
