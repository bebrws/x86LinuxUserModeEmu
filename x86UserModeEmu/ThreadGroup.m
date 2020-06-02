//
//  ThreadGroup.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "ThreadGroup.h"
#import "sync.h"
#import "Task.h"

@implementation ThreadGroup

- (id)initWithLeaderTask:(Task *)task {
    self = [super init];
    if (self) {
        cond_init(&self->childExit);
        cond_init(&self->stoppedCond);
        self.leader = task;
    }
    return self;
}

-(NSString *)description {
    return [[NSString alloc] initWithFormat:@"LdrPid:%d doingGrpExit:%d grpCde:%d stpd?:%d", self.leader.pid.id, self.doingGroupExit, self.groupExitCode, self.stopped];
}

@end
