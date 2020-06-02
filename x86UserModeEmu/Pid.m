#import <Foundation/Foundation.h>
#include <stddef.h>
#include "misc.h"
#import "Pid.h"

#include "Globals.h"

@implementation Pid

- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.isEmpty = true;
    [self clearSessionAndGroup];
    return self;
}

- (void)clearSessionAndGroup {
    self.session = [NSMutableArray new];
    self.pgroup  = [NSMutableArray new];
}

+ (Boolean)empty:(dword_t)id {
    NSString *pidKey = [NSString stringWithFormat:@"%d", id];
    Pid *p = [pids objectForKey:pidKey];
    if (!p) {
        return true;
    }
    
    return p.isEmpty;
}

+ (id)getPid:(dword_t)id {
    NSString *pidKey = [NSString stringWithFormat:@"%d", id];
    Pid *p = [pids objectForKey:pidKey];
    if (p) {
        return p;
    } else {
        Pid *newPid = [Pid init];
        [pids setValue:newPid forKey:pidKey];
        return newPid;
    }
}

+ (Task *)getTask:(dword_t)id includeZombie:(Boolean) includeZombie {
    NSString *pidKey = [NSString stringWithFormat:@"%d", id];
    Pid *p = [pids objectForKey:pidKey];
    
    if (p) {
        if (p.task->zombie && !includeZombie) {
            return nil;
        }
        return p.task;
    } else {
        return nil;
    }
}

-(NSString *)description {
    return [NSString stringWithFormat:@"Pid:%d PGroup:%@ Session:%@", self.id, self.pgroup, self.session];
}

@end
