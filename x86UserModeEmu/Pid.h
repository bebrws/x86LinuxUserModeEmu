// This is all obviously from Ish

#import <Foundation/Foundation.h>
#import "Task.h"

@class Pid;

@interface Pid : NSObject {
// @public dword_t id;
}

    @property (nonatomic, assign) dword_t id;
    @property (nonatomic, strong) Task *task;
    @property (nonatomic, strong) NSMutableArray *session;
    @property (nonatomic, strong) NSMutableArray *pgroup;
    @property (nonatomic, assign) Boolean isEmpty;

    + (Task *)getTask:(dword_t)id includeZombie:(Boolean) includeZombie;
    + (id)getPid:(dword_t)id;
    + (Boolean)empty:(dword_t)id;
    - (id)init;
    - (void)clearSessionAndGroup;
@end

