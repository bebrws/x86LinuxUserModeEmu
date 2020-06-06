//
//  Globals.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "Globals.h"
#include "Task.h"
#include "misc.h"
#import "SigInfo.h"
#import "SigHandler.h"
#import "SigQueue.h"
// TODO Remove this file
// Init the in AppDelegate
// And prob only need pids
//

int xsave_extra = 0;
int fxsave_extra = 0;

//Task *current;

NSMutableDictionary *pids;
SigInfo *siginfo_nil;

lock_t cpuStepLock;

lock_t pidsLock;


FileDescriptor *AT_PWD;

size_t get_real_page_size() {
    return sysconf(_SC_PAGESIZE);
}

id get_siginfo_nil() {
    if (!siginfo_nil) {
        siginfo_nil = [[SigInfo alloc] init];
        siginfo_nil->info.code = SI_KERNEL_;
    }
    
    return siginfo_nil;
}

void (*exit_hook)(Task *task, int code) = NULL;

void ios_handle_exit(Task *task, int code) {
    // we are interested in init and in children of init
    // this is called with pids_lock as an implementation side effect, please do not cite as an example of good API design
    if (task.parent != NULL && task.parent.parent != NULL)
        return;
    // pid should be saved now since task would be freed
    pid_t pid = task.pid.id;
//    dispatch_async(dispatch_get_main_queue(), ^{
//        [[NSNotificationCenter defaultCenter] postNotificationName:ProcessExitedNotification
//                                                            object:nil
//                                                          userInfo:@{@"pid": @(pid),
//                                                                     @"code": @(code)}];
//    });
}

