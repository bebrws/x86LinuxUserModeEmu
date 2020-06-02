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
// NSMutableArray *pids;
NSMutableDictionary *pids;
SigInfo *siginfo_nil;
NSLock *CPUStepLock;
//NSLock *pidLock;
//
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

