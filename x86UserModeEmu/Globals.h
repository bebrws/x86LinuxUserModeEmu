#import <Foundation/Foundation.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#import "misc.h"

#import "Task.h"
#import "Pid.h"
#import "SigInfo.h"


#ifndef globals_h
#define globals_h

extern int xsave_extra;
extern int fxsave_extra;

//Task *current;
// extern NSMutableArray *pids;
extern NSMutableDictionary *pids;
//    //extern int cur_pid;
extern FileDescriptor *AT_PWD;
extern SigInfo *siginfo_nil;
//    //extern NSLock *pidLock;

size_t get_real_page_size();
id get_siginfo_nil();

// Just for debugging logging in CPU
extern NSLock *CPUStepLock;

#endif
