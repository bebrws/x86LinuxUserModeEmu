//
//  ThreadGroup.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "misc.h"
#import "Task.h"
#import "sys/sync.h"
#import "time.h"

#ifndef thread_group_H
#define thread_group_H


// ---------- Resources
#define RLIMIT_CPU_ 0
#define RLIMIT_FSIZE_ 1
#define RLIMIT_DATA_ 2
#define RLIMIT_STACK_ 3
#define RLIMIT_CORE_ 4
#define RLIMIT_RSS_ 5
#define RLIMIT_NPROC_ 6
#define RLIMIT_NOFILE_ 7
#define RLIMIT_MEMLOCK_ 8
#define RLIMIT_AS_ 9
#define RLIMIT_LOCKS_ 10
#define RLIMIT_SIGPENDING_ 11
#define RLIMIT_MSGQUEUE_ 12
#define RLIMIT_NICE_ 13
#define RLIMIT_RTPRIO_ 14
#define RLIMIT_RTTIME_ 15
#define RLIMIT_NLIMITS_ 16

#define RUSAGE_SELF_ 0
#define RUSAGE_CHILDREN_ -1

#define RLIM_INFINITY_ ((rlim_t_) -1)


typedef qword_t rlim_t_;
typedef dword_t rlim32_t_;

struct rlimit_ {
    rlim_t_ cur;
    rlim_t_ max;
};

struct rlimit32_ {
    rlim32_t_ cur;
    rlim32_t_ max;
};

struct rusage_ {
    struct timeval_ utime;
    struct timeval_ stime;
    dword_t maxrss;
    dword_t ixrss;
    dword_t idrss;
    dword_t isrss;
    dword_t minflt;
    dword_t majflt;
    dword_t nswap;
    dword_t inblock;
    dword_t oublock;
    dword_t msgsnd;
    dword_t msgrcv;
    dword_t nsignals;
    dword_t nvcsw;
    dword_t nivcsw;
};

//typedef struct {
//    struct timeval_ utime;
//    struct timeval_ stime;
//    dword_t maxrss;
//    dword_t ixrss;
//    dword_t idrss;
//    dword_t isrss;
//    dword_t minflt;
//    dword_t majflt;
//    dword_t nswap;
//    dword_t inblock;
//    dword_t oublock;
//    dword_t msgsnd;
//    dword_t msgrcv;
//    dword_t nsignals;
//    dword_t nvcsw;
//    dword_t nivcsw;
//} rusage_;



// Process Groups and Sessions:
// https://stackoverflow.com/questions/6548823/use-and-meaning-of-session-and-process-group-in-unix
// A process group is a collection of related processes which can all be signalled at once.
//
// A session is a collection of process groups, which are either attached to a single terminal device
// (known as the controlling terminal) or not attached to any terminal.
//

@class Task;

@interface ThreadGroup : NSObject {
    
    // locked by pids_lock
    @public pid_t_ sid;
    @public pid_t pgid;
    
    @public cond_t stoppedCond;
    
    @public struct tty *tty;
    @public struct timer *timer;
    
    @public struct rlimit_ limits[RLIMIT_NLIMITS_];

    
    @public struct rusage_ childrenRusage;
    @public cond_t childExit;
    
    @public lock_t lock;
    @public cond_t cond;
    
    @public struct rusage_ rusage;
}

@property (nonatomic, assign) BOOL stopped;
@property (nonatomic, assign) dword_t groupExitCode;
@property (nonatomic, assign) BOOL doingGroupExit;
@property (nonatomic, strong) NSMutableArray *session; // TODO: Correct? List of processes in the same session
@property (nonatomic, strong) NSMutableArray *pgroup;  // TODO: Correct? List of processes in the same group
@property (nonatomic, strong) NSMutableArray *threads; // locked by pids_lock, by majority vote This is an array of Tasks
@property (nonatomic, strong) Task *leader;     // This is immutable - "POSIX prohibits the change of the process group
                                                // ID of a session leader." - https://en.wikipedia.org/wiki/Process_group

- (id)initWithLeaderTask:(Task *)task;

@end


#endif
