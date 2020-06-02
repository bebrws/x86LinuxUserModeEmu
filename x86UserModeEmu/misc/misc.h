//
//  misc.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//
#ifdef __OBJC__
#import <Foundation/Foundation.h>
#else
#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <objc/message.h>
#endif

#include <stdint.h>

#ifndef misc_h
#define misc_h

// utility macros
#define glue(a, b) _glue(a, b)
#define _glue(a, b) a##b
#define glue3(a,b,c) glue(a, glue(b, c))
#define glue4(a,b,c,d) glue(a, glue3(b, c, d))

#define str(x) _str(x)
#define _str(x) #x


#define wrlock_destroy(lock) pthread_rwlock_destroy(lock)
#define read_wrlock(lock) pthread_rwlock_rdlock(lock)
#define read_wrunlock(lock) pthread_rwlock_unlock(lock)
#define write_wrlock(lock) pthread_rwlock_wrlock(lock)
#define write_wrunlock(lock) pthread_rwlock_unlock(lock)


typedef int64_t sqword_t;
typedef uint64_t qword_t;
typedef uint32_t dword_t;
typedef int32_t sdword_t;
typedef uint16_t word_t;
typedef uint8_t byte_t;

typedef dword_t addr_t;
typedef dword_t uint_t;
typedef sdword_t int_t;

typedef sdword_t pid_t_;
typedef dword_t uid_t_;
typedef word_t mode_t_;
typedef sqword_t off_t_;
typedef dword_t time_t_;
typedef dword_t clock_t_;

typedef dword_t pages_t;
typedef dword_t page_t;

typedef int (*syscall_t)(dword_t, dword_t, dword_t, dword_t, dword_t, dword_t);


// Signals:

typedef qword_t sigset_t_;

#define SIG_ERR_ -1
#define SIG_DFL_ 0
#define SIG_IGN_ 1

#define SA_SIGINFO_ 4
#define SA_NODEFER_ 0x40000000

#define NUM_SIGS 64

#define    SIGHUP_    1
#define    SIGINT_    2
#define    SIGQUIT_   3
#define    SIGILL_    4
#define    SIGTRAP_   5
#define    SIGABRT_   6
#define    SIGIOT_    6
#define    SIGBUS_    7
#define    SIGFPE_    8
#define    SIGKILL_   9
#define    SIGUSR1_   10
#define    SIGSEGV_   11
#define    SIGUSR2_   12
#define    SIGPIPE_   13
#define    SIGALRM_   14
#define    SIGTERM_   15
#define    SIGSTKFLT_ 16
#define    SIGCHLD_   17
#define    SIGCONT_   18
#define    SIGSTOP_   19
#define    SIGTSTP_   20
#define    SIGTTIN_   21
#define    SIGTTOU_   22
#define    SIGURG_    23
#define    SIGXCPU_   24
#define    SIGXFSZ_   25
#define    SIGVTALRM_ 26
#define    SIGPROF_   27
#define    SIGWINCH_  28
#define    SIGIO_     29
#define    SIGPWR_    30
#define SIGSYS_    31

#define SI_USER_ 0
#define SI_TIMER_ -2
#define SI_TKILL_ -6
#define SI_KERNEL_ 128
#define SEGV_MAPERR_ 1
#define SEGV_ACCERR_ 2


#define SIGNAL_IGNORE 0
#define SIGNAL_KILL 1
#define SIGNAL_CALL_HANDLER 2
#define SIGNAL_STOP 3



typedef struct {
    int_t sig;
    int_t sig_errno;
    int_t code;
    
    union {
        struct {
            pid_t_ pid;
            uid_t_ uid;
        } kill;
        struct {
            pid_t_ pid;
            uid_t_ uid;
            int_t status;
            clock_t_ utime;
            clock_t_ stime;
        } child;
        struct {
            addr_t addr;
        } fault;
        struct {
            addr_t addr;
            int_t syscall;
        } sigsys;
    };
} siginfo_; // Ending in an underscore to notate that this is not the official unix based siginfo struct


// void *formatNSString (void **dest, void *format, ...);

#endif /* misc_h */
