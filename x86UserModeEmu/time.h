//
//  time.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#ifndef time_h
#define time_h

#define CLOCK_REALTIME_ 0
#define CLOCK_MONOTONIC_ 1
#define CLOCK_PROCESS_CPUTIME_ID_ 2


struct timeval_ {
    dword_t sec;
    dword_t usec;
};
struct timespec_ {
    dword_t sec;
    dword_t nsec;
};
struct timezone_ {
    dword_t minuteswest;
    dword_t dsttime;
};


#define ITIMER_REAL_ 0
#define ITIMER_VIRTUAL_ 1
#define ITIMER_PROF_ 2
struct itimerval_ {
    struct timeval_ interval;
    struct timeval_ value;
};

struct itimerspec_ {
    struct timespec_ interval;
    struct timespec_ value;
};

struct tms_ {
    clock_t_ tms_utime;  /* user time */
    clock_t_ tms_stime;  /* system time */
    clock_t_ tms_cutime; /* user time of children */
    clock_t_ tms_cstime; /* system time of children */
};


static inline clock_t_ clock_from_timeval(struct timeval_ timeval) {
    return timeval.sec * 100 + timeval.usec / 10000;
}



#endif /* time_h */

