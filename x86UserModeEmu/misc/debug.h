//
//  debug.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/4/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>

#ifndef debug_h
#define debug_h


#if defined(__i386__) || defined(__x86_64__)
#define debugger __asm__("int3")
#else
#include <signal.h>
#define debugger raise(SIGTRAP)
#endif

_Noreturn void die(const char *msg, ...);

#define ERRNO_DIE(msg) { perror(msg); abort(); }

#endif /* debug_h */
