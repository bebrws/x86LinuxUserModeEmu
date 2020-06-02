//
//  syscalls.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "syscalls.h"
#include "misc.h"
#include "sys/exec.h"

syscall_t syscall_table[] = {
    [11]  = (syscall_t) sys_execve,
};
