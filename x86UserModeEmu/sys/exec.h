//
//  exec.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#ifndef exec_h
#define exec_h

#include <stdio.h>
#include "misc.h"

dword_t sys_execve(addr_t file, addr_t argv, addr_t envp);

#endif /* exec_h */
