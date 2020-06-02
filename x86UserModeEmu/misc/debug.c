//
//  debug.c
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/9/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#include <stdio.h>
#include "debug.h"


void die(const char *msg, ...) {
    // TODO Print out error message
    perror(msg);
    abort();
}
