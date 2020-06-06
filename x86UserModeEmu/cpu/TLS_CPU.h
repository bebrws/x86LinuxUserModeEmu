//
//  TLS_CPU.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 6/5/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "CPU.h"
#import "debug.h"
#import "errno.h"

typedef struct user_desc {
    dword_t entry_number;
    dword_t base_addr;
    dword_t limit;
    unsigned int seg_32bit:1;
    unsigned int contents:2;
    unsigned int read_exec_only:1;
    unsigned int limit_in_pages:1;
    unsigned int seg_not_present:1;
    unsigned int useable:1;
} user_desc;

NS_ASSUME_NONNULL_BEGIN

@interface CPU ()

- (uint32_t)taskSetThreadArea:(addr_t) u_info_addr {
    user_desc info;
    if ([self.task userRead:u_info_addr buf:&info count:sizeof(info)]) {
        return _EFAULT;
    }
    
    self->state.tls_ptr = info.base_addr;
    
}

- (uint32_t)sysSetThreadArea:(addr_t) u_info_addr {
    
}

@end

NS_ASSUME_NONNULL_END
