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
    
    // https://man7.org/linux/man-pages/man2/set_thread_area.2.html
    // When set_thread_area() is passed an entry_number of -1, it searches
    // for a free TLS entry.  If set_thread_area() finds a free TLS entry,
    // the value of u_info->entry_number is set upon return to show which
    // entry was changed.
    //
    // So here we are just picking a random entry in the not implemented TLS
    // entry array to mark this as
    if (info.entry_number == -1) {
        info.entry_number = 0xc; // 0xc could probably be anything within bounds of whatever the TLS array size is
    }
    
    // Then write back any changes, like the entry number, back into the processes virtual memory
    if ([self.task userWrite:u_info_addr buf:&info count:sizeof(info)]) {
        return _EFAULT;
    }
    
    return 0;
    
}


- (uint32_t)sysSetThreadArea:(addr_t) u_info_addr {
    // u_info_addr is an address to a user_desc struct in a processes virtual memory
    // the base_addr is saved in a processes' tls_ptr attribute and whenever opcode 0x65 is used
    // meaning use the special GS segment, then the tls_ptr is added to the current addr variable and
    // the next opcode is parsed and executed
    return [self taskSetThreadArea:u_info_addr];
}

// The TID address is where, when a new thread is created (depending on if the CLONE_CHILD_SETTID flag is set),
// the thread id will be written to. If the CLONE_CHILD_CLEARTID flag is set then 0 is written to the address
// upon termination along with a few more steps mentioned:
// https://www.man7.org/linux/man-pages/man2/set_tid_address.2.html
- (uint32_t)sysSetTIDAddress:(addr_t) tid_addr {
    self->task->clear_tid = tid_addr;
    return self.task.pid.id;
}

@end

NS_ASSUME_NONNULL_END
