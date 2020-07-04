// For debugging in lldb:
// e (Task *)([Pid getTask:1 includeZombie:true]).cpu.ishDebugState
// po (Task *)([Pid getTask:1 includeZombie:true]).cpu.ishDebugState[@"63"]
//

#include <signal.h>
#import "CPU.h"
#import "Task.h"
#import "MappedMemory.h"
#import "Memory.h"
#import "PageTableEntry.h"
#import "Globals.h"
#import "misc.h"
#import "debug.h"
#import "log.h"
#include "errno.h"
#include "Globals.h"
#include <stdio.h>

#import "cpuid.h"

#define NO_ERR_UN_IMP FFLog("\n\nNo error unimplemented opcode 0x9b");
// Resumable programmable breakpoint
// From
// https://stackoverflow.com/questions/44140778/resumable-assert-breakpoint-on-ios-like-debugbreak-with-ms-compiler

#include <unistd.h>
#if defined(__APPLE__) && defined(__aarch64__)
#define __debugbreak() __asm__ __volatile__ (            \
        "   mov    x0, %x0;    \n" /* pid                */ \
        "   mov    x1, #0x11;  \n" /* SIGSTOP            */ \
        "   mov    x16, #0x25; \n" /* syscall 37 = kill  */ \
        "   svc    #0x80       \n" /* software interrupt */ \
        "   mov    x0, x0      \n" /* nop                */ \
        : :  "r" (getpid())                                   \
        :   "x0", "x1", "x16", "memory")
#elif defined(__APPLE__) && defined(__arm__)
#define __debugbreak() __asm__ __volatile__ (            \
        "   mov    r0, %0;     \n" /* pid                */ \
        "   mov    r1, #0x11;  \n" /* SIGSTOP            */ \
        "   mov    r12, #0x25; \n" /* syscall 37 = kill  */ \
        "   svc    #0x80       \n" /* software interrupt */ \
        "   mov    r0, r0      \n" /* nop                */ \
        : :  "r" (getpid())                                   \
        :   "r0", "r1", "r12", "memory")
#elif defined(__APPLE__) && (defined(__i386__) || defined(__x86_64__))
#define __debugbreak() __asm__ __volatile__ ("int $3; mov %eax, %eax")
#endif


#define DBADDR(addr)   if (self->state.eip == addr) { __debugbreak(); /*__builtin_trap();*/ }
#define SEGFAULT     self->state.eip = saved_ip; self->state.segfault_addr = self->state.esp - 32 / 8; return INT_GPF;

// Used by Group1Opcodes.h :
#define UNDEFINED_OP self->state.eip = saved_ip; return INT_UNDEFINED;

@class MappedMemory;
@class Memory;
@class PageTableEntry;

@implementation CPU

// ########################################### HANDLE INTERRUPT



- (uint32_t) sys_exit:(uint32_t)status {
    STRACE("exit(%d)\n", status);
    [self.task doExit:status << 8];
    // Shouldn't get here due ot the pthread_exit in do_exit
    return 0;
}

- (uint32_t) sys_setresuid:(uid_t_)ruid euid:(uid_t_)euid suid:(uid_t_)suid {
    STRACE("setresuid(%d, %d, %d)", ruid, euid, suid);
    if (self.task->euid != 0) { // If not superuser
        if (ruid != (uid_t) -1 && ruid != self.task->uid && ruid != self.task->euid && ruid != self.task->suid)
            return _EPERM;
        if (euid != (uid_t) -1 && euid != self.task->uid && euid != self.task->euid && euid != self.task->suid)
            return _EPERM;
        if (suid != (uid_t) -1 && suid != self.task->uid && suid != self.task->euid && suid != self.task->suid)
            return _EPERM;
    }
    
    if (ruid != (uid_t) -1) {
        self.task->uid = ruid;
    }
    if (euid != (uid_t) -1) {
        self.task->euid = euid;
    }
    if (suid != (uid_t) -1) {
        self.task->suid = suid;
    }
    return 0;
}

- (uint32_t) sys_getresuid:(addr_t)ruid_addr euid_addr:(addr_t)euid_addr suid_addr:(addr_t)suid_addr {
    STRACE("getresuid(%#x, %#x, %#x)", ruid_addr, euid_addr, suid_addr);
    
    if ([self.task userWrite:ruid_addr buf:self.task->uid count:sizeof(self.task->uid)]) {
        return _EFAULT;
    }
    if ([self.task userWrite:euid_addr buf:self.task->euid count:sizeof(self.task->euid)]) {
        return _EFAULT;
    }
    if ([self.task userWrite:suid_addr buf:self.task->suid count:sizeof(self.task->suid)]) {
        return _EFAULT;
    }
    return 0;
}

- (uint32_t) sys_getgid32 {
    STRACE("getgid32()");
    return self.task->gid;
}
- (uint32_t) sys_getgid {
    STRACE("getgid()");
    return self.task->gid & 0xffff;
}

- (uint32_t) sys_getegid32 {
    STRACE("getegid32()");
    return self.task->egid;
}
- (uint32_t) sys_getegid {
    STRACE("getegid()");
    return self.task->egid & 0xffff;
}

- (uint32_t) sys_setgid:(uid_t_)gid {
    STRACE("setgid(%d)", gid);
    if (self.task->euid == 0) { // If superuser
        self.task->gid = self.task->sgid = gid;
    } else {
        if (gid != self.task->gid && gid != self.task->sgid)
            return _EPERM;
    }
    self.task->egid = gid;
    return 0;
}

- (uint32_t) sys_setresgid:(uid_t_)rgid egid:(uid_t_)egid sgid:(uid_t_)sgid {
    STRACE("setresgid(%d, %d, %d)", rgid, egid, sgid);
    if (self.task->euid != 0) { // If not superuser
        if (rgid != (uid_t) -1 && rgid != self.task->gid && rgid != self.task->egid && rgid != self.task->sgid) {
            return _EPERM;
        }
        if (egid != (uid_t) -1 && egid != self.task->gid && egid != self.task->egid && egid != self.task->sgid) {
            return _EPERM;
        }
        if (sgid != (uid_t) -1 && sgid != self.task->gid && sgid != self.task->egid && sgid != self.task->sgid) {
            return _EPERM;
        }
    }
    
    if (rgid != (uid_t) -1) {
        self.task->gid = rgid;
    }
    if (egid != (uid_t) -1) {
        self.task->egid = egid;
    }
    if (sgid != (uid_t) -1) {
        self.task->sgid = sgid;
    }
    return 0;
}

- (uint32_t) sys_getresgid:(addr_t)rgid_addr egid_addr:(addr_t)egid_addr sgid_addr:(addr_t)sgid_addr {
    STRACE("getresgid(%#x, %#x, %#x)", rgid_addr, egid_addr, sgid_addr);
    if ([self.task userWrite:rgid_addr buf:&self.task->gid count:sizeof(self.task->gid)]) {
        return _EFAULT;
    }
    if ([self.task userWrite:egid_addr buf:&self.task->egid count:sizeof(self.task->egid)]) {
        return _EFAULT;
    }
    if ([self.task userWrite:sgid_addr buf:&self.task->sgid count:sizeof(self.task->sgid)]) {
        return _EFAULT;
    }
    return 0;
}

- (uint32_t) sys_getgroups:(uint32_t)size list:(addr_t)list {
    if (size == 0)
        return self.task->ngroups;
    if (size < self.task->ngroups)
        return _EINVAL;
    
    if ([self.task userWrite:list buf:self.task->groups count:size * sizeof(uid_t_)]) {
        return _EFAULT;
    }
    return 0;
}

- (uint32_t) sys_setgroups:(uint32_t)size list:(addr_t)list {
    if (size > MAX_GROUPS) {
        return _EINVAL;
    }
    
    if ([self.task userRead:list buf:self.task->groups count:size * sizeof(uid_t_)]) {
        return _EFAULT;
    }
    self.task->ngroups = size;
    return 0;
}

// this does not really work
- (uint32_t) sys_capget:(addr_t)header_addr data_addr:(addr_t)data_addr {
    STRACE("capget(%#x, %#x)", header_addr, data_addr);
    return 0;
}
- (uint32_t) sys_capset:(addr_t)header_addr data_addr:(addr_t)data_addr {
    STRACE("capset(%#x, %#x)", header_addr, data_addr);
    return 0;
}

// minimal version according to Linux sys/personality.h
- (uint32_t) sys_personality:(dword_t)pers {
    if (pers == 0xffffffff)  // get personality, return default (Linux)
        return 0x00000000;
    if (pers == 0x00000000)  // set personality to Linux
        return 0x00000000;
    return _EINVAL;  // otherwise return error
}

- (pid_t_) sys_getpid {
    STRACE("getpid()");
    return self.task->tgid;
}
- (pid_t_) sys_gettid {
    STRACE("gettid()");
    return self.task.pid.id;
}
- (pid_t_) sys_getppid {
    STRACE("getppid()");
    pid_t_ ppid;
    lock(&pidsLock);
    if (self.task.parent != NULL)
        ppid = self.task.parent.pid.id;
    else
        ppid = 0;
    unlock(&pidsLock);
    return ppid;
}

- (uint32_t) sys_getuid32 {
    STRACE("getuid32()");
    return self.task->uid;
}
- (uint32_t) sys_getuid {
    STRACE("getuid()");
    return self.task->uid & 0xffff;
}

- (uint32_t) sys_geteuid32 {
    STRACE("geteuid32()");
    return self.task->euid;
}
- (uint32_t) sys_geteuid {
    STRACE("geteuid()");
    return self.task->euid & 0xffff;
}

- (uint32_t) sys_setuid:(uid_t_)uid {
    STRACE("setuid(%d)", uid);
    if (self.task->euid == 0) { // self.task->euid == 0 is superuser() this is checking if the executing uid is superuser, root
        self.task->uid = self.task->suid = uid;
    } else {
        if (uid != self.task->uid && uid != self.task->suid)
            return _EPERM;
    }
    self.task->euid = uid;
    return 0;
}


- (uint32_t) sysMProtect:(addr_t)addr len:(uint32_t)len protFlags:(uint32_t) protFlags {
    // https://www.man7.org/linux/man-pages/man2/mprotect.2.html
    // changes the access protections for memory pages starting at addr and running through len length
    // addr must be page aligned
    // len will be rounded up to the next nearest page
    // prot contains the flags to set the on the pages, they are listed in the link above
    STRACE("mprotect(0x%x, 0x%x, 0x%x)", addr, len, prot);
    if (PGOFFSET(addr) != 0) {
        return _EINVAL;
    }
    if (protFlags & ~P_RWX) {
        return _EINVAL;
    }
    pages_t pages = PAGE_ROUND_UP(len);
    write_wrlock(&self.task.mem->lock);
    int err = [self.task.mem setPageTableEntryFlags:PAGE(addr) len:pages flags:protFlags];
    write_wrunlock(&self.task.mem->lock);
    return err;
}


- (void)handleInterrupt:(int)interrupt {
    switch (interrupt) {
        case INT_SYSCALL: {
            self.syscall = self->state.eax;
            CLog(@"P: %d SYSCALL #%d 0x%x    on insn # %d\n", self.task.pid.id, self.syscall, self.syscall, self->instructionCount);
            
            // if (self.syscall >= 10000) || syscall is not defined yet
            //     CLog(@"P: %d SYSCALL #%d 0x%x is not defined. Delivering SISSYS signal.\n", self.task.pid.id, self.syscall, self.syscall);
            //     deliver_signal(current, SIGSYS_, SIGINFO_NIL);
            STRACE(@"SYSCALL #%d 0x%x    on insn # %d\n", self.syscall, self.syscall, self->instructionCount);
            // The arguments passed to a syscall are:
            // syscall(self->state.ebx, self->state.ecx, self->state.edx, self->state.esi, self->state.edi, self->state.ebp)
            int result = -1;
            switch (self.syscall) {
                case 1:
                    result = [self sys_exit:self->state.ebx];
                    break;
                case 2:
                    result = [self.task sys_fork];
                    break;
                case 3:
                    result = [self.task sys_read:self->state.ebx buf_addr:self->state.ecx size:self->state.edx];
                    break;
                case 4:
                    result = [self.task sys_write:self->state.ebx buf_addr:self->state.ecx size:self->state.edx];
                    break;
                case 5:
                    result = [self.task sys_open:self->state.ebx flags:self->state.ecx mode:self->state.edx];
                    break;
                case 20:
                    result = [self sys_getpid];
                    break;
                case 24:
                    result = [self sys_getuid];
                    break;
                case 47:
                    result = [self sys_getgid];
                    break;
                case 49:
                    result = [self sys_geteuid];
                    break;
                case 50:
                    result = [self sys_getegid];
                    break;
                case 64:
                    result = [self sys_getppid];
                    break;
                case 80:
                    result = [self sys_getgroups:self->state.ebx list:self->state.ecx];
                    break;
                case 81:
                    result = [self sys_setgroups:self->state.ebx list:self->state.ecx];
                    break;
                case 125:
                    result = [self sysMProtect:self->state.ebx len:self->state.ecx protFlags:self->state.edx];
                    break;
                case 136:
                    result = [self sys_personality:self->state.ebx];
                    break;
                case 184:
                    result = [self sys_capget:self->state.ebx data_addr:self->state.ecx];
                    break;
                case 185:
                    result = [self sys_capset:self->state.ebx data_addr:self->state.ecx];
                    break;
                case 190:
                    result = [self.task sys_vfork];
                    break;
                case 199:
                    result = [self sys_getuid32];
                    break;
                case 200:
                    result = [self sys_getgid32];
                    break;
                case 201:
                    result = [self sys_geteuid32];
                    break;
                case 202:
                    result = [self sys_getegid32];
                    break;
                case 208:
                    result = [self sys_setresuid:self->state.ebx euid:self->state.ecx suid:self->state.edx];
                    break;
                case 209:
                    result = [self sys_getresuid:self->state.ebx euid_addr:self->state.ecx suid_addr:self->state.edx];
                    break;
                case 210:
                    result = [self sys_setresgid:self->state.ebx egid:self->state.ecx sgid:self->state.edx];
                    break;
                case 211:
                    result = [self sys_getresgid:self->state.ebx egid_addr:self->state.ecx sgid_addr:self->state.edx];
                    break;
                case 213:
                    result = [self sys_setuid:self->state.ebx];
                    break;
                case 214:
                    result = [self sys_setgid:self->state.ebx];
                    break;
                case 224:
                    result = [self sys_gettid];
                    break;
                case 243:
                    result = [self.task sysSetThreadArea:self->state.ebx];
                    break;
                case 258:
                    result = [self.task sysSetTIDAddress:self->state.ebx];
                    break;
                case 295:
                    result = [self.task sys_openat:self->state.ebx path_addr:self->state.ecx flags:self->state.edx mode:self->state.esi];
                    break;
                default:
                    result = -1;
                    CLog(@"Unimplemented syscall attempted.");
                    die("Unimplemented syscall attempted.");
                    break;
            }
            
            self->state.eax = result;
            
            // int result = syscall(self->state.ebx, self->state.ecx, self->state.edx, self->state.esi, self->state.edi, self->state.ebp);
            STRACE(@"SYSCALL #%d 0x%x Result: %d\n", self.syscall, self.syscall, result);
            
            break;
        }
        case INT_GPF: {
            // Handling a General Page Fault interrupt for memory access to an invalid page/address
            CLog(@"P: %d handed general page fault interrupt %d addr %x\n", self.task.pid.id, interrupt, self->state.segfault_addr);
            
            PageTableEntry *segFaultPageTableEntry = [self.task.mem getPageTableEntry:PAGE(self->state.segfault_addr)];
            
            SigInfo *generalPageFaultSigInfo = [[SigInfo alloc] init];
            // SEGV_ACCERR is a signal code for SIGSEGV that specifies Invalid permissions for mapped object
            // SEGV_MAPERR means that the address is not mapped to a valid object
            //
            // Again there is an underscore after these defines and structs because they are the limited or custom versions
            // that this emulator is using and not the official unix defines or structs that have similar names, usually
            // just without the _
            generalPageFaultSigInfo->info.code = segFaultPageTableEntry.isInUse ? SEGV_ACCERR_ : SEGV_MAPERR_;
            generalPageFaultSigInfo->info.fault.addr = self->state.segfault_addr;
            
            [self.task deliverSignalTo:self.task signal:SIGSEGV_ sigInfo:generalPageFaultSigInfo];
            break;
        }
        case INT_UNDEFINED: {
            CLog(@"P: %d handed undefined interrupt %d addr %x\n", self.task.pid.id, interrupt, self->state.segfault_addr);
            // Read 8 bytes before calling deliverSignal
            // TODO: Why 8 bytes?
            for (int i = 0; i < 8; i++) {
                char c;
                if (![self.task userRead:self->state.eip + i buf:&c count:1]) {
                    break;
                } else {
                    CLog(@"Byte %d read: %x\n", i, c);
                }
            }
            
            SigInfo *undefinedSigInfo = [[SigInfo alloc] init];
            undefinedSigInfo->info.code = SI_KERNEL_;
            undefinedSigInfo->info.fault.addr = self->state.eip;
            
            [self.task deliverSignalTo:self.task signal:SIGILL_ sigInfo:undefinedSigInfo];
            die("UNDEFINED not implemented");
            break;
        }
        case INT_TIMER: {
            // TODO: Die ?
            CLog(@"P: %d handling timer interrupt? Shouldnt happen? interrupt %d addr %x\n", self.task.pid.id, interrupt, self->state.segfault_addr);
            // Do nothing - this should continue on to the recieveSignals code
            break;
        }
        default: {
            CLog(@"P: %d handed other interrupt %d addr %x\n", self.task.pid.id, interrupt, self->state.segfault_addr);
            // TODO: sys_exit
            die("Should call sys_exit here");
            // sys_exit(interrupt);
            break;
        }
    }
    
    [self.task recieveSignals];
    // TODO: Lock and wait for the current tasks group to be "unstopped" by recieving an ignore signal
    lock(&self.task.group->lock);
    while (self.task.group.stopped) {
        // [self.task waitForIgnoreSignals:&self.task.group->lock timeout:NULL];
        [self.task waitForIgnoreSignals:&self.task.group->cond lock:&self.task.group->lock timeout:NULL];
        //wait_for_ignore_signals(&self.task.group->stoppedCond, &self.task.group->lock, NULL);
    }
    unlock(&self.task.group->lock);
}





// ########################################### END HANDLE INTERRUPT


- (id)initWithTask:(Task *)task {
    self = [super init];
    if (self) {
        self.task = task;
    }

    return self;
}

- (void)previewMemoryAfterIP {
    char previewString[4096 + 1];
    [self.task userRead:self->state.eip buf:&previewString count:4096];
    CLog(@"bytes in hex: %@\n", [[NSData dataWithBytes:previewString length:(4096 + 1) * sizeof(char)] description]);
}

- (void)collapseFlags {
    collapse_flags(&self->state);
}

- (NSThread *)thread {
    if (!_thread) {
        _thread = [[NSThread alloc] initWithTarget:self selector:@selector(runLoop) object:nil];
    }
    return _thread;
}

- (void)start {
    if (![self.thread isExecuting]) {
        [self.thread start];
    }
}

- (void)stop {
    if ([self.thread isExecuting]) {
        [self.thread cancel];
    }
}

- (NSString *)description {
    return [[NSString alloc] initWithFormat:@"P: %d insn#: %d - eax: %x ebx: %x ecx: %x edx: %x esi: %x edi: %x ebp: %x esp: %x eip: %x eflags: %x res: %x\ncf_bit %d pf %d af %d zf %d sf %d tf %d if_ %d df %d of_bit %d iopl %d pf_res %d sf_res %d af_ops %d cf %d\n", self.task.pid.id, self->instructionCount, self->state.eax, self->state.ebx, self->state.ecx, self->state.edx, self->state.esi, self->state.edi, self->state.ebp, self->state.esp, self->state.eip, self->state.eflags, (int32_t)self->state.res, self->state.cf_bit, self->state.pf, self->state.af, self->state.zf, self->state.sf, self->state.tf, self->state.if_, self->state.df, self->state.of_bit, self->state.iopl, self->state.pf_res, self->state.sf_res, self->state.af_ops, self->state.cf];
}

// Reads the next byte pointed to by the instruction pointer then increments the instruction
// pointer register and returns the read byte
- (int)readByteIncIP:(uint8_t *)readByte {
    // FFLog(@"EIP before 1 byte read: %x", self->state.eip);
    int err = [self.task userRead:self->state.eip buf:readByte count:sizeof(char)];
    if (err) {
        FFLog(@"Error reading 1 byte from vmem vaddr by eip: %x", self->state.eip);
    }
    // FFLog(@"Byte read %x", readByte);
    // FFLog(@"Inc IP From %x", self->state.eip);
    self->state.eip += sizeof(char);
    // FFLog(@"Inc IP To %x", self->state.eip);
    return err;
}

- (int)readFourBytesIncIP:(uint32_t *)readBytes {
    // FFLog(@"EIP before 4 byte read: %x", self->state.eip);
    int err = [self.task userRead:self->state.eip buf:readBytes count:sizeof(int32_t)];
    if (err) {
        FFLog(@"Error reading 4 bytes from vmem vaddr by eip: %x", self->state.eip);
    }
    self->state.eip += sizeof(int32_t);
    return err;
}

- (int)readTwoBytesIncIP:(uint16_t *)readBytes {
    // FFLog(@"EIP before 2 byte read: %x", self->state.eip);
    int err = [self.task userRead:self->state.eip buf:readBytes count:sizeof(uint16_t)];
    if (err) {
        FFLog(@"Error reading 2 bytes from vmem vaddr by eip: %x", self->state.eip);
    }
    self->state.eip += sizeof(uint16_t);
    return err;
}

- (int)readByteIncSP:(uint8_t *)readBytes {
    // FFLog(@"ESP before 1 byte read: %x", self->state.esp);
    int err = [self.task userRead:self->state.eip buf:readBytes count:sizeof(uint8_t)];
    if (err) {
        FFLog(@"Error reading 1 bytes from vmem vaddr by esp: %x", self->state.esp);
    }
    self->state.esp += sizeof(char);
    return err;
}

- (int)readFourBytesIncSP:(uint32_t *)readBytes {
    // FFLog(@"ESP before 4 byte read: %x", self->state.esp);
    int err = [self.task userRead:self->state.esp buf:readBytes count:sizeof(uint32_t)];
    if (err) {
        FFLog(@"Error reading 4 bytes from vmem vaddr by esp: %x", self->state.esp);
    }
    self->state.esp += sizeof(int32_t);
    return err;
}

- (int)readTwoBytesIncSP:(uint16_t *)readBytes {
    // FFLog(@"ESP before 2 byte read: %x", self->state.esp);
    int err = [self.task userRead:self->state.esp buf:readBytes count:sizeof(uint16_t)];
    if (err) {
        FFLog(@"Error reading 2 bytes from vmem vaddr by esp: %x", self->state.esp);
    }
    self->state.esp += sizeof(uint16_t);
    return err;
}
































// -------------------------------------------------------------------- START STEP 32

- (int)step:(uint32_t) addrDefault {
    dword_t saved_ip = self->state.eip;
//    char previewString[4096 + 1];
//    for (int i = 0; i < 4096; i+=8) {
//        [self.task userRead:self->state.eip buf:&previewString count:4096];
//        NSData *ad = [NSData dataWithBytes:previewString length:(4096 + 1) * sizeof(char)];
//        NSRange r = NSMakeRange(i, i+8);
//        CLog(@"bytes in hex: %@\n", [[ad subdataWithRange:r] description]);
//    }
//
    // FFLog(@"4096 bytes after current IP:");
    //    [self previewMemoryAfterIP];r

    // FFLog(@"Current page %x  first 12 address bits %x", PAGE(self->state.eip), PGOFFSET(self->state.eip));
    Memory *mem = self.task.mem;
    PageTableEntry *pe = [mem getPageTableEntry:PAGE(self->state.eip)];
    MappedMemory *mm = pe.mappedMemory;
    const char *d = mm.data;
    NSString *debugString = mm.debugString;
    page_t mmps = mm.pageStart;
    page_t mmnp = mm.numPages;

    // FFLog(@"pgTblEntry offsetInMem:  %x   offsetInFile: %x   DebugString: %@    PgStart: %x  PageCount:  %x  ", pe.offsetIntoMappedMemory,  pe.mappedMemory.fileOffset, debugString, mmps, mmnp);

    modrm mrm;
    uint8_t modRMByte;
    
    uint8_t firstOpByte;
    uint8_t secondOpByte;

// restart32:


    
    [self readByteIncIP:&firstOpByte];
    
//    CPULog("%@", [self description]);
    
    
    // # ifdef BDEBUG
    //if (self.task.pid.id == 2) {
        // printf("\n\n");
        // [self printState:firstOpByte];
    //}
    // CLog(@"P: %d OpCode: 0x%x\n", self.task.pid.id, firstOpByte);
    // # endif
    
    // if (self.task.pid.id == 1)
    // JSON Comparison debugging code
    NSString *dsk = [NSString stringWithFormat:@"%d", self->instructionCount + 1];
    NSDictionary * parsedData = parsedData = self.ishDebugState[dsk]; // (Task *)([Pid getTask:self.task.pid.id includeZombie:true]).cpu.ishDebugState[dsk];
    
    uint32_t stackVar = [self.task userReadFourBytes:self->state.esp];

    // CPULog("%x\t%x\t%x\t%x\t%x\t%x\t%x\t%x\t%x\t%x\t%x\t%x\tflags\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%x - X86\n", self->state.eax, self->state.ebx, self->state.ecx, self->state.edx, self->state.esi, self->state.edi, self->state.ebp, self->state.esp, self->state.eip, self->state.eflags, self->state.res, stackVar, self->state.cf_bit, self->state.pf, self->state.af, self->state.zf, self->state.sf, self->state.tf, self->state.if_, self->state.df, self->state.of_bit, self->state.iopl, self->state.pf_res, self->state.sf_res, self->state.af_ops, self->state.cf, firstOpByte);
    
        if (parsedData) {
            // CPULog("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tflags\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s - ISH\n", [parsedData[@"eax"] UTF8String], [parsedData[@"ebx"] UTF8String], [parsedData[@"ecx"] UTF8String], [parsedData[@"edx"] UTF8String], [parsedData[@"esi"] UTF8String], [parsedData[@"edi"] UTF8String], [parsedData[@"ebp"] UTF8String], [parsedData[@"esp"] UTF8String], [parsedData[@"eip"] UTF8String], [parsedData[@"eflags"] UTF8String], [parsedData[@"res"] UTF8String], [parsedData[@"cf_bit"] UTF8String], [parsedData[@"pf"] UTF8String], [parsedData[@"af"] UTF8String], [parsedData[@"zf"] UTF8String], [parsedData[@"sf"] UTF8String], [parsedData[@"tf"] UTF8String], [parsedData[@"if_"] UTF8String], [parsedData[@"df"] UTF8String], [parsedData[@"of_bit"] UTF8String], [parsedData[@"iopl"] UTF8String], [parsedData[@"pf_res"] UTF8String], [parsedData[@"sf_res"] UTF8String], [parsedData[@"af_ops"] UTF8String], [parsedData[@"cf"] UTF8String], [parsedData[@"insn"] UTF8String]);
            
            
            // CPULog("x86 insn #:%d Ish insn #:%s :\n", self->instructionCount, [parsedData[@"num"] UTF8String]);
            // CPULog("%x %x %x %x %x %x %x %x %x %x %x\n", self->instructionCount, self->state.eax, self->state.ebx, self->state.ecx, self->state.edx, self->state.esi, self->state.edi, self->state.ebp, self->state.esp, self->state.eip, self->state.eflags, self->state.res);
            // CPULog("%s %s %s %s %s %s %s %s %s %s %s %s\n", [parsedData[@"eax"] UTF8String], [parsedData[@"ebx"] UTF8String], [parsedData[@"ecx"] UTF8String], [parsedData[@"edx"] UTF8String], [parsedData[@"esi"] UTF8String], [parsedData[@"edi"] UTF8String], [parsedData[@"ebp"] UTF8String], [parsedData[@"esp"] UTF8String], [parsedData[@"eip"] UTF8String], [parsedData[@"eflags"] UTF8String], [parsedData[@"res"] UTF8String], [parsedData[@"insn"] UTF8String]);
            
            
            // Compare against the current state
            if (self->instructionCount != 0 && !([parsedData[@"eax"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.eax]] &&
                  [parsedData[@"ebx"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.ebx]] &&
                  [parsedData[@"ecx"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.ecx]] &&
                  [parsedData[@"edx"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.edx]] &&
                  
                  [parsedData[@"esi"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.esi]] &&
                  [parsedData[@"edi"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.edi]] &&
                  [parsedData[@"ebp"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.ebp]] &&
                  [parsedData[@"esp"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.esp]] &&
                  
                  [parsedData[@"eip"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.eip]] &&
                  [parsedData[@"eflags"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.eflags]] &&
                  [parsedData[@"stack"] isEqualTo:[NSString stringWithFormat:@"%x", stackVar]] &&
                  [parsedData[@"res"] isEqualTo:[NSString stringWithFormat:@"%x", self->state.res]] )) {
                
                CLog(@"\n\nError Diff on insn %d:\n\nx86 then ish:\n", self->instructionCount);
                CPULog("\nx86 - eax %x\tebx %x\tecx %x\tedx %x\tesi %x\tedi %x\tebp %x\tesp %x\teip %x\teflags %x\tres %x\tstack %x\tflags\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%x - X86\n", self->state.eax, self->state.ebx, self->state.ecx, self->state.edx, self->state.esi, self->state.edi, self->state.ebp, self->state.esp, self->state.eip, self->state.eflags, self->state.res, stackVar, self->state.cf_bit, self->state.pf, self->state.af, self->state.zf, self->state.sf, self->state.tf, self->state.if_, self->state.df, self->state.of_bit, self->state.iopl, self->state.pf_res, self->state.sf_res, self->state.af_ops, self->state.cf, firstOpByte);
                CPULog("\nish - eax %s\tebx %s\tecx %s\tedx %s\tesi %s\tedi %s\tebp %s\tesp %s\teip %s\teflags %s\tres %s\tstack %s\tflags\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s - ISH\n",
                   [parsedData[@"eax"] UTF8String], [parsedData[@"ebx"] UTF8String], [parsedData[@"ecx"] UTF8String], [parsedData[@"edx"] UTF8String], [parsedData[@"esi"] UTF8String], [parsedData[@"edi"] UTF8String], [parsedData[@"ebp"] UTF8String], [parsedData[@"esp"] UTF8String], [parsedData[@"eip"] UTF8String], [parsedData[@"eflags"] UTF8String], [parsedData[@"res"] UTF8String], [parsedData[@"stack"] UTF8String], [parsedData[@"cf_bit"] UTF8String], [parsedData[@"pf"] UTF8String], [parsedData[@"af"] UTF8String], [parsedData[@"zf"] UTF8String], [parsedData[@"sf"] UTF8String], [parsedData[@"tf"] UTF8String], [parsedData[@"if_"] UTF8String], [parsedData[@"df"] UTF8String], [parsedData[@"of_bit"] UTF8String], [parsedData[@"iopl"] UTF8String], [parsedData[@"pf_res"] UTF8String], [parsedData[@"sf_res"] UTF8String], [parsedData[@"af_ops"] UTF8String], [parsedData[@"cf"] UTF8String], [parsedData[@"insn"] UTF8String]);
                
                CPULog("~~~ ERROR: Ish/X86 TRACE MISMATCH - Instruction number %d. EIP: %x\n", self->instructionCount, self->state.eip);
                printf("\n");
            } else {
                // CPULog("ISH and x86 match registers - Instruction number %d. EIP: %x\n", self->instructionCount, self->state.eip);
            }
            
        } else {
            CPULog("No comparison data for this instruction. insn #:%d\n", self->instructionCount);
        }
    
//    CPULog("\nEIP Comps %@ %@\n", parsedData[@"eip"] , [NSString stringWithFormat:@"%x", self->state.eip] );
    
    


    self->instructionCount += 1;
    
    uint32_t addr = addrDefault;
    



    uint8_t *moffs8;
    uint32_t *moffs32;

    enum reg32 tmpReg;

    dword_t *regPtr;
    dword_t *rmPtr;

    double tempdouble;
    float80 tempfloat80;
    float tempfloat;
    uint8_t imm8 = 0;
    uint16_t imm16 = 0;
    uint32_t imm32 = 0;
    uint64_t imm64 = 0;
    uint8_t temp8 = 0;
    uint8_t *temp8ptr = 0;
    uint16_t temp16 = 0;
    uint32_t temp32 = 0;
    uint32_t *temp32ptr = 0;
    uint64_t temp64 = 0;
    uint64_t *temp64ptr = 0;
    uint8_t divisor8;
    uint8_t dividend8;
    uint32_t divisor32;
    uint32_t dividend32;
    uint16_t divisor16;
    uint16_t dividend16;
    uint32_t *rmReadPtr;
    uint32_t rmReadValue;
    uint32_t *rmWritePtr;
    enum reg32 opReg;
    

    switch (firstOpByte) {
        // TODO: Implement a group
        // http://ref.x86asm.net/coder32.html#x30
        // https://www.sandpile.org/x86/opc_1.htm

        // All thats left is
        // ADD
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x03:
        case 0x04:
        case 0x05:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:8];

                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, *(int8_t *)regPtr, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr, (uint8_t *)&self->state.res);
                    *(int8_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    self->state.cf = __builtin_add_overflow((uint32_t)rmReadValue, *(uint32_t *)regPtr, (uint32_t *)&self->state.res);
                    self->state.of = __builtin_add_overflow((int32_t)rmReadValue, *(int32_t *)regPtr, (int32_t *)&self->state.res);

                    *(int32_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:8];

                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, *(int8_t *)regPtr, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr, (uint8_t *)&self->state.res);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:32];

                    self->state.of = __builtin_add_overflow((int32_t)rmReadValue, *(int32_t *)regPtr, (int32_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint32_t)rmReadValue, *(uint32_t *)regPtr, (uint32_t *)&self->state.res);
                    *(int32_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];

                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, (int8_t)imm8, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, (uint8_t)imm8, (uint8_t *)&self->state.res);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readFourBytesIncIP:&imm32];
                    regPtr =  [self getRegPointer:reg_eax opSize:32];

                    self->state.of = __builtin_add_overflow((int32_t)rmReadValue, (int32_t)imm32, (int32_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint32_t)rmReadValue, (uint32_t)imm32, (uint32_t *)&self->state.res);
                    *(int32_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;
        // OR
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0c:
        case 0x0d:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:8];

                    self->state.res = *(uint8_t *)rmWritePtr = *(uint8_t *)regPtr | (uint8_t)rmReadValue;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:32];

                    self->state.res = *(uint32_t *)rmWritePtr = *(uint32_t *)regPtr | (uint32_t)rmReadValue;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:8];

                    self->state.res = *(uint8_t *)regPtr = *(uint8_t *)regPtr | (uint8_t)rmReadValue;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:32];

                    self->state.res = *(uint32_t *)regPtr = *(uint32_t *)regPtr | (uint32_t)rmReadValue;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];
                    self->state.res = *(int8_t *)regPtr = *(int8_t *)regPtr | (uint8_t)imm8;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readFourBytesIncIP:&imm32];
                    regPtr =  [self getRegPointer:reg_eax opSize:32];
                    self->state.res = *(int32_t *)regPtr = *(int32_t *)regPtr | (uint32_t)imm32;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;

        case 0x0f:
// multibyterestart32:
            [self readByteIncIP:&secondOpByte];
            switch(secondOpByte) {
                case 0x18 ... 0x1f:
                    // http://ref.x86asm.net/coder32.html#x0F18
                    // HINT_NOP    r/m16/32
                    // Read the ModRM byte but do nothing
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    break;
                case 0x28:
                    // MOVAPS    xmm    xmm/m128
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x29:
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x31:
                    /*
                    imm64 = ({ uint32_t low, high; __asm__ volatile("rdtsc" : "=a" (high), "=d" (low)); ((uint64_t) high) << 32 | low; });
                    self->state.eax = imm64 & 0xffffffff;
                    self->state.edx = imm64 >> 32;
                     */
                    __asm__ volatile("rdtsc" : "=a" (self->state.edx), "=d" (self->state.eax));
                    break;
                case 0x40:
                    // CMOVO    r16/32    r/m16/32                o.......                    Conditional Move - overflow (OF=1)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (self->state.of) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x41:
                    // CMOVNO    r16/32    r/m16/32                o.......                    Conditional Move - not overflow (OF=0)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (!self->state.of) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x42:
                    // CMOVB      r16/32    r/m16/32                .......c                    Conditional Move - below/not above or equal/carry (CF=1)
                    // CMOVNAE    r16/32    r/m16/32
                    // CMOVC      r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (self->state.cf) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x43:
                    // CMOVNB    r16/32    r/m16/32                .......c                    Conditional Move - not below/above or equal/not carry (CF=0)
                    // CMOVAE    r16/32    r/m16/32
                    // CMOVNC    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (!self->state.cf) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x44:
                    // CMOVZ    r16/32    r/m16/32                ....z...                    Conditional Move - zero/equal (ZF=1)
                    // CMOVE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (self->state.zf_res ? (self->state.res == 0) : self->state.zf) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x45:
                    // CMOVNZ    r16/32    r/m16/32                ....z...                    Conditional Move - not zero/not equal (ZF=0)
                    // CMOVNE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (!(self->state.zf_res ? (self->state.res == 0) : self->state.zf)) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x46:
                    // CMOVBE    r16/32    r/m16/32                ....z..c                    Conditional Move - below or equal/not above (CF=1 OR ZF=1)
                    // CMOVNA    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (self->state.cf | (self->state.zf_res ? (self->state.res == 0) : self->state.zf)) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x47:
                    // CMOVNBE    r16/32    r/m16/32                ....z..c                    Conditional Move - not below or equal/above (CF=0 AND ZF=0)
                    // CMOVA    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (!(self->state.cf | (self->state.zf_res ? (self->state.res == 0) : self->state.zf))) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x48:
                    // CMOVS    r16/32    r/m16/32                ...s....                    Conditional Move - sign (SF=1)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if ((self->state.sf_res ? (self->state.res < 0) : self->state.sf)) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x49:
                    // CMOVNS    r16/32    r/m16/32                ...s....                    Conditional Move - not sign (SF=0)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (!(self->state.sf_res ? (self->state.res < 0) : self->state.sf)) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x4a:
                    // CMOVP    r16/32    r/m16/32                ......p.                    Conditional Move - parity/parity even (PF=1)
                    // CMOVPE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if ((self->state.pf_res ? (!__builtin_parity(self->state.res & 0xff)) : self->state.pf)) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x4b:
                    // CMOVNP    r16/32    r/m16/32                ......p.                    Conditional Move - not parity/parity odd (PF=0)
                    // CMOVPO    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (!(self->state.pf_res ? (!__builtin_parity(self->state.res & 0xff)) : self->state.pf)) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x4c:
                    // CMOVL    r16/32    r/m16/32                o..s....                    Conditional Move - less/not greater (SF!=OF)
                    // CMOVNGE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (((self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) ^ (self->state.of))) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x4d:
                    // CMOVNL    r16/32    r/m16/32                o..s....                    Conditional Move - not less/greater or equal (SF=OF)
                    // CMOVGE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (!((self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) ^ (self->state.of))) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x4e:
                    // CMOVLE    r16/32    r/m16/32                o..sz...                    Conditional Move - less or equal/not greater ((ZF=1) OR (SF!=OF))
                    // CMOVNG    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if ((((self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) ^ (self->state.of)) | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x4f:
                    // CMOVNLE    r16/32    r/m16/32                o..sz...                    Conditional Move - not less nor equal/greater ((ZF=0) AND (SF=OF))
                    // CMOVG    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (!(((self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) ^ (self->state.of)) | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                        *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    }
                    break;
                case 0x57:
                    // XORPS    xmm    xmm/m128            sse1                        Bitwise Logical XOR for Single-FP Values
                    // A NOP
                    break;
                case 0x65:
                    die("Figure out how to implement without goto");
                    addr += self->state.tls_ptr;
                    // goto multibyterestart32;
                    break;
                case 0x6e:
                    // MOVD    mm    r/m32            mmx                        Move Doubleword
                    // A NOP
                    break;
                case 0x6f:
                    // MOVDQA    xmm    xmm/m128            sse2                        Move Aligned Double Quadword
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x73:
                    // PSRLQ    mm    imm8            mmx                        Shift Packed Data Right Logical
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    switch(mrm.opcode) {
                        case 0x02:

                        default:
                            self->state.eip = saved_ip;
                            return INT_UNDEFINED;
                            break;
                    }
                    break;
                case 0x77:
                    // EMMS                    mmx                        Empty MMX Technology State
                    // A NOP
                    break;
                case 0x7e:
                    // MOVD    r/m32    mm            mmx                        Move Doubleword
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x7f:
                    // MOVQ    mm/m64    mm            mmx                        Move Quadword
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x80:
                    // JO    rel16/32                    o.......                    Jump near if overflow (OF=1)
                    [self readFourBytesIncIP:&imm32];

                    if (self->state.of) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x81:
                    // JNO    rel16/32                    o.......                    Jump near if not overflow (OF=0)
                    [self readFourBytesIncIP:&imm32];

                    if (!self->state.of) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x82:
                    // JB    rel16/32                    .......c                    Jump near if below/not above or equal/carry (CF=1)
                    // JNAE    rel16/32
                    // JC    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if (self->state.cf) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x83:
                    // JNB    rel16/32                    .......c                    Jump near if not below/above or equal/not carry (CF=0)
                    // JAE    rel16/32
                    // JNC    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if (!self->state.cf) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x84:
                    // JZ    rel16/32                    ....z...                    Jump near if zero/equal (ZF=1)
                    // JE    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if ((self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x85:
                    // JNZ    rel16/32                    ....z...                    Jump near if not zero/not equal (ZF=0)
                    // JNE    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if (!(self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x86:
                    // JBE    rel16/32                    ....z..c                    Jump near if below or equal/not above (CF=1 OR ZF=1)
                    // JNA    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if (self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x87:
                    // JNBE    rel16/32                    ....z..c                    Jump near if not below or equal/above (CF=0 AND ZF=0)
                    // JA    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if (!(self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x88:
                    // JS    rel16/32                    ...s....                    Jump near if sign (SF=1)
                    [self readFourBytesIncIP:&imm32];

                    if (self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x89:
                    // JNS    rel16/32                    ...s....                    Jump near if not sign (SF=0)
                    [self readFourBytesIncIP:&imm32];

                    if (!(self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf)) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x8a:
                    // JP    rel16/32                    ......p.                    Jump near if parity/parity even (PF=1)
                    // JPE    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if ((self->state.pf_res ? !__builtin_parity(self->state.res & 0xff): self->state.pf)) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x8b:
                    // JNP    rel16/32                    ......p.                    Jump near if not parity/parity odd (PF=0)
                    // JPO    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if (!(self->state.pf_res ? !__builtin_parity(self->state.res & 0xff): self->state.pf)) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x8c:
                    // JL    rel16/32                    o..s....                    Jump near if less/not greater (SF!=OF)
                    // JNGE    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if ((self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) ^ self->state.of) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x8d:
                    // JNL    rel16/32                    o..s....                    Jump near if not less/greater or equal (SF=OF)
                    // JGE    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if (!(self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) ^ self->state.of) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x8e:
                    // JLE    rel16/32                    o..sz...                    Jump near if less or equal/not greater ((ZF=1) OR (SF!=OF))
                    // JNG    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if ((self->state.zf_res ? self->state.res == 0 : self->state.zf) | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x8f:
                    // JNLE    rel16/32                    o..sz...                    Jump near if not less nor equal/greater ((ZF=0) AND (SF=OF))
                    // 2JG    rel16/32
                    [self readFourBytesIncIP:&imm32];

                    if (!((self->state.zf_res ? self->state.res == 0 : self->state.zf) | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                        self->state.eip += imm32;
                    }
                    break;
                case 0x90:
                    // SETO    r/m8                    o.......                    Set Byte on Condition - overflow (OF=1)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.of) ? 1 : 0;
                    break;
                case 0x91:
                    // SETNO    r/m8                    o.......                    Set Byte on Condition - not overflow (OF=0)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.of) ? 0 : 1;
                    break;
                case 0x92:
                    // SETB    r/m8                    .......c                    Set Byte on Condition - below/not above or equal/carry (CF=1)
                    // SETNAE    r/m8
                    // SETC
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.cf) ? 1 : 0;
                    break;
                case 0x93:
                    // SETNB    r/m8                    .......c                    Set Byte on Condition - not below/above or equal/not carry (CF=0)
                    // SETAE    r/m8
                    // SETNC
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.cf) ? 0 : 1;
                    break;
                case 0x94:
                    // SETZ    r/m8                    ....z...                    Set Byte on Condition - zero/equal (ZF=1)
                    // SETE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.zf_res ? self->state.res == 0 : self->state.zf) ? 1 : 0;
                    break;
                case 0x95:
                    // SETNZ    r/m8                    ....z...                    Set Byte on Condition - not zero/not equal (ZF=0)
                    // SETNE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.zf_res ? self->state.res == 0 : self->state.zf) ? 0 : 1;
                    break;
                case 0x96:
                    // SETBE    r/m8                    ....z..c                    Set Byte on Condition - below or equal/not above (CF=1 OR ZF=1)
                    // SETNA
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) ? 1 : 0;
                    break;
                case 0x97:
                    // SETNBE    r/m8                    ....z..c                    Set Byte on Condition - not below or equal/above (CF=0 AND ZF=0)
                    // SETA
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) ? 0 : 1;
                    break;
                case 0x98:
                    // SETS    r/m8                    ...s....                    Set Byte on Condition - sign (SF=1)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.sf_res ? self->state.res < 0 : self->state.sf) ? 1 : 0;
                    break;
                case 0x99:
                    // SETNS    r/m8                    ...s....                    Set Byte on Condition - not sign (SF=0)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.sf_res ? self->state.res < 0 : self->state.sf) ? 0 : 1;
                    break;
                case 0x9a:
                    // SETP    r/m8                    ......p.                    Set Byte on Condition - parity/parity even (PF=1)
                    // SETPE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.pf_res ? !__builtin_parity(self->state.res & 0xFF) : self->state.pf) ? 1 : 0;
                    break;
                case 0x9b:
                    // SETNP    r/m8                    ......p.                    Set Byte on Condition - not parity/parity odd (PF=0)
                    // SETPO
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = (self->state.pf_res ? !__builtin_parity(self->state.res & 0xFF) : self->state.pf) ? 0 : 1;
                    break;
                case 0x9c:
                    // SETL    r/m8                    o..s....                    Set Byte on Condition - less/not greater (SF!=OF)
                    // SETNGE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = ((self->state.sf_res ? self->state.res < 0 : self->state.sf) ^ self->state.of) ? 1 : 0;
                    break;
                case 0x9d:
                    // SETNL    r/m8                    o..s....                    Set Byte on Condition - not less/greater or equal (SF=OF)
                    // SETGE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = ((self->state.sf_res ? self->state.res < 0 : self->state.sf) ^ self->state.of) ? 0 : 1;
                    break;
                case 0x9e:
                    // SETLE    r/m8                    o..sz...                    Set Byte on Condition - less or equal/not greater ((ZF=1) OR (SF!=OF))
                    // SETNG
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = ((self->state.zf_res ? self->state.res == 0 : self->state.zf) | ((self->state.sf_res ? self->state.res < 0 : self->state.sf) ^ self->state.of)) ? 1 : 0;
                    break;
                case 0x9f:
                    // SETNLE    r/m8                    o..sz...                    Set Byte on Condition - not less nor equal/greater ((ZF=0) AND (SF=OF))
                    // SETG
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    *(uint8_t *)rmWritePtr = ((self->state.zf_res ? self->state.res == 0 : self->state.zf) | ((self->state.sf_res ? self->state.res < 0 : self->state.sf) ^ self->state.of)) ? 0 : 1;
                    break;
                case 0xa2:
                    // CPUID    IA32_BIOS_…    EAX    ECX    ...                            CPU Identification
                    do_cpuid(&self->state.eax, &self->state.ebx, &self->state.ecx, &self->state.edx);
                    break;
                case 0xa3:
                    // BT    r/m16/32    r16/32                    o..szapc    .......c    o..szap.        Bit Test
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:32] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    self->state.cf = (rmReadValue & (1 << *(uint32_t *)regPtr % 32)) ? 1 : 0;
                    break;
                case 0xa4:
                    // SHLD    r/m16/32    r16/32    imm8                o..szapc    o..sz.pc    o....a.c        Double Precision Shift Left
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    [self readByteIncIP:&imm8];

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    // temp8 = (uint8_t)imm8 % 32;
                    if ((uint8_t)imm8 % 32 != 0) {
                        self->state.res = rmReadValue << ((uint8_t)imm8 % 32) | *(uint32_t *)regPtr >> (32 - ((uint8_t)imm8 % 32));
                        *(uint32_t *)rmWritePtr = self->state.res;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    }
                    break;
                case 0xa5:
                    // SHLD    r/m16/32    r16/32    CL                o..szapc    o..sz.pc    o....a.c        Double Precision Shift Left
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    if ((uint8_t)self->state.cl % 32 != 0) {
                        self->state.res = rmReadValue << ((uint8_t)self->state.cl % 32) | *(uint32_t *)regPtr >> (32 - ((uint8_t)self->state.cl % 32));
                        *(uint32_t *)rmWritePtr = self->state.res;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    }
                    break;
                case 0xab:
                    // BTS    r/m16/32    r16/32                    o..szapc    .......c    o..szap.        Bit Test And Set
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:32] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    self->state.cf = *regPtr & (1 << rmReadValue % 32);
                    *(uint32_t *)rmWritePtr = rmReadValue | (1 << *(uint32_t *)regPtr % 32);
                    break;
                case 0xac:
                    // SHRD    r/m16/32    r16/32    imm8                o..szapc    o..sz.pc    o....a.c        Double Precision Shift Right
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    [self readByteIncIP:&imm8];

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    // temp8 = (uint8_t)imm8 % 32;
                    if ((uint8_t)imm8 % 32 != 0) {
                        self->state.res = rmReadValue >> ((uint8_t)imm8 % 32) | *(uint32_t *)regPtr << (32 - ((uint8_t)imm8 % 32));
                        *(uint32_t *)rmWritePtr = self->state.res;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    }
                    break;
                case 0xad:
                    // SHRD    r/m16/32    r16/32    CL                o..szapc    o..sz.pc    o....a.c        Double Precision Shift Right
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    if ((uint8_t)self->state.cl % 32 != 0) {
                        self->state.res = rmReadValue >> ((uint8_t)self->state.cl % 32) | *(uint32_t *)regPtr << (32 - ((uint8_t)self->state.cl % 32));
                        *(uint32_t *)rmWritePtr = self->state.res;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    }
                    break;
                case 0xaf:
                    // IMUL    r16/32    r/m16/32                    o..szapc    o......c    ...szap.        Signed Multiply
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    self->state.cf = self->state.of = __builtin_mul_overflow(*(int32_t *)regPtr, (int32_t)rmReadValue, (int32_t *)&self->state.res);
                    *(uint32_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0xb0:
                    // CMPXCHG    r/m8    AL    r8                o..szapc    o..szapc            Compare and Exchange
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    self->state.cf = __builtin_sub_overflow((uint8_t)rmReadValue, (uint8_t)self->state.al, (uint8_t *) &self->state.res);
                    self->state.of = __builtin_sub_overflow((uint8_t)rmReadValue,  (int8_t)self->state.al,  (int8_t *) &self->state.res);
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;

                    if (self->state.res == 0) {
                        regPtr = [self getRegPointer:mrm.reg opSize:8];
                        *(uint8_t *)rmWritePtr = *(uint8_t *)regPtr;
                    } else {
                        *(uint8_t *)&self->state.al = (uint8_t)rmReadValue;
                    }
                    break;
                case 0xb1:
                    // CMPXCHG    r/m16/32    eAX    r16/32                o..szapc    o..szapc            Compare and Exchange
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    self->state.cf = __builtin_sub_overflow((uint32_t)rmReadValue, (uint32_t)self->state.eax, (uint32_t *) &self->state.res);
                    self->state.of = __builtin_sub_overflow((uint32_t)rmReadValue,  (int32_t)self->state.eax,  (int32_t *) &self->state.res);
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;

                    if (self->state.res == 0) {
                        regPtr = [self getRegPointer:mrm.reg opSize:32];
                        *(uint32_t *)rmWritePtr = *(uint32_t *)regPtr;
                    } else {
                        *(uint32_t *)&self->state.eax = (uint32_t)rmReadValue;
                    }
                    break;
                case 0xb3:
                    // BTR    r/m16/32    r16/32                    o..szapc    .......c    o..szap.        Bit Test and Reset
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:32] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    self->state.cf = *regPtr & ~(1 << rmReadValue % 32);
                    *(uint32_t *)rmWritePtr = rmReadValue | (1 << *(uint32_t *)regPtr % 32);
                    break;
                case 0xb6:
                    // MOVZX    r16/32    r/m8                                    Move with Zero-Extend
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    *(uint32_t *)regPtr = (uint8_t)rmReadValue;
                    break;
                case 0xb7:
                    // http://ref.x86asm.net/coder32.html#x0FB7
                    // MOVZX    r16/32    r/m16                                    Move with Zero-Extend
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    *(uint32_t *)regPtr = (uint16_t)rmReadValue; // might want to ditch this cast this is supposed to be a move of 16bit into a 32 bit reg with 0 extend
                    break;
                case 0xba:
                    // BT     r/m16/32    imm8                      o..szapc    .......c    o..szap.        Bit Test
                    // BTS    r/m16/32    imm8                      o..szapc    .......c    o..szap.        Bit Test and Set
                    // BTR    r/m16/32    imm8                      o..szapc    .......c    o..szap.        Bit Test and Reset
                    // BTC    r/m16/32    imm8                      o..szapc    .......c    o..szap.        Bit Test and Complement
                    [self readByteIncIP:&modRMByte];
                    [self readByteIncIP:&imm8];

                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + (imm8 / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    switch(mrm.opcode) {
                        case 4:
                            self->state.cf = rmReadValue & (1 << imm8 % 32);
                            break;
                        case 5:
                            self->state.cf = rmReadValue & (1 << imm8 % 32);
                            *(uint32_t *)rmWritePtr = rmReadValue | (1 << imm8 % 32);
                            break;
                        case 6:
                            self->state.cf = rmReadValue & (1 << imm8 % 32);
                            *(uint32_t *)rmWritePtr = rmReadValue | ~(1 << imm8 % 32);
                            break;
                        case 7:
                            self->state.cf = rmReadValue & (1 << imm8 % 32);
                            *(uint32_t *)rmWritePtr = rmReadValue ^ (1 << imm8 % 32);
                            break;
                        default:
                            self->state.eip = saved_ip;
                            return INT_UNDEFINED;
                            break;
                    }

                    self->state.cf = *regPtr & (1 << imm8 % 32);
                    break;
                case 0xbb:
                    // BTC    r/m16/32    r16/32                    o..szapc    .......c    o..szap.        Bit Test and Complement
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:32] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    self->state.cf = rmReadValue & (1 << *(uint32_t *)regPtr % 32);
                    *(uint32_t *)rmWritePtr = rmReadValue ^ (1 << *(uint32_t *)regPtr % 32);
                    break;
                case 0xbc:
                    // BSF    r16/32    r/m16/32                    o..szapc    ....z...    o..s.apc        Bit Scan Forward
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:32] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    self->state.zf = rmReadValue == 0;
                    self->state.zf_res = 0;

                    if (!self->state.zf) {
                        *(uint32_t *)regPtr = __builtin_ctz(rmReadValue);
                    }
                    break;
                case 0xbd:
                    // BSR    r16/32    r/m16/32                    o..szapc    ....z...    o..s.apc        Bit Scan Reverse
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:32] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    self->state.zf = rmReadValue == 0;
                    self->state.zf_res = 0;

                    if (!self->state.zf) {
                        *(uint32_t *)regPtr = 32 - __builtin_ctz(rmReadValue);
                    }
                    break;
                case 0xbe:
                    // MOVSX    r16/32    r/m8                                    Move with Sign-Extension
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    break;
                case 0xbf:
                    // MOVSX    r16/32    r/m16                                    Move with Sign-Extension
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    break;
                case 0xc0:
                    // XADD    r/m8    r8                    o..szapc    o..szapc            Exchange and Add
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:8];

                    temp8 = *(uint8_t *)regPtr;
                    *(uint8_t *)regPtr = (uint8_t)rmReadValue;
                    *(uint8_t *)rmWritePtr = (uint8_t)temp8;
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr, (uint8_t *)&self->state.res);
                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, *(int8_t *)regPtr, (int8_t *)&self->state.res);
                    *(uint8_t *)rmWritePtr = (uint8_t)self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0xc1:
                    // XADD    r/m16/32    r16/32                    o..szapc    o..szapc            Exchange and Add
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    temp8 = *(uint32_t *)regPtr;
                    *(uint32_t *)regPtr = (uint32_t)rmReadValue;
                    *(uint32_t *)rmWritePtr = (uint32_t)temp8;
                    self->state.cf = __builtin_add_overflow((uint32_t)rmReadValue, *(uint32_t *)regPtr, (uint32_t *)&self->state.res);
                    self->state.of = __builtin_add_overflow((int32_t)rmReadValue, *(int32_t *)regPtr, (int32_t *)&self->state.res);
                    *(uint32_t *)rmWritePtr = (uint32_t)self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0xc8:
                    // Byte Swap operations:
                    *(uint32_t *)&self->state.eax = __builtin_bswap32(((uint32_t)self->state.eax));
                    break;
                case 0xc9:
                    *(uint32_t *)&self->state.ecx = __builtin_bswap32(((uint32_t)self->state.ecx));
                    break;
                case 0xca:
                    *(uint32_t *)&self->state.edx = __builtin_bswap32(((uint32_t)self->state.edx));
                    break;
                case 0xcb:
                    *(uint32_t *)&self->state.ebx = __builtin_bswap32(((uint32_t)self->state.ebx));
                    break;
                case 0xcc:
                    *(uint32_t *)&self->state.esp = __builtin_bswap32(((uint32_t)self->state.esp));
                    break;
                case 0xcd:
                    *(uint32_t *)&self->state.ebp = __builtin_bswap32(((uint32_t)self->state.ebp));
                    break;
                case 0xce:
                    *(uint32_t *)&self->state.esi = __builtin_bswap32(((uint32_t)self->state.esi));
                    break;
                case 0xcf:
                    *(uint32_t *)&self->state.edi = __builtin_bswap32(((uint32_t)self->state.edi));
                    break;
                default:
                    die("Unimplemented 2 part opcode 0x0f");
                    break;
            }
            break;

        // ADC
        case 0x10:
        case 0x11:
        case 0x12:
        case 0x13:
        case 0x14:
        case 0x15:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:8];

                    __builtin_add_overflow((int8_t)rmReadValue, *(int8_t *)regPtr + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    __builtin_add_overflow((int32_t)rmReadValue, *(int32_t *)regPtr + self->state.cf, (int32_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint32_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow((uint8_t)rmReadValue, *(uint32_t *)regPtr + self->state.cf, (uint32_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint32_t)-1) / 2);
                    *(int32_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:8];

                    __builtin_add_overflow(*(int8_t *)regPtr, (int8_t)rmReadValue + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow(*(uint8_t *)regPtr, (uint8_t)rmReadValue + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:32];

                    __builtin_add_overflow(*(int32_t *)regPtr, (int32_t)rmReadValue + self->state.cf, (int32_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint32_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow(*(uint32_t *)regPtr, (uint32_t)rmReadValue + self->state.cf, (uint32_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint32_t *)regPtr == ((uint32_t)-1) / 2);
                    *(int32_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];

                    __builtin_add_overflow(*(int8_t *)regPtr, (int8_t)imm8 + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow(*(uint8_t *)regPtr, (uint8_t)imm8 + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readFourBytesIncIP:&imm32];
                    regPtr =  [self getRegPointer:reg_eax opSize:32];

                    __builtin_add_overflow(*(int32_t *)regPtr, (int32_t)imm32 + self->state.cf, (int32_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int32_t *)regPtr == ((uint32_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow(*(uint32_t *)regPtr, (uint32_t)imm32 + self->state.cf, (uint32_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint32_t *)regPtr == ((uint32_t)-1) / 2);
                    *(int32_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;

        // SBB is just SUB but the 2nd op has cf added to it
        // and
        // of = result || (cf &&  reg == ((uint8_t)-1) / 2)
        case 0x18:
        case 0x19:
        case 0x1a:
        case 0x1b:
        case 0x1c:
        case 0x1d:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:8];

                    __builtin_sub_overflow((int8_t)rmReadValue, *(int8_t *)regPtr + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    __builtin_sub_overflow((int32_t)rmReadValue, *(int32_t *)regPtr + self->state.cf, (int32_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint32_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow((uint8_t)rmReadValue, *(uint32_t *)regPtr + self->state.cf, (uint32_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint32_t)-1) / 2);
                    *(int32_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:8];

                    __builtin_sub_overflow(*(int8_t *)regPtr, (int8_t)rmReadValue + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow(*(uint8_t *)regPtr, (uint8_t)rmReadValue + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:32];

                    __builtin_sub_overflow(*(int32_t *)regPtr, (int32_t)rmReadValue + self->state.cf, (int32_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint32_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow(*(uint32_t *)regPtr, (uint32_t)rmReadValue + self->state.cf, (uint32_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint32_t *)regPtr == ((uint32_t)-1) / 2);
                    *(int32_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];

                    __builtin_sub_overflow(*(int8_t *)regPtr, (int8_t)imm8 + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow(*(uint8_t *)regPtr, (uint8_t)imm8 + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readFourBytesIncIP:&imm32];
                    regPtr =  [self getRegPointer:reg_eax opSize:32];

                    __builtin_sub_overflow(*(int32_t *)regPtr, (int32_t)imm32 + self->state.cf, (int32_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int32_t *)regPtr == ((uint32_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow(*(uint32_t *)regPtr, (uint32_t)imm32 + self->state.cf, (uint32_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint32_t *)regPtr == ((uint32_t)-1) / 2);
                    *(int32_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;

        case 0x20:
        case 0x21:
        case 0x22:
        case 0x23:
        case 0x24:
        case 0x25:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:8];

                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue & *(uint8_t *)regPtr;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    self->state.res = *(uint32_t *)rmWritePtr = (uint32_t)rmReadValue & *(uint32_t *)regPtr;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    self->state.res = *(uint8_t *)regPtr = (uint8_t)rmReadValue & *(uint8_t *)regPtr;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    self->state.res = *(uint32_t *)regPtr = (uint32_t)rmReadValue & *(uint32_t *)regPtr;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];

                    temp8 = (uint8_t)imm8 & *(uint8_t *)regPtr;
                    memcpy((uint8_t *)&regPtr, (uint8_t *)&temp8, sizeof(uint8_t));
                    memcpy((uint8_t *)&self->state.res, (uint8_t *)&temp8, sizeof(uint8_t));

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readFourBytesIncIP:&imm32];
                    regPtr =  [self getRegPointer:reg_eax opSize:32];
                    self->state.res = *(uint32_t *)regPtr = (uint32_t)imm32 & *(uint32_t *)regPtr;

                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;
//            28        r                    L    SUB    r/m8    r8                    o..szapc    o..szapc            Subtract
//            29        r                    L    SUB    r/m16/32    r16/32                    o..szapc    o..szapc            Subtract
//            2A        r                        SUB    r8    r/m8                    o..szapc    o..szapc            Subtract
//            2B        r                        SUB    r16/32    r/m16/32                    o..szapc    o..szapc            Subtract
//            2C                                SUB    AL    imm8                    o..szapc    o..szapc            Subtract
//            2D                                SUB    eAX    imm16/32
        case 0x28:
        case 0x29:
        case 0x2a:
        case 0x2b:
        case 0x2c:
        case 0x2d:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:8];

                    self->state.of = __builtin_sub_overflow((int8_t)rmReadValue, *(int8_t *)regPtr, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr, (uint8_t *)&self->state.res);
                    *(int8_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr = [self getRegPointer:mrm.reg opSize:32];

                    self->state.of = __builtin_sub_overflow((int32_t)rmReadValue, *(int32_t *)regPtr, (int32_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint32_t)rmReadValue, *(uint32_t *)regPtr, (uint32_t *)&self->state.res);
                    *(int32_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:8];

                    self->state.of = __builtin_sub_overflow(*(int8_t *)regPtr, (int8_t)rmReadValue, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow(*(uint8_t *)regPtr, (uint8_t)rmReadValue, (uint8_t *)&self->state.res);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:32];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:32];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                    }

                    regPtr =  [self getRegPointer:mrm.reg opSize:32];

                    self->state.of = __builtin_sub_overflow(*(int32_t *)regPtr, (int32_t)rmReadValue, (int32_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow(*(uint32_t *)regPtr, (uint32_t)rmReadValue, (uint32_t *)&self->state.res);
                    *(int32_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];

                    self->state.of = __builtin_sub_overflow(*(int8_t *)regPtr, (int8_t)imm8, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow(*(uint8_t *)regPtr, (uint8_t)imm8, (uint8_t *)&self->state.res);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readFourBytesIncIP:&imm32];
                    regPtr =  [self getRegPointer:reg_eax opSize:32];

                    self->state.of = __builtin_sub_overflow(*(int32_t *)regPtr, (int32_t)imm32, (int32_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow(*(uint32_t *)regPtr, (uint32_t)imm32, (uint32_t *)&self->state.res);
                    *(int32_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;

        case 0x2e:
            // TODO: Why? Research why some of these opcodes skip the interrup checking step and just restart up here
            // This should be a goto to the top of this step function
            die("Hit an opcode that was not expected");
            break;

        case 0x30:
            // XOR    r/m8    r8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            self->state.res = *((uint8_t *)rmWritePtr) = *((uint8_t *)rmReadPtr) ^ *((uint8_t *)regPtr);

            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x31:
            // XOR    r/m16/32    r16/32
            // Saving value into r/m16/32
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t)); memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            self->state.res = *((dword_t *)rmWritePtr) = *((dword_t *)rmReadPtr) ^ *((dword_t *)regPtr);

            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x32:
            // XOR    r8    r/m8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            }
            self->state.res = *((uint8_t *)regPtr) = *((uint8_t *)regPtr) ^ *((uint8_t *)rmReadPtr);

            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x33:
            // XOR    r16/32    r/m16/32
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            }
            self->state.res = *((dword_t *)regPtr) = *((dword_t *)regPtr) ^ *((dword_t *)rmReadPtr);

            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x34:
            // XOR    Al    imm8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:reg_eax opSize:8];

            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }

            *((uint8_t *)regPtr) = *((uint8_t *)regPtr) ^ (uint8_t)imm8;
            self->state.res = *((int8_t *)regPtr);

            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x35:
            // XOR    EAX    imm8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:reg_eax opSize:32];

            if ([self readFourBytesIncIP:&imm32]) {
                SEGFAULT
            }

            *((uint32_t *)regPtr) = *((uint32_t *)regPtr) ^ (uint32_t)imm32;
            self->state.res = *((int32_t *)regPtr);

            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x38:
            // CMP    r/m8    r8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            self->state.cf = __builtin_sub_overflow(*((uint8_t *)rmReadPtr), *((uint8_t *)regPtr), (uint8_t *)&temp8);
            self->state.of = __builtin_sub_overflow(*((int8_t *)rmReadPtr), *((int8_t *)regPtr), (int8_t *)&temp8);
            self->state.res = (int8_t)temp8;
            // sets cf and of

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x39:
            // CMP    r/m16/32    r16/32
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t)); memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            self->state.cf = __builtin_sub_overflow(*((uint32_t *)rmReadPtr), *((uint32_t *)regPtr), (uint32_t *)&temp32);
            self->state.of = __builtin_sub_overflow(*((int32_t *)rmReadPtr), *((int32_t *)regPtr), (int32_t *)&temp32);
            self->state.res = (int32_t)temp32;
            // sets cf and of

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x3a:
            // CMP    r8    r/m8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            self->state.cf = __builtin_sub_overflow(*((uint8_t *)regPtr), *((uint8_t *)rmReadPtr), (uint8_t *)&temp8);
            self->state.of = __builtin_sub_overflow(*((int8_t *)regPtr), *((int8_t *)rmReadPtr), (int8_t *)&temp8);
            self->state.res = (int8_t)temp8;
            // sets cf and of

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x3b:
            // CMP    r16/32    r/m16/32
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t)); memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            self->state.cf = __builtin_sub_overflow(*((uint32_t *)regPtr), *((uint32_t *)rmReadPtr), (uint32_t *)&temp32);
            self->state.of = __builtin_sub_overflow(*((int32_t *)regPtr), *((int32_t *)rmReadPtr), (int32_t *)&temp32);
            self->state.res = (int32_t)temp32;
            // sets cf and of

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x3c:
            // CMP    Al    imm8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:reg_eax opSize:8];

            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }

            self->state.cf = __builtin_sub_overflow(*((uint8_t *)regPtr), (uint8_t)imm8, (uint8_t *)&temp8);
            self->state.of = __builtin_sub_overflow(*((int8_t *)regPtr), (int8_t)imm8, (int8_t *)&temp8);
            self->state.res = (int8_t)temp8;
            // sets cf and of

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x3d:
            // CMP    EAX    imm8
            //
            regPtr = [self getRegPointer:reg_eax opSize:32];

            if ([self readFourBytesIncIP:&imm32]) {
                SEGFAULT
            }

            self->state.cf = __builtin_sub_overflow(*((uint32_t *)regPtr), (uint32_t)imm32, (uint32_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow(*((int32_t *)regPtr), (int32_t)imm32, (int32_t *)&self->state.res);

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;

        case 0x3e:
            // TODO: Why? Research why some of these opcodes skip the interrup checking step and just restart up here
            // This should be a goto to the top of this step function
            die("Hit an opcode that was not expected");
            break;

        case 0x40:
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:
            // INC    r16/32
            opReg = 0x7 & firstOpByte;
            regPtr = [self getRegPointer:opReg opSize:32];
//            *regPtr = *regPtr + 1;
            // No carry flag is set
            // self->state.cf = __builtin_add_overflow(*(uint32_t *)regPtr, (uint32_t)1, (uint32_t *)&self->state.res);
            self->state.of = __builtin_add_overflow(*(int32_t *)regPtr, (int32_t)1, (int32_t *)&self->state.res);
            *regPtr = self->state.res;
            // set the auxillary flag
            self->state.af_ops = 1;
            // set zero flag, sign flag, parity flag
            self->state.zf_res = 1;
            self->state.sf_res = 1;
            self->state.pf_res = 1;

            break;
        case 0x48:
        case 0x49:
        case 0x4a:
        case 0x4b:
        case 0x4c:
        case 0x4d:
        case 0x4e:
        case 0x4f:
            // DEC    r16/32
            opReg = 0x7 & firstOpByte;
            regPtr = [self getRegPointer:opReg opSize:32];
            //            *regPtr = *regPtr + 1;
            // No carry flag is set
            // self->state.cf = __builtin_add_overflow(*(uint32_t *)regPtr, (uint32_t)1, (uint32_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow(*(int32_t *)regPtr, (int32_t)1, (int32_t *)&self->state.res);
            *regPtr = self->state.res;
            // set the auxillary flag
            self->state.af_ops = 1;
            // set zero flag, sign flag, parity flag
            self->state.zf_res = 1;
            self->state.sf_res = 1;
            self->state.pf_res = 1;

            break;
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
            // PUSH    r16/32
            opReg = 0x7 & firstOpByte;
            regPtr = [self getRegPointer:opReg opSize:32];
            if ([self.task userWrite:self->state.esp - 4 buf:regPtr count:4]) {
                SEGFAULT
            }
            // # ifdef BDEBUG
            // CLog(@"PUSHed %x to [%x]\n", *regPtr, self->state.esp - 4);
            // # endif
            self->state.esp -= 4;

            break;
        case 0x58:
        case 0x59:
        case 0x5a:
        case 0x5b:
        case 0x5c:
        case 0x5d:
        case 0x5e:
        case 0x5f:
            // POP    r16/32
            opReg = 0x7 & firstOpByte;
            regPtr = [self getRegPointer:opReg opSize:32];
            if ([self.task userRead:self->state.esp buf:regPtr count:4]) {
                SEGFAULT
            }
            self->state.esp += 4;

            break;

        case 0x60:
            tmpReg = reg_eax;
            do {
                *(int32_t *)[self.task.mem getPointer:self->state.esp type:32] = [self getRegisterValue:tmpReg opSize:32];
                tmpReg += 1;
                self->state.esp -= 4;
            } while (tmpReg != reg_edi);
            break;
        case 0x61:
            tmpReg = reg_edi;
            do {
                [self readFourBytesIncSP:&imm32];
                *(int32_t *)[self getRegPointer:tmpReg opSize:32] = imm32;
                tmpReg -= 1;
            } while (tmpReg != reg_eax);
            break;

        case 0x65:
            addr += self->state.tls_ptr;
            [self step:addr];
            // goto restart;
            break;
        case 0x66:
            return [self step16: addr];
            break;
        case 0x67:
            // TODO: Why? Research why some of these opcodes skip the interrup checking step and just restart up here
            // This should be a goto to the top of this step function
            die("Hit an opcode that was not expected");
            break;
        case 0x68:
            [self readFourBytesIncIP:&imm32];
            [self.task userWrite:self->state.esp - 4 buf:&imm32 count:4];
            self->state.esp -= 4;
            break;
        case 0x69:
            // IMUL
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            [self readFourBytesIncIP:&imm32];

            self->state.cf = self->state.of = __builtin_mul_overflow((int32_t)rmReadValue, (int32_t)imm32, (int32_t *)&self->state.res);
            *(int32_t *)regPtr = (int32_t)self->state.res;
            
            self->state.pf_res = 1;
            self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = 0;
            break;

        case 0x6a:
            [self readByteIncIP:&imm8];
            imm32 = (uint32_t)imm8;
            [self.task userWrite:(self->state.esp - 4) buf:&imm32 count:4];
            self->state.esp -= 4;
            break;
        case 0x6b:
            // IMUL
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            [self readByteIncIP:&imm8];

            self->state.cf = self->state.of = __builtin_mul_overflow((int32_t)rmReadValue, (int8_t)imm8, (int32_t *)&self->state.res);
            self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = 0;
            break;

        case 0x70:
            // JO rel8
            // Jump if overflow flag is set to a relative 8 bit address
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.of) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x71:
            // JNO    rel8
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (!self->state.of) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x72:
            // JB    rel8
            // JNAE    rel8
            // JC    rel8
            // Jump short if below/not above or equal/carry. if CF==1
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.cf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x73:
            // JNB    rel8
            // JAE    rel8
            // JNC    rel8
            // Jump short if not below/above or equal/not carry. if CF==0
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (!self->state.cf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)imm8;
            }
            break;
        case 0x74:
            // JZ    rel8
            // JE    rel8
            // Jump short if zero/equal (ZF==1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.zf_res ? self->state.res == 0 : self->state.zf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x75:
            // JNZ    rel8
            // JNE    rel8
            // Jump short if not zero/not equal (ZF==0)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x76:
            // JBE    rel8
            // JNA    rel8
            // Jump short if below or equal/not above (CF=1 OR ZF=1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x77:
            // JNBE    rel8
            // JA    rel8
            // Jump short if not below or equal/above (CF=0 AND ZF=0)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x78:
            // JS    rel8
            // Jump short if sign (SF=1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (self->state.sf_res ? self->state.res < 0 : self->state.sf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x79:
            // JNS    rel8
            // Jump short if not sign (SF=1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(self->state.sf_res ? self->state.res < 0 : self->state.sf)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7a:
            // JP    rel8
            // JPE    rel8
            // Jump short if parity/parity even (PF=1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (self->state.pf_res ? !__builtin_parity(self->state.res & 0xff) : self->state.pf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7b:
            // JNP    rel8
            // JPO    rel8
            // Jump short if not parity/parity odd (PF=0)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(self->state.pf_res ? !__builtin_parity(self->state.res & 0xff) : self->state.pf)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7c:
            // JL    rel8
            // JNGE    rel8
            // Jump short if less/not greater (SF!=OF)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Use XOR of the sign flag and overflow flag to check if they are not equal because
            // (in any order) 0 ^ 1 is 1       1 ^ 1 is 0         0 ^ 0 is 0
            // Meaning sign flag XOR overflow flag is only true when one is 1 and the other is 0
            if ((self->state.sf_res ? self->state.res == 0 : self->state.sf) ^ self->state.of) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7d:
            // JNL    rel8
            // JGE    rel8
            // Jump short if not less/greater or equal (SF=OF)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (!((self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) ^ self->state.of)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7e:
            // JLE    rel8
            // JNG    rel8
            // Jump short if less or equal/not greater ((ZF=1) OR (SF!=OF))
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.zf_res ? self->state.res == 0 : self->state.zf | ((self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) ^ self->state.of)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7f:
            // JNLE    rel8
            // JG    rel8
            // Jump short if not less nor equal/greater ((ZF=0) AND (SF=OF))
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(((self->state.sf_res ? (int32_t)self->state.res < 0 : self->state.sf) ^ (self->state.of)) | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x80:
            // 0x80 and 0x82 are the same code

            // The opcode 0x83 can be a few different operations
            // The reg bits in the modrm byte are what define which operation this really is
            // ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
            #define MODRM_VAR       mrm
            #define IMM_SZ          8
            #define RM_SZ           8
            #define IMM_READ_METHOD readByteIncIP
            #include "Group1OpCodes.h"
            #undef IMM_READ_METHOD
            #undef MODRM_VAR
            #undef IMM_SZ
            #undef RM_SZ
            break;
        case 0x81:
            // The opcode 0x81 can be a few different operations. Its part of the Group 1 of opcodes
            // http://www.mlsite.net/8086/#tbl_ext
            // The reg bits in the modrm byte are what define which operation this really is
            // ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
            #define MODRM_VAR       mrm
            #define IMM_SZ          32
            #define RM_SZ           32
            #define IMM_READ_METHOD readFourBytesIncIP
            #include "Group1OpCodes.h"
            #undef IMM_READ_METHOD
            #undef MODRM_VAR
            #undef IMM_SZ
            #undef RM_SZ
            break;
        case 0x82:
            #define MODRM_VAR       mrm
            #define IMM_SZ          8
            #define RM_SZ           8
            #define IMM_READ_METHOD readByteIncIP
            #include "Group1OpCodes.h"
            #undef IMM_READ_METHOD
            #undef MODRM_VAR
            #undef IMM_SZ
            #undef RM_SZ
            break;
        case 0x83:
            #define MODRM_VAR       mrm
            #define IMM_SZ          8
            #define RM_SZ           32
            #define IMM_READ_METHOD readByteIncIP
            #include "Group1OpCodes.h"
            #undef IMM_READ_METHOD
            #undef MODRM_VAR
            #undef IMM_SZ
            #undef RM_SZ
            break;
        case 0x84:
            // TEST    r/m8    r8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            self->state.res = (uint8_t)rmReadValue & *(uint8_t *)regPtr;

            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x85:
            // TEST    r/m32    r32
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            self->state.res = (uint32_t)rmReadValue & *(uint32_t *)regPtr;

            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x86:
            // XCHG    r8    r/m8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            temp8 = *(uint8_t *)regPtr;
            *(uint8_t *)regPtr = rmReadValue;
            *(uint8_t *)rmWritePtr = temp8;
            break;
        case 0x87:
            // XCHG    r32    r/m32
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            temp32 = *(uint32_t *)regPtr;
            *(uint32_t *)regPtr = rmReadValue;
            *(uint32_t *)rmWritePtr = temp32;
            break;
        case 0x88:
            // MOV    r/m8    r8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            *((dword_t *)rmWritePtr) = *((dword_t *)regPtr);
            break;
        case 0x89:
            // MOV    r/m16/32/64    r16/32/64
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            *((uint32_t *)rmWritePtr) = *((uint32_t *)regPtr);
            break;
        case 0x8a:
            // MOV    r8    r/m8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                // rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                /*
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                */
                rmReadValue = [self.task userReadOneBytes:addr];
            }
            // memcpy(regPtr, rmReadPtr, sizeof(uint32_t));
            *(uint8_t *)regPtr = (uint8_t)rmReadValue;
            break;
        case 0x8b:
            // MOV    r16/32    r/m16/32
            // DBADDR(0xf7fc3421 + 1) // + 1 for opcode read
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                //CLog(@"P: %d 0x8b Mov %@, %@\n", self.task.pid.id, [CPU getRegisterString:mrm.base], [CPU getRegisterString:mrm.base]);
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                rmReadValue = [self.task userReadFourBytes:addr];
                /*
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                */
                //CLog(@"P: %d 0x8b Mov %@, [%x] = %x\n", self.task.pid.id, [CPU getRegisterString:mrm.reg], modrmAddress, *((dword_t *)rmReadPtr));
            }
            *regPtr = rmReadValue;
            break;
        case 0x8c:
            // MOV    r16/32    Sreg
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            if (mrm.reg != reg_ebp) {
                self->state.eip = saved_ip;
                return INT_UNDEFINED;
            }
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            *((dword_t *)rmWritePtr) = self->state.gs;
            break;

        // This one is out of order because 8c and 8e are the inverse of each other
        case 0x8d:
            // LEA    r16/32    m
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                self->state.eip = saved_ip;
                return INT_UNDEFINED;
            }

            addr = [self getModRMAddress:mrm opSize:32];

            *((dword_t *)regPtr) = addr;
            break;
        case 0x8e:
            // MOV    Sreg    r16/32
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            if (mrm.reg != reg_ebp) {
                self->state.eip = saved_ip;
                return INT_UNDEFINED;
            }
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            }
            self->state.gs = *((dword_t *)rmReadPtr);
            break;

        case 0x8f:
            // POP r/m32
            // Pop esp into temp32
            // move temp32 in mrmwriteptr
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            [self readFourBytesIncSP:&temp32];
            *(uint32_t *)rmWritePtr = temp32;
            break;

        case 0x90:
        case 0x91:
        case 0x92:
        case 0x93:
        case 0x94:
        case 0x95:
        case 0x96:
        case 0x97:
            opReg = 0x7 & firstOpByte;
            temp32 = [self getRegPointer:opReg opSize:32];
            *(uint32_t *)[self getRegPointer:opReg opSize:32] = ((uint32_t)self->state.eax);
            *(uint32_t *)&self->state.eax = temp32;
            break;
        case 0x98:
            *(uint32_t *)[self getRegPointer:reg_eax opSize:32] = (uint16_t)[self getRegisterValue:reg_eax opSize:16];
            break;
        case 0x99:
            // TODO: Remove this ternary should b -1 always right?
            // TODO: Why is this here?
            *(uint32_t *)[self getRegPointer:reg_edx opSize:32] = ([self getRegisterValue:reg_eax opSize:32] & (1 << (32 - 1)) ? (uint32_t)-1 : 0);
            break;
        case 0x9b:
            NO_ERR_UN_IMP
            break;
        case 0x9c:
            collapse_flags(&self->state);
            [self.task userWrite:(self->state.esp - 4) buf:&self->state.eflags count:4]; // sizeof(self->state.eflags)]
            self->state.esp -= 4;
            break;
        case 0x9d:
            [self.task userRead:self->state.esp buf:&self->state.eflags count:4];
            self->state.esp += 4;
            expand_flags(&self->state);
            break;
        case 0x9e:
            self->state.eflags &= 0xffffff00 | ~0b11010101;
            self->state.eflags |= self->state.ah & 0b11010101;
            expand_flags(&self->state);
            break;

        case 0xa0:
            [self readFourBytesIncIP:&imm32];

            addr += imm32;

            moffs8 = [self.task.mem getPointer:addr type:MEM_READ];
            *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = *(uint8_t *)moffs8;
            break;

        case 0xa1:
            [self readFourBytesIncIP:&imm32];

            addr += imm32;

            moffs32 = [self.task.mem getPointer:addr type:MEM_READ];
            *(uint32_t *)[self getRegPointer:reg_eax opSize:32] = *(uint32_t *)moffs32;
            break;

        case 0xa2:
            [self readFourBytesIncIP:&imm32];

            addr += imm32;

            moffs8 = [self.task.mem getPointer:addr type:MEM_WRITE];
            *((uint8_t *)moffs8) = (uint8_t)[self getRegisterValue:reg_eax opSize:8];
            break;

        case 0xa3:
            [self readFourBytesIncIP:&imm32];

            addr += imm32;

            moffs32 = [self.task.mem getPointer:addr type:MEM_WRITE];
            *moffs32 = [self getRegisterValue:reg_eax opSize:32];
            break;

        case 0xa4:
            *(uint8_t *)[self getRegisterPointedMemory:reg_edi registerSize:8 accessType:MEM_WRITE] = *(uint8_t *)[self getRegisterPointedMemory:reg_esi registerSize:8 accessType:MEM_READ];

            self->state.esi += self->state.df ? -1 : 1;
            self->state.edi += self->state.df ? -1 : 1;
            break;

        case 0xa5:
            *(uint32_t *)[self getRegisterPointedMemory:reg_edi registerSize:32 accessType:MEM_WRITE] = *(uint32_t *)[self getRegisterPointedMemory:reg_esi registerSize:32 accessType:MEM_READ];

            self->state.esi += self->state.df ? -4 : 4;
            self->state.edi += self->state.df ? -4 : 4;
            break;

        case 0xa6:
            self->state.cf = __builtin_sub_overflow(*(uint8_t *)[self getRegisterPointedMemory:reg_esi registerSize:8 accessType:MEM_READ], *(uint8_t *)[self getRegisterPointedMemory:reg_edi registerSize:8 accessType:MEM_READ], (uint8_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow(*(int8_t *)[self getRegisterPointedMemory:reg_esi registerSize:8 accessType:MEM_READ], *(int8_t *)[self getRegisterPointedMemory:reg_edi registerSize:8 accessType:MEM_READ], (int8_t *)&self->state.res);

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;

            self->state.esi += self->state.df ? -1 : 1;
            self->state.edi += self->state.df ? -1 : 1;
            break;

        case 0xa7:
            self->state.cf = __builtin_sub_overflow(*(uint32_t *)[self getRegisterPointedMemory:reg_esi registerSize:32 accessType:MEM_READ], *(uint32_t *)[self getRegisterPointedMemory:reg_edi registerSize:32 accessType:MEM_READ], (uint32_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow(*(int32_t *)[self getRegisterPointedMemory:reg_esi registerSize:32 accessType:MEM_READ], *(int32_t *)[self getRegisterPointedMemory:reg_edi registerSize:32 accessType:MEM_READ], (int32_t *)&self->state.res);

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;

            self->state.esi += self->state.df ? -4 : 4;
            self->state.edi += self->state.df ? -4 : 4;
            break;

        case 0xa8:
            [self readByteIncIP:&imm8];
            self->state.res = [self getRegisterValue:reg_eax opSize:8] & imm8;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0xa9:
            [self readFourBytesIncIP:&imm32];
            self->state.res = [self getRegisterValue:reg_eax opSize:32] & imm32;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;

        case 0xaa:
            [self.task userWrite:(uint8_t)[self getRegisterValue:reg_edi opSize:8] buf:(uint8_t *)[self getRegPointer:reg_eax opSize:8] count:1];
            self->state.edi += self->state.df ? -1 : 1;
            break;

        case 0xab:
            [self.task userWrite:(uint32_t)[self getRegisterValue:reg_edi opSize:32] buf:(uint32_t *)[self getRegPointer:reg_eax opSize:32] count:4];
            self->state.edi += self->state.df ? -4 : 4;
            break;

        case 0xac:
            [self.task userWrite:(uint8_t)[self getRegisterValue:reg_esi opSize:8] buf:(uint8_t *)[self getRegPointer:reg_eax opSize:8] count:1];
            self->state.edi += self->state.df ? -1 : 1;
            break;

        case 0xad:
            [self.task userWrite:(uint32_t)[self getRegisterValue:reg_esi opSize:32] buf:(uint32_t *)[self getRegPointer:reg_eax opSize:32] count:4];
            self->state.edi += self->state.df ? -4 : 4;
            break;

        case 0xae:
            // SCAS      m8    eA
            // Scan String
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            // regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                // This shouldnt happen?
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                die("Unexpected opcode");
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            // temp32 = [edi] == the value of what is in the memory location that edi points to
            temp32 = [self.task userReadOneBytes:(uint8_t)[self getRegisterValue:reg_edi opSize:8]];

            self->state.cf = __builtin_sub_overflow((uint8_t)temp32, *((uint8_t *)[self getRegPointer:reg_eax opSize:8]), (uint8_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow( (int8_t)temp32,  *((int8_t *)[self getRegPointer:reg_eax opSize:8]),  (int8_t *)&self->state.res);

            self->state.edi += self->state.df ? -4 : 4;

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;

        case 0xaf:
            // SCAS      m16/32    eAX
            // SCASD     m32       EAX
            // Scan String
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            // regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                // This shouldnt happen?
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t)); memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                die("Unexpected opcode");
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            // temp32 = [edi] == the value of what is in the memory location that edi points to
            temp32 = [self.task userReadFourBytes:(uint32_t)[self getRegisterValue:reg_edi opSize:32]];

            self->state.cf = __builtin_sub_overflow((uint32_t)temp32, *((uint32_t *)[self getRegPointer:reg_eax opSize:32]), (uint32_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow( (int32_t)temp32,  *((int32_t *)[self getRegPointer:reg_eax opSize:32]),  (int32_t *)&self->state.res);

            self->state.edi += self->state.df ? -4 : 4;

            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;

        case 0xb0:
        case 0xb1:
        case 0xb2:
        case 0xb3:
        case 0xb4:
        case 0xb5:
        case 0xb6:
        case 0xb7:
            [self readByteIncIP:&imm8];
            rmWritePtr = [self getRegPointer:(0x7 & firstOpByte) opSize:8];
            *(uint8_t *)rmWritePtr = (uint8_t)imm8;
            break;

        case 0xb8:
        case 0xb9:
        case 0xba:
        case 0xbb:
        case 0xbc:
        case 0xbd:
        case 0xbe:
        case 0xbf:
            [self readFourBytesIncIP:&imm32];
            rmWritePtr = [self getRegPointer:(0x7 & firstOpByte) opSize:32];
            *(uint32_t *)rmWritePtr = (uint32_t)imm32;
            break;

        case 0xc0:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            // NOTE: In this case I am reading the 4 byte immediate value into the temp32 variable
            // which is unusal
            // I am doing this to re use code I wrote earlier for 0xd3 which will use the temp32 variable
            // as the argument for this operations
            [self readByteIncIP:&temp8];

            switch (mrm.reg) {
                case 0x0:
                    *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8 | (uint8_t)rmReadValue >> (8 - (uint8_t)temp8);
                    self->state.cf = (uint8_t)rmReadValue & 1;
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                    }
                case 0x1:
                    *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8 | (uint8_t)rmReadValue << (8 - temp8);
                    self->state.cf = (uint8_t)rmReadValue >> (8 - 1);
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ ((uint8_t)rmReadValue & 1);
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (8 - 1);
                    self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x5:
                    self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (temp8 - 1) & 1;
                    self->state.of = (uint8_t)rmReadValue >> (8 - 1);
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x7:
                    self->state.cf = ((uint8_t)rmReadValue >> (temp8 - 1)) & 1;
                    self->state.of = 0;
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;

        case 0xc1:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            // NOTE: In this case I am reading the 4 byte immediate value into the temp8 variable
            // which is unusal
            // I am doing this to re use code I wrote earlier for 0xd3 which will use the temp8 variable
            // as the argument for this operations
            [self readByteIncIP:&temp8];

            switch (mrm.reg) {
                case 0x0:
                    *rmWritePtr = *rmReadPtr << temp8 | *rmReadPtr >> (8 - temp8);
                    self->state.cf = *rmReadPtr & 1;
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ *rmReadPtr >> (8 - 1);
                    }
                    break;
                case 0x1:
                    *rmWritePtr = *rmReadPtr >> temp8 | *rmReadPtr << (8 - temp8);
                    self->state.cf = *rmReadPtr >> (8 - 1);
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ (*rmReadPtr & 1);
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    self->state.cf = *rmReadPtr << (temp8 - 1) >> (8 - 1);
                    self->state.of = self->state.cf ^ *rmReadPtr >> (8 - 1);
                    self->state.res = *rmWritePtr = *rmReadPtr << temp8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x5:
                    self->state.cf = *rmReadPtr << (temp8 - 1) >> (temp8 - 1) & 1;
                    self->state.of = *rmReadPtr >> (8 - 1);
                    self->state.res = *rmWritePtr = *rmReadPtr >> temp8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;                    break;
                case 0x7:
                    self->state.cf = (*rmReadPtr >> (temp8 - 1)) & 1;
                    self->state.of = 0;
                    self->state.res = *rmWritePtr = *rmReadPtr >> temp8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;

        case 0xc2:
            // RETN imm16
            [self readTwoBytesIncIP:&imm16];
            [self readFourBytesIncSP:&self->state.eip];
            self->state.esp += (uint16_t)imm16;
            break;

        case 0xc3:
            // RETN
            [self readFourBytesIncSP:&self->state.eip];
            break;

        case 0xc6:
            // MOV    r/m8    imm8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            [self readByteIncIP:&imm8];
            *((uint8_t *)rmWritePtr) = (uint8_t)imm8;
            break;

        case 0xc7:
            // MOV    r/m16/32    imm16/32
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            [self readFourBytesIncIP:&imm32];
            *((uint32_t *)rmWritePtr) = (uint32_t)imm32;
            break;

        case 0xc9:
            // LEAVE    eBP
            self->state.esp = self->state.ebp;
            [self readFourBytesIncSP:&self->state.ebp];
            break;

        case 0xcd:
            // INT   imm8 - THIS IS THE SYSCALL Op
            [self readByteIncIP:&imm8];
            return imm8;
            break;

        case 0xd0:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch (mrm.reg) {
                case 0x0:
                    temp8 = 1;
                    if (temp8) {
                        *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8 | (uint8_t)rmReadValue >> (8 - (uint8_t)temp8);
                        self->state.cf = (uint8_t)rmReadValue & 1;
                        if (temp8 == 1) {
                            self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                        }
                    }
                    break;
                case 0x1:
                    temp8 = 1;
                    if (temp8) {
                        *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8 | (uint8_t)rmReadValue << (8 - temp8);
                        self->state.cf = (uint8_t)rmReadValue >> (8 - 1);
                        if (temp8 == 1) {
                            self->state.of = self->state.cf ^ ((uint8_t)rmReadValue & 1);
                        }
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    temp8 = 1;
                    if (temp8) {
                        self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (8 - 1);
                        self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                        self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x5:
                    temp8 = 1;
                    if (temp8) {
                        self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (temp8 - 1) & 1;
                        self->state.of = (uint8_t)rmReadValue >> (8 - 1);
                        self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x7:
                    temp8 = 1;
                    if (temp8) {
                        self->state.cf = ((uint8_t)rmReadValue >> (temp8 - 1)) & 1;
                        self->state.of = 0;
                        self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;

        case 0xd1:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch (mrm.reg) {
                case 0x0:
                    temp32 = 1;
                    if (temp32) {
                        *rmWritePtr = *rmReadPtr << temp32 | *rmReadPtr >> (32 - temp32);
                        self->state.cf = *rmReadPtr & 1;
                        if (temp32 == 1) {
                            self->state.of = self->state.cf ^ *rmReadPtr >> (32 - 1);
                        }
                    }
                    break;
                case 0x1:
                    temp32 = 1;
                    if (temp32) {
                        *rmWritePtr = *rmReadPtr >> temp32 | *rmReadPtr << (32 - temp32);
                        self->state.cf = *rmReadPtr >> (32 - 1);
                        if (temp32 == 1) {
                            self->state.of = self->state.cf ^ (*rmReadPtr & 1);
                        }
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    temp32 = 1;
                    if (temp32) {
                        self->state.cf = *rmReadPtr << (temp32 - 1) >> (32 - 1);
                        self->state.of = self->state.cf ^ *rmReadPtr >> (32 - 1);
                        self->state.res = *rmWritePtr = *rmReadPtr << temp32;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x5:
                    temp32 = 1;
                    if (temp32) {
                        self->state.cf = *rmReadPtr << (temp32 - 1) >> (temp32 - 1) & 1;
                        self->state.of = *rmReadPtr >> (32 - 1);
                        self->state.res = *rmWritePtr = *rmReadPtr >> temp32;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x7:
                    temp32 = 1;
                    if (temp32) {
                        self->state.cf = (*rmReadPtr >> (temp32 - 1)) & 1;
                        self->state.of = 0;
                        self->state.res = *rmWritePtr = *rmReadPtr >> temp32;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;

        case 0xd2:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            temp8 = *(uint8_t *)[self getRegPointer:reg_ecx opSize:8] % 8;

            if (temp8 == 0) break;

            switch (mrm.reg) {
                case 0x0:
                    *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8 | (uint8_t)rmReadValue >> (8 - (uint8_t)temp8);
                    self->state.cf = (uint8_t)rmReadValue & 1;
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                    }
                case 0x1:
                    *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8 | (uint8_t)rmReadValue << (8 - temp8);
                    self->state.cf = (uint8_t)rmReadValue >> (8 - 1);
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ ((uint8_t)rmReadValue & 1);
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (8 - 1);
                    self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x5:
                    self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (temp8 - 1) & 1;
                    self->state.of = (uint8_t)rmReadValue >> (8 - 1);
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x7:
                    self->state.cf = ((uint8_t)rmReadValue >> (temp8 - 1)) & 1;
                    self->state.of = 0;
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;

        case 0xd3:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            // temp32 = *(uint32_t *)[self getRegPointer:reg_ecx opSize:8] % 32;
            temp8 = self->state.cl % 32; // This is the shift count

            switch (mrm.reg) {
                case 0x0:
                    if (temp8 != 0) {
                        *rmWritePtr = *rmReadPtr << temp8 | *rmReadPtr >> (32 - temp8);
                        self->state.cf = *rmReadPtr & 1;
                        if (temp32 == 1) {
                            self->state.of = self->state.cf ^ *rmReadPtr >> (32 - 1);
                        }
                    }
                    break;
                case 0x1:
                    if (temp8 != 0) {
                        *rmWritePtr = *rmReadPtr >> temp8 | *rmReadPtr << (32 - temp8);
                        self->state.cf = *rmReadPtr >> (32 - 1);
                        if (temp8 == 1) {
                            self->state.of = self->state.cf ^ (*rmReadPtr & 1);
                        }
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    if (temp8 != 0) {
                        self->state.cf = (*rmReadPtr << (temp8 - 1)) >> (32 - 1);
                        self->state.of = (self->state.cf ^ *rmReadPtr) >> (32 - 1);
                        self->state.res = *rmWritePtr = *rmReadPtr << temp8;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x5:
                    if (temp8 != 0) {
                        self->state.cf = *rmReadPtr << (temp8 - 1) >> (temp8 - 1) & 1;
                        self->state.of = *rmReadPtr >> (32 - 1);
                        self->state.res = *rmWritePtr = *rmReadPtr >> temp8;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x7:
                    if (temp8 != 0) {
                        self->state.cf = (*rmReadPtr >> (temp8 - 1)) & 1;
                        self->state.of = 0;
                        self->state.res = *rmWritePtr = *rmReadPtr >> temp8;

                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;

        // FPU Instructions Starts here

        case 0xd8:
            // http://ref.x86asm.net/coder32.html#xD8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x2:
                    self->state.c1 = self->state.c2 = 0;
                    if (mrm.type == modrm_register) {
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.c0 = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], f80_from_double(tempfloat));
                        self->state.c0 = f80_eq(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x3:
                    self->state.c1 = self->state.c2 = 0;
                    if (mrm.type == modrm_register) {
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.c0 = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], f80_from_double(tempfloat));
                        self->state.c0 = f80_eq(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.fp[self->state.top] = f80_sub(f80_from_double(tempfloat), self->state.fp[self->state.top]);
                    }
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x7:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.fp[self->state.top] = f80_div(f80_from_double(tempfloat), self->state.fp[self->state.top]);
                    }
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xd9:
            // http://ref.x86asm.net/coder32.html#xD9
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        tempfloat80 = self->state.fp[self->state.top + mrm.rm_opcode];
                        self->state.top -= 1;
                        self->state.fp[self->state.top] = tempfloat80;
                    } else {
                        self->state.top -= 1;
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.fp[self->state.top] = f80_from_double(tempfloat);
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        tempfloat80 = self->state.fp[self->state.top];
                        self->state.fp[self->state.top] = self->state.fp[self->state.top + mrm.rm_opcode];
                        self->state.fp[self->state.top + mrm.rm_opcode] = tempfloat80;
                    } else {
                        die("Shouldnt happen");
                    }
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.fp[self->state.top] = f80_from_double(tempfloat);
                    }
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:4];
                        self->state.fp[self->state.top] = f80_from_double(tempfloat);
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    die("Shoudlnt happen");
                    break;
                case 0x5:
                    // FCW    x87 FPU Control Word (16 bits). See Figure 8-6 in the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 1, for the layout of the x87 FPU control word.
                    // Not fxsave op but load:
                    // https://www.felixcloutier.com/x86/fxsave
                    [self.task userRead:addr buf:&self->state.fcw count:2];
                    break;
                case 0x6:
                    die("Shoudlnt happen");
                    break;
                case 0x7:
                    // fxsave
                    [self.task userWrite:addr buf:&self->state.fcw count:2];
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xda:
            // http://ref.x86asm.net/coder32.html#xDA
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch(mrm.opcode) {
                case 0x0:
                    [self.task userRead:addr buf:&temp32 count:4];
                    self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], f80_from_int(temp32));
                    break;
                case 0x1:
                    [self.task userRead:addr buf:&temp32 count:4];
                    self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], f80_from_int(temp32));
                    break;
                case 0x2:
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x3:
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    self->state.top += 1;
                    break;
                case 0x4:
                    [self.task userRead:addr buf:&temp32 count:4];
                    self->state.fp[self->state.top] = f80_sub(f80_from_int(temp32), self->state.fp[self->state.top]);
                    break;
                case 0x5:
                    [self.task userRead:addr buf:&temp32 count:4];
                    self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], f80_from_int(temp32));
                    break;
                case 0x6:
                    [self.task userRead:addr buf:&temp32 count:4];
                    self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], f80_from_int(temp32));
                    break;
                case 0x7:
                    [self.task userRead:addr buf:&temp32 count:4];
                    self->state.fp[self->state.top] = f80_div(f80_from_int(temp32), self->state.fp[self->state.top]);
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xdb:
            // http://ref.x86asm.net/coder32.html#xDB
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch(mrm.opcode) {
                case 0x0:
                    [self.task userRead:addr buf:&temp32 count:4];
                    tempfloat80 = f80_from_int(temp32);
                    self->state.top -= 1;
                    self->state.fp[self->state.top] = tempfloat80;
                    break;
                case 0x1:
                    die("shouldnt happen?");
                    break;
                case 0x2:
                    temp32 = f80_to_int(self->state.fp[self->state.top]);
                    [self.task userWrite:addr buf:&temp32 count:4];
                    break;
                case 0x3:
                    temp32 = f80_to_int(self->state.fp[self->state.top]);
                    [self.task userWrite:addr buf:&temp32 count:4];
                    self->state.top += 1;
                    break;
                case 0x4:
                    die("shouldnt happen?");
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.zf = f80_eq(self->state.fp[self->state.top + 0], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.cf = f80_lt(self->state.fp[self->state.top + 0], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.pf = 0;
                        self->state.pf_res = 0;
                    } else {
                        die("shouldnt happen?");
                    }
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.zf = f80_eq(self->state.fp[self->state.top + 0], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.cf = f80_lt(self->state.fp[self->state.top + 0], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.pf = 0;
                        self->state.pf_res = 0;
                    } else {
                        die("shouldnt happen?");
                    }
                    break;
                case 0x7:
                    [self.task userRead:addr buf:&self->state.fp[self->state.top] count:10];
                    self->state.top += 1;
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xdc:
            // http://ref.x86asm.net/coder32.html#xDC
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        tempfloat80 = f80_from_double(tempdouble);
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], tempfloat80);
                        self->state.c1 = 0;
                        self->state.c2 = 0;
                        self->state.c3 = f80_eq(self->state.fp[self->state.top], tempfloat80);
                    }
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        tempfloat80 = f80_from_double(tempdouble);
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], tempfloat80);
                        self->state.c1 = 0;
                        self->state.c2 = 0;
                        self->state.c3 = f80_eq(self->state.fp[self->state.top], tempfloat80);
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], self->state.fp[self->state.top]);
                    }
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x7:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_div(f80_from_double(tempdouble), self->state.fp[self->state.top]);
                    }
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xdd:
            // http://ref.x86asm.net/coder32.html#xDD
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {

                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        tempfloat80 = f80_from_double(tempdouble);
                        self->state.top -= 1;
                        self->state.fp[self->state.top] = tempfloat80;
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        tempdouble = f80_to_double(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&tempdouble count:8];
                    }
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        tempdouble = f80_to_double(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&tempdouble count:8];
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.c1 = 0;
                        self->state.c2 = 0;
                        self->state.c3 = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        die("shoudlnt happen");
                    }
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.c1 = 0;
                        self->state.c2 = 0;
                        self->state.c3 = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        die("shoudlnt happen");
                    }
                    self->state.top += 1;
                    break;
                case 0x6:
                    die("shouldnt happen");
                    break;
                case 0x7:
                    die("shouldnt happen");
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xde:
            // http://ref.x86asm.net/coder32.html#xDE
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_add(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top] = f80_add(tempfloat80, self->state.fp[self->state.top]);;
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_mul(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_mul(tempfloat80, self->state.fp[self->state.top]);
                    }
                    self->state.top += 1;
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        self->state.eip = saved_ip;
                        return INT_UNDEFINED;
                    }
                    self->state.top += 1;
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        self->state.eip = saved_ip;
                        return INT_UNDEFINED;
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_sub(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_sub(self->state.fp[self->state.top], tempfloat80);
                    }
                    self->state.top += 1;
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_sub(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_sub(tempfloat80, self->state.fp[self->state.top]);
                    }
                    self->state.top += 1;
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_div(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_div(self->state.fp[self->state.top], tempfloat80);
                    }
                    self->state.top += 1;
                    break;
                case 0x7:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_div(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_div(tempfloat80, self->state.fp[self->state.top]);
                    }
                    self->state.top += 1;
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xdf:
            // http://ref.x86asm.net/coder32.html#xDF
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        self->state.top += 1;
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.top -= 1;
                        self->state.fp[self->state.top] = tempfloat80;
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        die("Shouldnt happen");
                    } else {
                        die("Shouldnt happen");
                    }
                    self->state.top += 1;
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        temp16 = f80_to_int(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&temp16 count:2];
                    }
                    self->state.top += 1;
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        temp16 = f80_to_int(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&temp16 count:2];
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        die("Could happen, just remove this if block for only the else block");
                    }
                    self->state.top += 1;
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.zf = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.cf = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.pf = 0;
                        self->state.pf_res = 0;
                        self->state.top += 1;
                    } else {
                        [self.task userRead:addr buf:&temp64 count:8];
                        tempfloat80 = f80_from_int(temp64);
                        self->state.top -= 1;
                        self->state.fp[self->state.top] = tempfloat80;
                    }
                    self->state.top += 1;
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.zf = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.cf = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.pf = 0;
                        self->state.pf_res = 0;
                        self->state.top += 1;
                    } else {
                        die("Could happen, just remove this if block for only the else block");
                    }
                    self->state.top += 1;
                    break;
                case 0x7:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        temp64 = f80_to_int(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&temp64 count:8];
                        self->state.top += 1;
                    }
                    self->state.top += 1;
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;

        // FPU Instructions Ends Here

        case 0xe3:
            // JCXZ     rel8    CX
            // JECXZ    rel8    ECX
            // Jump short if eCX register is 0
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.ecx == 0) {
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0xe8:
            // CALL    rel16/32
            if ([self readFourBytesIncIP:&imm32]) {
                SEGFAULT
            }
            if ([self.task userWrite:self->state.esp - 4 buf:&self->state.eip count:4]) {
                SEGFAULT
            }
            self->state.esp -= 4;

            self->state.eip += (uint32_t)(int32_t)imm32;
            // TODO: If this is a 16bit CALL then & eip by 0xffff after this eip += imm
            break;

        case 0xe9:
            // JMP    rel16/32
            if ([self readFourBytesIncIP:&imm32]) {
                SEGFAULT
            }
            self->state.eip += (uint32_t)(int32_t)imm32;
            break;

        case 0xeb:
            // JMP    rel8
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            self->state.eip += (uint32_t)(int8_t)imm8;
            break;
        case 0xf6:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch (mrm.reg) {
                case 0x0:
                case 0x1:
                    // TEST    r/m8    imm8
                    [self readByteIncIP:&imm8];

                    self->state.res = (uint8_t)rmReadValue & (uint8_t)imm8;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    break;
                case 0x2:
                    // NOT    r/m8
                    *(int8_t *)rmWritePtr = ~(int8_t)rmReadValue;
                    break;
                case 0x3:
                    // NEG    r/m8
                    // 2's compliment negation
                    [self readByteIncIP:&imm8];

                    self->state.of = __builtin_sub_overflow((int8_t)0, (int8_t)rmReadValue, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint8_t)0, (uint8_t)rmReadValue, (uint8_t *)&self->state.res);

                    *(int8_t *)rmWritePtr = (int8_t)self->state.res;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af_ops = 0;
                    break;
                case 0x4:
                    // MUL    AX    AL * r/m8
                    // Unsigned multiply
                    temp64 = (*(uint8_t *)[self getRegPointer:reg_eax opSize:8] * (uint64_t)((uint8_t)rmReadValue));

                    *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = temp32;
                    *(uint8_t *)[self getRegPointer:reg_edx opSize:8] = temp32 >> 8;

                    FFLog(@"\n\n\n  Check this OpCode result out! Is it correct? F6 /4    MUL r/m8   \n\n\n\n");
                    __debugbreak();

                    // TODO: Was implemented as:
                    // uint64_t tmp = ((uint8_t)cpu->eax) * (uint64_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return INT_GPF; } val; }));
                    // *(uint8_t *)&cpu->eax = tmp;
                    // *(uint8_t *)&cpu->edx = tmp >> 8;

                    self->state.cf = self->state.of = ((int32_t)temp64 != (uint32_t)temp64);
                    self->state.af = self->state.af_ops = 0;
                    self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    // IMUL    AX    AL * r/m8
                    // Signed multiply

                    // TODO: This outer int64_t cast is unnecessary?
                    temp64 = (int64_t)(*(int8_t *)[self getRegPointer:reg_eax opSize:8] * (int64_t)((int8_t)rmReadValue));

                    *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = temp32;
                    *(uint8_t *)[self getRegPointer:reg_edx opSize:8] = temp32 >> 8;

                    FFLog(@"\n\n\n  Check this OpCode result out! Is it correct? F6 /5    IMUL r/m8   \n\n\n\n");
                    __debugbreak();

                    // TODO: Does this of/cf check actually do anything?
                    self->state.cf = self->state.of = ((int32_t)temp64 != temp64);
                    self->state.af = self->state.af_ops = 0;
                    self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x6:
                    // DIV    AX    AL * r/m8
                    // Unsigned Divide
                    do {
                        divisor8 = (int8_t)rmReadValue;
                        // Divide by 0
                        if (divisor8 == 0) {
                            //break;
                            return INT_DIV;
                        }

                        FFLog(@"\n\n\n  Check this op! \n\n\n");
                        __debugbreak();

                        // Combine al and dl back into one 16 bit unsigned int
                        dividend16 = (*(uint8_t *)[self getRegPointer:reg_eax opSize:8]) | ((*(uint8_t *)[self getRegPointer:reg_edx opSize:8]) << 8);

                        *(uint8_t *)[self getRegPointer:reg_edx opSize:8] = dividend16 % (uint8_t)rmReadValue;
                        *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = dividend16 / (uint8_t)rmReadValue;
                    } while (0);
                    break;
                case 0x7:
                    // IDIV    AX    AL * r/m8
                    // Signed Divide
                    do {
                        divisor8 = (int8_t)rmReadValue;
                        // Divide by 0
                        if (divisor8 == 0) {
                            //break;
                            return INT_DIV;
                        }

                        FFLog(@"\n\n\n  Check this op! \n\n\n");
                        __debugbreak();

                        // Combine al and dl back into one 16 bit unsigned int
                        dividend16 = (*(uint8_t *)[self getRegPointer:reg_eax opSize:8]) | ((*(uint8_t *)[self getRegPointer:reg_edx opSize:8]) << 8);

                        *(uint8_t *)[self getRegPointer:reg_edx opSize:8] = dividend16 % (uint8_t)rmReadValue;
                        *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = dividend16 / (uint8_t)rmReadValue;
                        // Should check is AL is > 0x7F of if int8_t al != uint8_t al maybe
                    } while (0);
                    break;
                default:
                    die("Impossible opcode encountered");
                    break;
            }
            break;
        case 0xf7:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch (mrm.reg) {
                case 0x0:
                case 0x1:
                    // TEST    r/m32    imm8
                    [self readFourBytesIncIP:&imm32];

                    self->state.res = (uint32_t)rmReadValue & (uint32_t)imm32;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    break;
                case 0x2:
                    // NOT    r/m32
                    *(int32_t *)rmWritePtr = ~(int32_t)rmReadValue;
                    break;
                case 0x3:
                    // NEG    r/m32
                    // 2's compliment negation
                    self->state.of = __builtin_sub_overflow((int32_t)0, (int32_t)rmReadValue, (int32_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint32_t)0, (uint32_t)rmReadValue, (uint32_t *)&self->state.res);

                    *(int32_t *)rmWritePtr = (int32_t)self->state.res;

                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af_ops = 0;
                    break;
                case 0x4:
                    // MUL    AX    AL * r/m32
                    // Unsigned multiply
                    temp64 = (*(uint32_t *)[self getRegPointer:reg_eax opSize:32] * (uint64_t)((uint32_t)rmReadValue));

                    *(uint32_t *)[self getRegPointer:reg_eax opSize:32] = temp32;
                    *(uint32_t *)[self getRegPointer:reg_edx opSize:32] = temp32 >> 8;

                    FFLog(@"\n\n\n  Check this OpCode result out! Is it correct? F6 /4    MUL r/m8   \n\n\n\n");
                    __debugbreak();

                    self->state.cf = self->state.of = ((int32_t)temp64 != (uint32_t)temp64);
                    self->state.af = self->state.af_ops = 0;
                    self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    // IMUL    AX    AL * r/m32
                    // Signed multiply

                    // TODO: This outer int64_t cast is unnecessary?
                    temp64 = (int64_t)(*(int32_t *)[self getRegPointer:reg_eax opSize:32] * (int64_t)((int32_t)rmReadValue));

                    *(uint32_t *)[self getRegPointer:reg_eax opSize:32] = temp32;
                    *(uint32_t *)[self getRegPointer:reg_edx opSize:32] = temp32 >> 32;

                    FFLog(@"\n\n\n  Check this OpCode result out! Is it correct? F6 /5    IMUL r/m8   \n\n\n\n");
                    __debugbreak();

                    // TODO: Does this of/cf check actually do anything?
                    self->state.cf = self->state.of = ((int32_t)temp64 != temp64);
                    self->state.af = self->state.af_ops = 0;
                    self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x6:
                    // DIV    AX    AL * r/m32
                    // Unsigned Divide
                    do {
                        divisor32 = (int32_t)rmReadValue;
                        // Divide by 0
                        if (divisor32 == 0) {
                            //break;
                            return INT_DIV;
                        }



                        // Combine al and dl back into one 16 bit unsigned int
                        dividend32 = (*(uint32_t *)[self getRegPointer:reg_eax opSize:32]) | ((*(uint32_t *)[self getRegPointer:reg_edx opSize:32]) << 32);

                        *(uint32_t *)[self getRegPointer:reg_edx opSize:32] = dividend32 % (uint32_t)rmReadValue;
                        *(uint32_t *)[self getRegPointer:reg_eax opSize:32] = dividend32 / (uint32_t)rmReadValue;
                    } while (0);
                    break;
                case 0x7:
                    // IDIV    AX    AL * r/m32
                    // Signed Divide
                    do {
                        divisor32 = (int32_t)rmReadValue;
                        // Divide by 0
                        if (divisor32 == 0) {
                            //break;
                            return INT_DIV;
                        }

                        FFLog(@"\n\n\n  Check this op! \n\n\n");
                        __debugbreak();

                        // Combine al and dl back into one 16 bit unsigned int
                        dividend16 = (*(uint32_t *)[self getRegPointer:reg_eax opSize:32]) | ((*(uint32_t *)[self getRegPointer:reg_edx opSize:32]) << 8);

                        *(uint32_t *)[self getRegPointer:reg_edx opSize:32] = dividend16 % (uint32_t)rmReadValue;
                        *(uint32_t *)[self getRegPointer:reg_eax opSize:32] = dividend16 / (uint32_t)rmReadValue;
                    } while (0);
                    break;
                default:
                    die("Impossible opcode encountered");
                    break;
            }
            break;
        case 0xfc:
            // CLD
            // Clear direction flag
            self->state.df = 0;
            break;
        case 0xfd:
            // SLD
            // Set direction flag
            self->state.df = 1;
            break;
        case 0xfe:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch (mrm.reg) {
                case 0x0:
                    // INC    r/m8
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, (uint8_t)1, (uint8_t *)&self->state.res);
                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, (int8_t)1, (int8_t *)&self->state.res);

                    *(uint8_t *)rmWritePtr = (int8_t)self->state.res;

                    self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    // DEC    r/m8
                    self->state.cf = __builtin_sub_overflow((uint8_t)rmReadValue, (uint8_t)1, (uint8_t *)&self->state.res);
                    self->state.of = __builtin_sub_overflow((int8_t)rmReadValue, (int8_t)1, (int8_t *)&self->state.res);

                    *(uint8_t *)rmWritePtr = (int8_t)self->state.res;

                    self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                default:
                    die("Impossible opcode encountered");
                    break;
            }
            break;
        case 0xff:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:32];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:32];
                rmReadPtr = [self getRegPointer:mrm.base opSize:32]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:32];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }

            switch (mrm.reg) {
                case 0x0:
                    // INC    r/m32
                    self->state.of = __builtin_add_overflow((int32_t)rmReadValue, (int32_t)1, &self->state.res);
                    self->state.cf = __builtin_add_overflow((uint32_t)rmReadValue, (uint32_t)1, &self->state.res);

                    *(uint32_t *)rmWritePtr = (int32_t)self->state.res;

                    self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    // DEC    r/m32
                    self->state.of = __builtin_sub_overflow((int32_t)rmReadValue, (int32_t)1, &self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint32_t)rmReadValue, (uint32_t)1, &self->state.res);

                    *(uint32_t *)rmWritePtr = (int32_t)self->state.res;

                    self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    // CALL    r/m16/32
                    [self.task userWrite:(self->state.esp-4) buf:&self->state.eip count:4];
                    self->state.esp -= 4;

                    self->state.eip = (uint32_t)rmReadValue;
                    break;
                case 0x3:
                    // CALLF    r/m16/32
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x4:
                    // JMP    r/m16/32
                    self->state.eip = (uint32_t)rmReadValue;
                    break;
                case 0x5:
                    // JMPF    r/m16/32
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x6:
                    // PUSH    r/m16/32
                    [self.task userWrite:(self->state.esp-4) buf:&rmReadValue count:4];
                    self->state.esp -= 4;
                    break;
                default:
                    die("Impossible opcode encountered");
                    break;
            }
            break;
        default:
            fprintf(stderr, "Unimplemented OP %x", firstOpByte);
            die("Unimplemented OP");
            break;
    }

    return -1;
}

// END STEP 32












































// -------------------------------------------------------------------- START STEP 16

- (int32_t)step16:(uint32_t) addrDefault {
    dword_t saved_ip = self->state.eip;
    modrm mrm;
    uint8_t modRMByte;
    
    uint8_t firstOpByte;
    uint8_t secondOpByte;
    
    uint32_t addr = addrDefault;
    
    uint8_t *moffs8;
    uint16_t *moffs16;
    uint32_t *moffs32;
    
    enum reg32 tmpReg;
    
    dword_t *regPtr;
    dword_t *rmPtr;
    
    double tempdouble;
    float80 tempfloat80;
    float tempfloat;
    uint8_t imm8 = 0;
    uint16_t imm16 = 0;
    uint32_t imm32 = 0;
    uint64_t imm64 = 0;
    uint8_t temp8 = 0;
    uint8_t *temp8ptr = 0;
    uint16_t temp16 = 0;
    uint32_t temp32 = 0;
    uint16_t *temp16ptr = 0;
    uint64_t temp64 = 0;
    uint64_t *temp64ptr = 0;
    uint8_t divisor8;
    uint8_t dividend8;
    uint16_t divisor32;
    uint16_t dividend32;
    uint16_t divisor16;
    uint16_t dividend16;
    uint16_t *rmReadPtr;
    uint16_t rmReadValue;
    uint16_t *rmWritePtr;
    enum reg32 opReg;
    
// restart16:
    [self readByteIncIP:&firstOpByte];
    // printf("\n\n16 bit mode -\n");
    // [self printState:firstOpByte];
    
    switch (firstOpByte) {
            // TODO: Implement a group
            // http://ref.x86asm.net/coder32.html#x30
            // https://www.sandpile.org/x86/opc_1.htm
            
            // All thats left is
            // ADD
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x03:
        case 0x04:
        case 0x05:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    
                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, *(int8_t *)regPtr, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr, (uint8_t *)&self->state.res);
                    *(int8_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.cf = __builtin_add_overflow((uint16_t)rmReadValue, *(uint16_t *)regPtr, (uint16_t *)&self->state.res);
                    self->state.of = __builtin_add_overflow((int16_t)rmReadValue, *(int16_t *)regPtr, (int16_t *)&self->state.res);
                    
                    *(int16_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:8];
                    
                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, *(int8_t *)regPtr, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr, (uint8_t *)&self->state.res);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.of = __builtin_add_overflow((int16_t)rmReadValue, *(int16_t *)regPtr, (int16_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint16_t)rmReadValue, *(uint16_t *)regPtr, (uint16_t *)&self->state.res);
                    *(int16_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];
                    
                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, (int8_t)imm8, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, (uint8_t)imm8, (uint8_t *)&self->state.res);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readTwoBytesIncIP:&imm16];
                    regPtr =  [self getRegPointer:reg_eax opSize:16];
                    
                    self->state.of = __builtin_add_overflow((int16_t)rmReadValue, (int16_t)imm16, (int16_t *)&self->state.res);
                    self->state.cf = __builtin_add_overflow((uint16_t)rmReadValue, (uint16_t)imm16, (uint16_t *)&self->state.res);
                    *(int16_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;
            // OR
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0c:
        case 0x0d:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:8];
                    
                    self->state.res = *(uint8_t *)rmWritePtr = *(uint8_t *)regPtr | (uint8_t)rmReadValue;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.res = *(uint16_t *)rmWritePtr = *(uint16_t *)regPtr | (uint16_t)rmReadValue;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:8];
                    
                    self->state.res = *(uint8_t *)regPtr = *(uint8_t *)regPtr | (uint8_t)rmReadValue;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.res = *(uint16_t *)regPtr = *(uint16_t *)regPtr | (uint16_t)rmReadValue;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];
                    self->state.res = *(int8_t *)regPtr = *(int8_t *)regPtr | (uint8_t)imm8;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readTwoBytesIncIP:&imm16];
                    regPtr =  [self getRegPointer:reg_eax opSize:16];
                    self->state.res = *(int16_t *)regPtr = *(int16_t *)regPtr | (uint16_t)imm16;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;
            
        case 0x0f:
            // multibyterestart16:
            [self readByteIncIP:&secondOpByte];
            switch(secondOpByte) {
                case 0x18 ... 0x1f:
                    // http://ref.x86asm.net/coder32.html#x0F18
                    // HINT_NOP    r/m16/32
                    // Read the ModRM byte but do nothing
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    break;
                case 0x28:
                    // MOVAPS    xmm    xmm/m128
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x29:
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x31:
                    /*
                     imm64 = ({ uint16_t low, high; __asm__ volatile("rdtsc" : "=a" (high), "=d" (low)); ((uint64_t) high) << 16 | low; });
                     self->state.eax = imm64 & 0xffffffff;
                     self->state.edx = imm64 >> 16;
                     */
                    __asm__ volatile("rdtsc" : "=a" (self->state.edx), "=d" (self->state.eax));
                    break;
                case 0x40:
                    // CMOVO    r16/32    r/m16/32                o.......                    Conditional Move - overflow (OF=1)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (self->state.of) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x41:
                    // CMOVNO    r16/32    r/m16/32                o.......                    Conditional Move - not overflow (OF=0)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (!self->state.of) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x42:
                    // CMOVB      r16/32    r/m16/32                .......c                    Conditional Move - below/not above or equal/carry (CF=1)
                    // CMOVNAE    r16/32    r/m16/32
                    // CMOVC      r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (self->state.cf) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x43:
                    // CMOVNB    r16/32    r/m16/32                .......c                    Conditional Move - not below/above or equal/not carry (CF=0)
                    // CMOVAE    r16/32    r/m16/32
                    // CMOVNC    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (!self->state.cf) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x44:
                    // CMOVZ    r16/32    r/m16/32                ....z...                    Conditional Move - zero/equal (ZF=1)
                    // CMOVE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (self->state.zf_res ? (self->state.res == 0) : self->state.zf) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x45:
                    // CMOVNZ    r16/32    r/m16/32                ....z...                    Conditional Move - not zero/not equal (ZF=0)
                    // CMOVNE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (!(self->state.zf_res ? (self->state.res == 0) : self->state.zf)) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x46:
                    // CMOVBE    r16/32    r/m16/32                ....z..c                    Conditional Move - below or equal/not above (CF=1 OR ZF=1)
                    // CMOVNA    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (self->state.cf | (self->state.zf_res ? (self->state.res == 0) : self->state.zf)) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x47:
                    // CMOVNBE    r16/32    r/m16/32                ....z..c                    Conditional Move - not below or equal/above (CF=0 AND ZF=0)
                    // CMOVA    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (!(self->state.cf | (self->state.zf_res ? (self->state.res == 0) : self->state.zf))) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x48:
                    // CMOVS    r16/32    r/m16/32                ...s....                    Conditional Move - sign (SF=1)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if ((self->state.sf_res ? (self->state.res < 0) : self->state.sf)) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x49:
                    // CMOVNS    r16/32    r/m16/32                ...s....                    Conditional Move - not sign (SF=0)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (!(self->state.sf_res ? (self->state.res < 0) : self->state.sf)) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x4a:
                    // CMOVP    r16/32    r/m16/32                ......p.                    Conditional Move - parity/parity even (PF=1)
                    // CMOVPE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if ((self->state.pf_res ? (!__builtin_parity(self->state.res & 0xff)) : self->state.pf)) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x4b:
                    // CMOVNP    r16/32    r/m16/32                ......p.                    Conditional Move - not parity/parity odd (PF=0)
                    // CMOVPO    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (!(self->state.pf_res ? (!__builtin_parity(self->state.res & 0xff)) : self->state.pf)) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x4c:
                    // CMOVL    r16/32    r/m16/32                o..s....                    Conditional Move - less/not greater (SF!=OF)
                    // CMOVNGE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (((self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) ^ (self->state.of))) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x4d:
                    // CMOVNL    r16/32    r/m16/32                o..s....                    Conditional Move - not less/greater or equal (SF=OF)
                    // CMOVGE    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (!((self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) ^ (self->state.of))) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x4e:
                    // CMOVLE    r16/32    r/m16/32                o..sz...                    Conditional Move - less or equal/not greater ((ZF=1) OR (SF!=OF))
                    // CMOVNG    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if ((((self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) ^ (self->state.of)) | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x4f:
                    // CMOVNLE    r16/32    r/m16/32                o..sz...                    Conditional Move - not less nor equal/greater ((ZF=0) AND (SF=OF))
                    // CMOVG    r16/32    r/m16/32
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (!(((self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) ^ (self->state.of)) | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                        *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    }
                    break;
                case 0x57:
                    // XORPS    xmm    xmm/m128            sse1                        Bitwise Logical XOR for Single-FP Values
                    // A NOP
                    break;
                case 0x65:
                    die("Figure out how to implement without goto");
                    addr += self->state.tls_ptr;
                    // goto multibyterestart16;
                    break;
                case 0x6e:
                    // MOVD    mm    r/m32            mmx                        Move Doubleword
                    // A NOP
                    break;
                case 0x6f:
                    // MOVDQA    xmm    xmm/m128            sse2                        Move Aligned Double Quadword
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x73:
                    // PSRLQ    mm    imm8            mmx                        Shift Packed Data Right Logical
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    switch(mrm.opcode) {
                        case 0x02:
                            
                        default:
                            self->state.eip = saved_ip;
                            return INT_UNDEFINED;
                            break;
                    }
                    break;
                case 0x77:
                    // EMMS                    mmx                        Empty MMX Technology State
                    // A NOP
                    break;
                case 0x7e:
                    // MOVD    r/m32    mm            mmx                        Move Doubleword
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x7f:
                    // MOVQ    mm/m64    mm            mmx                        Move Quadword
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x80:
                    // JO    rel16/32                    o.......                    Jump near if overflow (OF=1)
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (self->state.of) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x81:
                    // JNO    rel16/32                    o.......                    Jump near if not overflow (OF=0)
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (!self->state.of) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x82:
                    // JB    rel16/32                    .......c                    Jump near if below/not above or equal/carry (CF=1)
                    // JNAE    rel16/32
                    // JC    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (self->state.cf) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x83:
                    // JNB    rel16/32                    .......c                    Jump near if not below/above or equal/not carry (CF=0)
                    // JAE    rel16/32
                    // JNC    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (!self->state.cf) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x84:
                    // JZ    rel16/32                    ....z...                    Jump near if zero/equal (ZF=1)
                    // JE    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if ((self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x85:
                    // JNZ    rel16/32                    ....z...                    Jump near if not zero/not equal (ZF=0)
                    // JNE    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (!(self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x86:
                    // JBE    rel16/32                    ....z..c                    Jump near if below or equal/not above (CF=1 OR ZF=1)
                    // JNA    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x87:
                    // JNBE    rel16/32                    ....z..c                    Jump near if not below or equal/above (CF=0 AND ZF=0)
                    // JA    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (!(self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x88:
                    // JS    rel16/32                    ...s....                    Jump near if sign (SF=1)
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x89:
                    // JNS    rel16/32                    ...s....                    Jump near if not sign (SF=0)
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (!(self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf)) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x8a:
                    // JP    rel16/32                    ......p.                    Jump near if parity/parity even (PF=1)
                    // JPE    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if ((self->state.pf_res ? !__builtin_parity(self->state.res & 0xff): self->state.pf)) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x8b:
                    // JNP    rel16/32                    ......p.                    Jump near if not parity/parity odd (PF=0)
                    // JPO    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (!(self->state.pf_res ? !__builtin_parity(self->state.res & 0xff): self->state.pf)) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x8c:
                    // JL    rel16/32                    o..s....                    Jump near if less/not greater (SF!=OF)
                    // JNGE    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if ((self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) ^ self->state.of) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x8d:
                    // JNL    rel16/32                    o..s....                    Jump near if not less/greater or equal (SF=OF)
                    // JGE    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (!(self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) ^ self->state.of) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x8e:
                    // JLE    rel16/32                    o..sz...                    Jump near if less or equal/not greater ((ZF=1) OR (SF!=OF))
                    // JNG    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if ((self->state.zf_res ? self->state.res == 0 : self->state.zf) | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x8f:
                    // JNLE    rel16/32                    o..sz...                    Jump near if not less nor equal/greater ((ZF=0) AND (SF=OF))
                    // 2JG    rel16/32
                    [self readTwoBytesIncIP:&imm16];
                    
                    if (!((self->state.zf_res ? self->state.res == 0 : self->state.zf) | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                        self->state.eip += imm16;
                    }
                    break;
                case 0x90:
                    // SETO    r/m8                    o.......                    Set Byte on Condition - overflow (OF=1)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.of) ? 1 : 0;
                    break;
                case 0x91:
                    // SETNO    r/m8                    o.......                    Set Byte on Condition - not overflow (OF=0)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.of) ? 0 : 1;
                    break;
                case 0x92:
                    // SETB    r/m8                    .......c                    Set Byte on Condition - below/not above or equal/carry (CF=1)
                    // SETNAE    r/m8
                    // SETC
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.cf) ? 1 : 0;
                    break;
                case 0x93:
                    // SETNB    r/m8                    .......c                    Set Byte on Condition - not below/above or equal/not carry (CF=0)
                    // SETAE    r/m8
                    // SETNC
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.cf) ? 0 : 1;
                    break;
                case 0x94:
                    // SETZ    r/m8                    ....z...                    Set Byte on Condition - zero/equal (ZF=1)
                    // SETE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.zf_res ? self->state.res == 0 : self->state.zf) ? 1 : 0;
                    break;
                case 0x95:
                    // SETNZ    r/m8                    ....z...                    Set Byte on Condition - not zero/not equal (ZF=0)
                    // SETNE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.zf_res ? self->state.res == 0 : self->state.zf) ? 0 : 1;
                    break;
                case 0x96:
                    // SETBE    r/m8                    ....z..c                    Set Byte on Condition - below or equal/not above (CF=1 OR ZF=1)
                    // SETNA
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) ? 1 : 0;
                    break;
                case 0x97:
                    // SETNBE    r/m8                    ....z..c                    Set Byte on Condition - not below or equal/above (CF=0 AND ZF=0)
                    // SETA
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) ? 0 : 1;
                    break;
                case 0x98:
                    // SETS    r/m8                    ...s....                    Set Byte on Condition - sign (SF=1)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.sf_res ? self->state.res < 0 : self->state.sf) ? 1 : 0;
                    break;
                case 0x99:
                    // SETNS    r/m8                    ...s....                    Set Byte on Condition - not sign (SF=0)
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.sf_res ? self->state.res < 0 : self->state.sf) ? 0 : 1;
                    break;
                case 0x9a:
                    // SETP    r/m8                    ......p.                    Set Byte on Condition - parity/parity even (PF=1)
                    // SETPE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.pf_res ? !__builtin_parity(self->state.res & 0xFF) : self->state.pf) ? 1 : 0;
                    break;
                case 0x9b:
                    // SETNP    r/m8                    ......p.                    Set Byte on Condition - not parity/parity odd (PF=0)
                    // SETPO
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = (self->state.pf_res ? !__builtin_parity(self->state.res & 0xFF) : self->state.pf) ? 0 : 1;
                    break;
                case 0x9c:
                    // SETL    r/m8                    o..s....                    Set Byte on Condition - less/not greater (SF!=OF)
                    // SETNGE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = ((self->state.sf_res ? self->state.res < 0 : self->state.sf) ^ self->state.of) ? 1 : 0;
                    break;
                case 0x9d:
                    // SETNL    r/m8                    o..s....                    Set Byte on Condition - not less/greater or equal (SF=OF)
                    // SETGE
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = ((self->state.sf_res ? self->state.res < 0 : self->state.sf) ^ self->state.of) ? 0 : 1;
                    break;
                case 0x9e:
                    // SETLE    r/m8                    o..sz...                    Set Byte on Condition - less or equal/not greater ((ZF=1) OR (SF!=OF))
                    // SETNG
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = ((self->state.zf_res ? self->state.res == 0 : self->state.zf) | ((self->state.sf_res ? self->state.res < 0 : self->state.sf) ^ self->state.of)) ? 1 : 0;
                    break;
                case 0x9f:
                    // SETNLE    r/m8                    o..sz...                    Set Byte on Condition - not less nor equal/greater ((ZF=0) AND (SF=OF))
                    // SETG
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    *(uint8_t *)rmWritePtr = ((self->state.zf_res ? self->state.res == 0 : self->state.zf) | ((self->state.sf_res ? self->state.res < 0 : self->state.sf) ^ self->state.of)) ? 0 : 1;
                    break;
                case 0xa2:
                    // CPUID    IA32_BIOS_…    EAX    ECX    ...                            CPU Identification
                    do_cpuid(&self->state.eax, &self->state.ebx, &self->state.ecx, &self->state.edx);
                    break;
                case 0xa3:
                    // BT    r/m16/32    r16/32                    o..szapc    .......c    o..szap.        Bit Test
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:16] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.cf = (rmReadValue & (1 << *(uint16_t *)regPtr % 16)) ? 1 : 0;
                    break;
                case 0xa4:
                    // SHLD    r/m16/32    r16/32    imm8                o..szapc    o..sz.pc    o....a.c        Double Precision Shift Left
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    [self readByteIncIP:&imm8];
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    // temp8 = (uint8_t)imm8 % 16;
                    if ((uint8_t)imm8 % 16 != 0) {
                        self->state.res = rmReadValue << ((uint8_t)imm8 % 16) | *(uint16_t *)regPtr >> (16 - ((uint8_t)imm8 % 16));
                        *(uint16_t *)rmWritePtr = self->state.res;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    }
                    break;
                case 0xa5:
                    // SHLD    r/m16/32    r16/32    CL                o..szapc    o..sz.pc    o....a.c        Double Precision Shift Left
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    if ((uint8_t)self->state.cl % 16 != 0) {
                        self->state.res = rmReadValue << ((uint8_t)self->state.cl % 16) | *(uint16_t *)regPtr >> (16 - ((uint8_t)self->state.cl % 16));
                        *(uint16_t *)rmWritePtr = self->state.res;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    }
                    break;
                case 0xab:
                    // BTS    r/m16/32    r16/32                    o..szapc    .......c    o..szap.        Bit Test And Set
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:16] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.cf = *regPtr & (1 << rmReadValue % 16);
                    *(uint16_t *)rmWritePtr = rmReadValue | (1 << *(uint16_t *)regPtr % 16);
                    break;
                case 0xac:
                    // SHRD    r/m16/32    r16/32    imm8                o..szapc    o..sz.pc    o....a.c        Double Precision Shift Right
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    [self readByteIncIP:&imm8];
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    // temp8 = (uint8_t)imm8 % 16;
                    if ((uint8_t)imm8 % 16 != 0) {
                        self->state.res = rmReadValue >> ((uint8_t)imm8 % 16) | *(uint16_t *)regPtr << (16 - ((uint8_t)imm8 % 16));
                        *(uint16_t *)rmWritePtr = self->state.res;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    }
                    break;
                case 0xad:
                    // SHRD    r/m16/32    r16/32    CL                o..szapc    o..sz.pc    o....a.c        Double Precision Shift Right
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    if ((uint8_t)self->state.cl % 16 != 0) {
                        self->state.res = rmReadValue >> ((uint8_t)self->state.cl % 16) | *(uint16_t *)regPtr << (16 - ((uint8_t)self->state.cl % 16));
                        *(uint16_t *)rmWritePtr = self->state.res;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    }
                    break;
                case 0xaf:
                    // IMUL    r16/32    r/m16/32                    o..szapc    o......c    ...szap.        Signed Multiply
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.cf = self->state.of = __builtin_mul_overflow(*(int16_t *)regPtr, (int16_t)rmReadValue, (int16_t *)&self->state.res);
                    *(uint16_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0xb0:
                    // CMPXCHG    r/m8    AL    r8                o..szapc    o..szapc            Compare and Exchange
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    self->state.cf = __builtin_sub_overflow((uint8_t)rmReadValue, (uint8_t)self->state.al, (uint8_t *) &self->state.res);
                    self->state.of = __builtin_sub_overflow((uint8_t)rmReadValue,  (int8_t)self->state.al,  (int8_t *) &self->state.res);
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    
                    if (self->state.res == 0) {
                        regPtr = [self getRegPointer:mrm.reg opSize:8];
                        *(uint8_t *)rmWritePtr = *(uint8_t *)regPtr;
                    } else {
                        *(uint8_t *)&self->state.al = (uint8_t)rmReadValue;
                    }
                    break;
                case 0xb1:
                    // CMPXCHG    r/m16/32    eAX    r16/32                o..szapc    o..szapc            Compare and Exchange
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    self->state.cf = __builtin_sub_overflow((uint16_t)rmReadValue, (uint16_t)self->state.eax, (uint16_t *) &self->state.res);
                    self->state.of = __builtin_sub_overflow((uint16_t)rmReadValue,  (int16_t)self->state.eax,  (int16_t *) &self->state.res);
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    
                    if (self->state.res == 0) {
                        regPtr = [self getRegPointer:mrm.reg opSize:16];
                        *(uint16_t *)rmWritePtr = *(uint16_t *)regPtr;
                    } else {
                        *(uint16_t *)&self->state.eax = (uint16_t)rmReadValue;
                    }
                    break;
                case 0xb3:
                    // BTR    r/m16/32    r16/32                    o..szapc    .......c    o..szap.        Bit Test and Reset
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:16] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.cf = *regPtr & ~(1 << rmReadValue % 16);
                    *(uint16_t *)rmWritePtr = rmReadValue | (1 << *(uint16_t *)regPtr % 16);
                    break;
                case 0xb6:
                    // MOVZX    r16/32    r/m8                                    Move with Zero-Extend
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    *(uint16_t *)regPtr = (uint8_t)rmReadValue;
                    break;
                case 0xb7:
                    // http://ref.x86asm.net/coder32.html#x0FB7
                    // MOVZX    r16/32    r/m16                                    Move with Zero-Extend
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    *(uint16_t *)regPtr = (uint16_t)rmReadValue; // might want to ditch this cast this is supposed to be a move of 16bit into a 32 bit reg with 0 extend
                    break;
                case 0xba:
                    // BT     r/m16/32    imm8                      o..szapc    .......c    o..szap.        Bit Test
                    // BTS    r/m16/32    imm8                      o..szapc    .......c    o..szap.        Bit Test and Set
                    // BTR    r/m16/32    imm8                      o..szapc    .......c    o..szap.        Bit Test and Reset
                    // BTC    r/m16/32    imm8                      o..szapc    .......c    o..szap.        Bit Test and Complement
                    [self readByteIncIP:&modRMByte];
                    [self readByteIncIP:&imm8];
                    
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + (imm8 / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    switch(mrm.opcode) {
                        case 4:
                            self->state.cf = rmReadValue & (1 << imm8 % 16);
                            break;
                        case 5:
                            self->state.cf = rmReadValue & (1 << imm8 % 16);
                            *(uint16_t *)rmWritePtr = rmReadValue | (1 << imm8 % 16);
                            break;
                        case 6:
                            self->state.cf = rmReadValue & (1 << imm8 % 16);
                            *(uint16_t *)rmWritePtr = rmReadValue | ~(1 << imm8 % 16);
                            break;
                        case 7:
                            self->state.cf = rmReadValue & (1 << imm8 % 16);
                            *(uint16_t *)rmWritePtr = rmReadValue ^ (1 << imm8 % 16);
                            break;
                        default:
                            self->state.eip = saved_ip;
                            return INT_UNDEFINED;
                            break;
                    }
                    
                    self->state.cf = *regPtr & (1 << imm8 % 16);
                    break;
                case 0xbb:
                    // BTC    r/m16/32    r16/32                    o..szapc    .......c    o..szap.        Bit Test and Complement
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:16] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    self->state.cf = rmReadValue & (1 << *(uint16_t *)regPtr % 16);
                    *(uint16_t *)rmWritePtr = rmReadValue ^ (1 << *(uint16_t *)regPtr % 16);
                    break;
                case 0xbc:
                    // BSF    r16/32    r/m16/32                    o..szapc    ....z...    o..s.apc        Bit Scan Forward
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:16] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.zf = rmReadValue == 0;
                    self->state.zf_res = 0;
                    
                    if (!self->state.zf) {
                        *(uint16_t *)regPtr = __builtin_ctz(rmReadValue);
                    }
                    break;
                case 0xbd:
                    // BSR    r16/32    r/m16/32                    o..szapc    ....z...    o..s.apc        Bit Scan Reverse
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        // The register contains a byte offset added to the address
                        if (!(rmReadPtr = [self.task.mem getPointer:(addr + ([self getRegisterValue:mrm.reg opSize:16] / 8)) type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.zf = rmReadValue == 0;
                    self->state.zf_res = 0;
                    
                    if (!self->state.zf) {
                        *(uint16_t *)regPtr = 16 - __builtin_ctz(rmReadValue);
                    }
                    break;
                case 0xbe:
                    // MOVSX    r16/32    r/m8                                    Move with Sign-Extension
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    break;
                case 0xbf:
                    // MOVSX    r16/32    r/m16                                    Move with Sign-Extension
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    break;
                case 0xc0:
                    // XADD    r/m8    r8                    o..szapc    o..szapc            Exchange and Add
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    
                    temp8 = *(uint8_t *)regPtr;
                    *(uint8_t *)regPtr = (uint8_t)rmReadValue;
                    *(uint8_t *)rmWritePtr = (uint8_t)temp8;
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr, (uint8_t *)&self->state.res);
                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, *(int8_t *)regPtr, (int8_t *)&self->state.res);
                    *(uint8_t *)rmWritePtr = (uint8_t)self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0xc1:
                    // XADD    r/m16/32    r16/32                    o..szapc    o..szapc            Exchange and Add
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    temp8 = *(uint16_t *)regPtr;
                    *(uint16_t *)regPtr = (uint16_t)rmReadValue;
                    *(uint16_t *)rmWritePtr = (uint16_t)temp8;
                    self->state.cf = __builtin_add_overflow((uint16_t)rmReadValue, *(uint16_t *)regPtr, (uint16_t *)&self->state.res);
                    self->state.of = __builtin_add_overflow((int16_t)rmReadValue, *(int16_t *)regPtr, (int16_t *)&self->state.res);
                    *(uint16_t *)rmWritePtr = (uint16_t)self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0xc8:
                    // Byte Swap operations:
                    *(uint16_t *)&self->state.eax = __builtin_bswap32(((uint16_t)self->state.eax));
                    break;
                case 0xc9:
                    *(uint16_t *)&self->state.ecx = __builtin_bswap32(((uint16_t)self->state.ecx));
                    break;
                case 0xca:
                    *(uint16_t *)&self->state.edx = __builtin_bswap32(((uint16_t)self->state.edx));
                    break;
                case 0xcb:
                    *(uint16_t *)&self->state.ebx = __builtin_bswap32(((uint16_t)self->state.ebx));
                    break;
                case 0xcc:
                    *(uint16_t *)&self->state.esp = __builtin_bswap32(((uint16_t)self->state.esp));
                    break;
                case 0xcd:
                    *(uint16_t *)&self->state.ebp = __builtin_bswap32(((uint16_t)self->state.ebp));
                    break;
                case 0xce:
                    *(uint16_t *)&self->state.esi = __builtin_bswap32(((uint16_t)self->state.esi));
                    break;
                case 0xcf:
                    *(uint16_t *)&self->state.edi = __builtin_bswap32(((uint16_t)self->state.edi));
                    break;
                default:
                    die("Unimplemented 2 part opcode 0x0f");
                    break;
            }
            break;
            
            // ADC
        case 0x10:
        case 0x11:
        case 0x12:
        case 0x13:
        case 0x14:
        case 0x15:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    
                    __builtin_add_overflow((int8_t)rmReadValue, *(int8_t *)regPtr + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    __builtin_add_overflow((int16_t)rmReadValue, *(int16_t *)regPtr + self->state.cf, (int16_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint16_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow((uint8_t)rmReadValue, *(uint16_t *)regPtr + self->state.cf, (uint16_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint16_t)-1) / 2);
                    *(int16_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:8];
                    
                    __builtin_add_overflow(*(int8_t *)regPtr, (int8_t)rmReadValue + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow(*(uint8_t *)regPtr, (uint8_t)rmReadValue + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:16];
                    
                    __builtin_add_overflow(*(int16_t *)regPtr, (int16_t)rmReadValue + self->state.cf, (int16_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint16_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow(*(uint16_t *)regPtr, (uint16_t)rmReadValue + self->state.cf, (uint16_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint16_t *)regPtr == ((uint16_t)-1) / 2);
                    *(int16_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];
                    
                    __builtin_add_overflow(*(int8_t *)regPtr, (int8_t)imm8 + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow(*(uint8_t *)regPtr, (uint8_t)imm8 + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readTwoBytesIncIP:&imm16];
                    regPtr =  [self getRegPointer:reg_eax opSize:16];
                    
                    __builtin_add_overflow(*(int16_t *)regPtr, (int16_t)imm16 + self->state.cf, (int16_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int16_t *)regPtr == ((uint16_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_add_overflow(*(uint16_t *)regPtr, (uint16_t)imm16 + self->state.cf, (uint16_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint16_t *)regPtr == ((uint16_t)-1) / 2);
                    *(int16_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;
            
            // SBB is just SUB but the 2nd op has cf added to it
            // and
            // of = result || (cf &&  reg == ((uint8_t)-1) / 2)
        case 0x18:
        case 0x19:
        case 0x1a:
        case 0x1b:
        case 0x1c:
        case 0x1d:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    
                    __builtin_sub_overflow((int8_t)rmReadValue, *(int8_t *)regPtr + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    __builtin_sub_overflow((int16_t)rmReadValue, *(int16_t *)regPtr + self->state.cf, (int16_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint16_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow((uint8_t)rmReadValue, *(uint16_t *)regPtr + self->state.cf, (uint16_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint16_t)-1) / 2);
                    *(int16_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:8];
                    
                    __builtin_sub_overflow(*(int8_t *)regPtr, (int8_t)rmReadValue + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow(*(uint8_t *)regPtr, (uint8_t)rmReadValue + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:16];
                    
                    __builtin_sub_overflow(*(int16_t *)regPtr, (int16_t)rmReadValue + self->state.cf, (int16_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint16_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow(*(uint16_t *)regPtr, (uint16_t)rmReadValue + self->state.cf, (uint16_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint16_t *)regPtr == ((uint16_t)-1) / 2);
                    *(int16_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];
                    
                    __builtin_sub_overflow(*(int8_t *)regPtr, (int8_t)imm8 + self->state.cf, (int8_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int8_t *)regPtr == ((uint8_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow(*(uint8_t *)regPtr, (uint8_t)imm8 + self->state.cf, (uint8_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint8_t *)regPtr == ((uint8_t)-1) / 2);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readTwoBytesIncIP:&imm16];
                    regPtr =  [self getRegPointer:reg_eax opSize:16];
                    
                    __builtin_sub_overflow(*(int16_t *)regPtr, (int16_t)imm16 + self->state.cf, (int16_t *)&self->state.res);
                    self->state.of = self->state.res || (self->state.cf && *(int16_t *)regPtr == ((uint16_t)-1) / 2); // 0x7f  since uint8_t here is equal to the max value of the type I believe, 0xff
                    __builtin_sub_overflow(*(uint16_t *)regPtr, (uint16_t)imm16 + self->state.cf, (uint16_t *)&self->state.res);
                    self->state.cf = self->state.res || (self->state.cf && *(uint16_t *)regPtr == ((uint16_t)-1) / 2);
                    *(int16_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;
            
        case 0x20:
        case 0x21:
        case 0x22:
        case 0x23:
        case 0x24:
        case 0x25:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue & *(uint8_t *)regPtr;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.res = *(uint16_t *)rmWritePtr = (uint16_t)rmReadValue & *(uint16_t *)regPtr;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    self->state.res = *(uint8_t *)regPtr = (uint8_t)rmReadValue & *(uint8_t *)regPtr;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    self->state.res = *(uint16_t *)regPtr = (uint16_t)rmReadValue & *(uint16_t *)regPtr;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];
                    
                    temp8 = (uint8_t)imm8 & *(uint8_t *)regPtr;
                    memcpy((uint8_t *)&regPtr, (uint8_t *)&temp8, sizeof(uint8_t));
                    memcpy((uint8_t *)&self->state.res, (uint8_t *)&temp8, sizeof(uint8_t));
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readTwoBytesIncIP:&imm16];
                    regPtr =  [self getRegPointer:reg_eax opSize:16];
                    self->state.res = *(uint16_t *)regPtr = (uint16_t)imm16 & *(uint16_t *)regPtr;
                    
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;
            //            28        r                    L    SUB    r/m8    r8                    o..szapc    o..szapc            Subtract
            //            29        r                    L    SUB    r/m16/32    r16/32                    o..szapc    o..szapc            Subtract
            //            2A        r                        SUB    r8    r/m8                    o..szapc    o..szapc            Subtract
            //            2B        r                        SUB    r16/32    r/m16/32                    o..szapc    o..szapc            Subtract
            //            2C                                SUB    AL    imm8                    o..szapc    o..szapc            Subtract
            //            2D                                SUB    eAX    imm16/32
        case 0x28:
        case 0x29:
        case 0x2a:
        case 0x2b:
        case 0x2c:
        case 0x2d:
            switch (0x7 & firstOpByte) {
                case 0x0:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    
                    self->state.of = __builtin_sub_overflow((int8_t)rmReadValue, *(int8_t *)regPtr, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint8_t)rmReadValue, *(uint8_t *)regPtr, (uint8_t *)&self->state.res);
                    *(int8_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.of = __builtin_sub_overflow((int16_t)rmReadValue, *(int16_t *)regPtr, (int16_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint16_t)rmReadValue, *(uint16_t *)regPtr, (uint16_t *)&self->state.res);
                    *(int16_t *)rmWritePtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:8];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:8];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:8];
                    
                    self->state.of = __builtin_sub_overflow(*(int8_t *)regPtr, (int8_t)rmReadValue, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow(*(uint8_t *)regPtr, (uint8_t)rmReadValue, (uint8_t *)&self->state.res);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x3:
                    [self readByteIncIP:&modRMByte];
                    mrm = [self decodeModRMByte:modRMByte];
                    regPtr = [self getRegPointer:mrm.reg opSize:16];
                    if (mrm.type == modrm_register) {
                        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    } else {
                        addr = [self getModRMAddress:mrm opSize:16];
                        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                            return INT_GPF;
                        }
                        memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                    }
                    
                    regPtr =  [self getRegPointer:mrm.reg opSize:16];
                    
                    self->state.of = __builtin_sub_overflow(*(int16_t *)regPtr, (int16_t)rmReadValue, (int16_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow(*(uint16_t *)regPtr, (uint16_t)rmReadValue, (uint16_t *)&self->state.res);
                    *(int16_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x4:
                    [self readByteIncIP:&imm8];
                    regPtr =  [self getRegPointer:reg_eax opSize:8];
                    
                    self->state.of = __builtin_sub_overflow(*(int8_t *)regPtr, (int8_t)imm8, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow(*(uint8_t *)regPtr, (uint8_t)imm8, (uint8_t *)&self->state.res);
                    *(int8_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    [self readTwoBytesIncIP:&imm16];
                    regPtr =  [self getRegPointer:reg_eax opSize:16];
                    
                    self->state.of = __builtin_sub_overflow(*(int16_t *)regPtr, (int16_t)imm16, (int16_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow(*(uint16_t *)regPtr, (uint16_t)imm16, (uint16_t *)&self->state.res);
                    *(int16_t *)regPtr = self->state.res;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
            }
            break;
            
        case 0x2e:
            // TODO: Why? Research why some of these opcodes skip the interrup checking step and just restart up here
            // This should be a goto to the top of this step function
            die("Hit an opcode that was not expected");
            break;
            
        case 0x30:
            // XOR    r/m8    r8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            self->state.res = *((uint8_t *)rmWritePtr) = *((uint8_t *)rmReadPtr) ^ *((uint8_t *)regPtr);
            
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x31:
            // XOR    r/m16/32    r16/32
            // Saving value into r/m16/32
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t)); memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            self->state.res = *((dword_t *)rmWritePtr) = *((dword_t *)rmReadPtr) ^ *((dword_t *)regPtr);
            
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x32:
            // XOR    r8    r/m8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            }
            self->state.res = *((uint8_t *)regPtr) = *((uint8_t *)regPtr) ^ *((uint8_t *)rmReadPtr);
            
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x33:
            // XOR    r16/32    r/m16/32
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            }
            self->state.res = *((dword_t *)regPtr) = *((dword_t *)regPtr) ^ *((dword_t *)rmReadPtr);
            
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x34:
            // XOR    Al    imm8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:reg_eax opSize:8];
            
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            
            *((uint8_t *)regPtr) = *((uint8_t *)regPtr) ^ (uint8_t)imm8;
            self->state.res = *((int8_t *)regPtr);
            
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x35:
            // XOR    EAX    imm8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:reg_eax opSize:16];
            
            if ([self readTwoBytesIncIP:&imm16]) {
                SEGFAULT
            }
            
            *((uint16_t *)regPtr) = *((uint16_t *)regPtr) ^ (uint16_t)imm16;
            self->state.res = *((int16_t *)regPtr);
            
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x38:
            // CMP    r/m8    r8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            self->state.cf = __builtin_sub_overflow(*((uint8_t *)rmReadPtr), *((uint8_t *)regPtr), (uint8_t *)&temp8);
            self->state.of = __builtin_sub_overflow(*((int8_t *)rmReadPtr), *((int8_t *)regPtr), (int8_t *)&temp8);
            self->state.res = (int8_t)temp8;
            // sets cf and of
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x39:
            // CMP    r/m16/32    r16/32
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t)); memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            self->state.cf = __builtin_sub_overflow(*((uint16_t *)rmReadPtr), *((uint16_t *)regPtr), (uint16_t *)&temp16);
            self->state.of = __builtin_sub_overflow(*((int16_t *)rmReadPtr), *((int16_t *)regPtr), (int16_t *)&temp16);
            self->state.res = (int16_t)temp16;
            // sets cf and of
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x3a:
            // CMP    r8    r/m8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            self->state.cf = __builtin_sub_overflow(*((uint8_t *)regPtr), *((uint8_t *)rmReadPtr), (uint8_t *)&temp8);
            self->state.of = __builtin_sub_overflow(*((int8_t *)regPtr), *((int8_t *)rmReadPtr), (int8_t *)&temp8);
            self->state.res = (int8_t)temp8;
            // sets cf and of
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x3b:
            // CMP    r16/32    r/m16/32
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t)); memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            self->state.cf = __builtin_sub_overflow(*((uint16_t *)regPtr), *((uint16_t *)rmReadPtr), (uint16_t *)&temp16);
            self->state.of = __builtin_sub_overflow(*((int16_t *)regPtr), *((int16_t *)rmReadPtr), (int16_t *)&temp16);
            self->state.res = (int16_t)temp16;
            // sets cf and of
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x3c:
            // CMP    Al    imm8
            //
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:reg_eax opSize:8];
            
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            
            self->state.cf = __builtin_sub_overflow(*((uint8_t *)regPtr), (uint8_t)imm8, (uint8_t *)&temp8);
            self->state.of = __builtin_sub_overflow(*((int8_t *)regPtr), (int8_t)imm8, (int8_t *)&temp8);
            self->state.res = (int8_t)temp8;
            // sets cf and of
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
        case 0x3d:
            // CMP    EAX    imm8
            //
            regPtr = [self getRegPointer:reg_eax opSize:16];
            
            if ([self readTwoBytesIncIP:&imm16]) {
                SEGFAULT
            }
            
            self->state.cf = __builtin_sub_overflow(*((uint16_t *)regPtr), (uint16_t)imm16, (uint16_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow(*((int16_t *)regPtr), (int16_t)imm16, (int16_t *)&self->state.res);
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
            
        case 0x3e:
            // TODO: Why? Research why some of these opcodes skip the interrup checking step and just restart up here
            // This should be a goto to the top of this step function
            die("Hit an opcode that was not expected");
            break;
            
        case 0x40:
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:
            // INC    r16/32
            opReg = 0x7 & firstOpByte;
            regPtr = [self getRegPointer:opReg opSize:16];
            //            *regPtr = *regPtr + 1;
            // No carry flag is set
            // self->state.cf = __builtin_add_overflow(*(uint16_t *)regPtr, (uint16_t)1, (uint16_t *)&self->state.res);
            self->state.of = __builtin_add_overflow(*(int16_t *)regPtr, (int16_t)1, (int16_t *)&self->state.res);
            *regPtr = self->state.res;
            // set the auxillary flag
            self->state.af_ops = 1;
            // set zero flag, sign flag, parity flag
            self->state.zf_res = 1;
            self->state.sf_res = 1;
            self->state.pf_res = 1;
            
            break;
        case 0x48:
        case 0x49:
        case 0x4a:
        case 0x4b:
        case 0x4c:
        case 0x4d:
        case 0x4e:
        case 0x4f:
            // DEC    r16/32
            opReg = 0x7 & firstOpByte;
            regPtr = [self getRegPointer:opReg opSize:16];
            //            *regPtr = *regPtr + 1;
            // No carry flag is set
            // self->state.cf = __builtin_add_overflow(*(uint16_t *)regPtr, (uint16_t)1, (uint16_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow(*(int16_t *)regPtr, (int16_t)1, (int16_t *)&self->state.res);
            *regPtr = self->state.res;
            // set the auxillary flag
            self->state.af_ops = 1;
            // set zero flag, sign flag, parity flag
            self->state.zf_res = 1;
            self->state.sf_res = 1;
            self->state.pf_res = 1;
            
            break;
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
            // PUSH    r16/32
            opReg = 0x7 & firstOpByte;
            regPtr = [self getRegPointer:opReg opSize:16];
            if ([self.task userWrite:self->state.esp - 2 buf:regPtr count:2]) {
                SEGFAULT
            }
            // # ifdef BDEBUG
            // CLog(@"PUSHed %x to [%x]\n", *regPtr, self->state.esp - 2);
            // # endif
            self->state.esp -= 2;
            
            break;
        case 0x58:
        case 0x59:
        case 0x5a:
        case 0x5b:
        case 0x5c:
        case 0x5d:
        case 0x5e:
        case 0x5f:
            // POP    r16/32
            opReg = 0x7 & firstOpByte;
            regPtr = [self getRegPointer:opReg opSize:16];
            if ([self.task userRead:self->state.esp buf:regPtr count:2]) {
                SEGFAULT
            }
            self->state.esp += 2;
            
            break;
            
        case 0x60:
            tmpReg = reg_eax;
            do {
                *(int16_t *)[self.task.mem getPointer:self->state.esp type:16] = [self getRegisterValue:tmpReg opSize:16];
                tmpReg += 1;
                self->state.esp -= 2;
            } while (tmpReg != reg_edi);
            break;
        case 0x61:
            tmpReg = reg_edi;
            do {
                [self readTwoBytesIncSP:&imm16];
                *(int16_t *)[self getRegPointer:tmpReg opSize:16] = imm16;
                tmpReg -= 1;
            } while (tmpReg != reg_eax);
            break;
            
        case 0x65:
            addr += self->state.tls_ptr;
            [self step16:addr];
            // goto restart16;
            break;
        case 0x66:
            die("Hit an opcode that should just call the 16 bit cpu step");
            // Like this:
            // return cpu_step16(cpu, tlb);
            // line 2752 is where its called from
            // another line is on 5649
            break;
        case 0x67:
            // TODO: Why? Research why some of these opcodes skip the interrup checking step and just restart up here
            // This should be a goto to the top of this step function
            die("Hit an opcode that was not expected");
            break;
        case 0x68:
            [self readTwoBytesIncIP:&imm16];
            [self.task userWrite:self->state.esp - 2 buf:&imm16 count:2];
            self->state.esp -= 2;
            break;
        case 0x69:
            // IMUL
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            [self readTwoBytesIncIP:&imm16];
            
            self->state.cf = self->state.of = __builtin_mul_overflow((int16_t)rmReadValue, (int16_t)imm16, (int16_t *)&self->state.res);
            *(int16_t *)regPtr = (int16_t)self->state.res;
            
            self->state.pf_res = 1;
            self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = 0;
            break;
            
        case 0x6a:
            [self readByteIncIP:&imm8];
            [self.task userWrite:(self->state.esp - 2) buf:&imm8 count:1];
            self->state.esp -= 2;
            break;
        case 0x6b:
            // IMUL
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            [self readByteIncIP:&imm8];
            
            self->state.cf = self->state.of = __builtin_mul_overflow((int16_t)rmReadValue, (int8_t)imm8, (int16_t *)&self->state.res);
            self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = 0;
            break;
            
        case 0x70:
            // JO rel8
            // Jump if overflow flag is set to a relative 8 bit address
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.of) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x71:
            // JNO    rel8
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (!self->state.of) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x72:
            // JB    rel8
            // JNAE    rel8
            // JC    rel8
            // Jump short if below/not above or equal/carry. if CF==1
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.cf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x73:
            // JNB    rel8
            // JAE    rel8
            // JNC    rel8
            // Jump short if not below/above or equal/not carry. if CF==0
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (!self->state.cf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint16_t)imm8;
            }
            break;
        case 0x74:
            // JZ    rel8
            // JE    rel8
            // Jump short if zero/equal (ZF==1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.zf_res ? self->state.res == 0 : self->state.zf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x75:
            // JNZ    rel8
            // JNE    rel8
            // Jump short if not zero/not equal (ZF==0)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint16_t)(int8_t)imm8;
            }
            break;
        case 0x76:
            // JBE    rel8
            // JNA    rel8
            // Jump short if below or equal/not above (CF=1 OR ZF=1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x77:
            // JNBE    rel8
            // JA    rel8
            // Jump short if not below or equal/above (CF=0 AND ZF=0)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(self->state.cf | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x78:
            // JS    rel8
            // Jump short if sign (SF=1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (self->state.sf_res ? self->state.res < 0 : self->state.sf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x79:
            // JNS    rel8
            // Jump short if not sign (SF=1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(self->state.sf_res ? self->state.res < 0 : self->state.sf)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7a:
            // JP    rel8
            // JPE    rel8
            // Jump short if parity/parity even (PF=1)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (self->state.pf_res ? !__builtin_parity(self->state.res & 0xff) : self->state.pf) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7b:
            // JNP    rel8
            // JPO    rel8
            // Jump short if not parity/parity odd (PF=0)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(self->state.pf_res ? !__builtin_parity(self->state.res & 0xff) : self->state.pf)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7c:
            // JL    rel8
            // JNGE    rel8
            // Jump short if less/not greater (SF!=OF)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Use XOR of the sign flag and overflow flag to check if they are not equal because
            // (in any order) 0 ^ 1 is 1       1 ^ 1 is 0         0 ^ 0 is 0
            // Meaning sign flag XOR overflow flag is only true when one is 1 and the other is 0
            if ((self->state.sf_res ? self->state.res == 0 : self->state.sf) ^ self->state.of) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7d:
            // JNL    rel8
            // JGE    rel8
            // Jump short if not less/greater or equal (SF=OF)
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (!((self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) ^ self->state.of)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7e:
            // JLE    rel8
            // JNG    rel8
            // Jump short if less or equal/not greater ((ZF=1) OR (SF!=OF))
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.zf_res ? self->state.res == 0 : self->state.zf | ((self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) ^ self->state.of)) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x7f:
            // JNLE    rel8
            // JG    rel8
            // Jump short if not less nor equal/greater ((ZF=0) AND (SF=OF))
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            // Is the "zf flag if res" flag is checked then check the res to determine the zf flag
            // Otherwise just check the last zf flag
            if (!(((self->state.sf_res ? (int16_t)self->state.res < 0 : self->state.sf) ^ (self->state.of)) | (self->state.zf_res ? self->state.res == 0 : self->state.zf))) {
                // TODO: Possibly cast this as int16_t to work with 16 bit instructions
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0x80:
            // 0x80 and 0x82 are the same code
            
            // The opcode 0x83 can be a few different operations
            // The reg bits in the modrm byte are what define which operation this really is
            // ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
#define MODRM_VAR       mrm
#define IMM_SZ          8
#define RM_SZ           8
#define IMM_READ_METHOD readByteIncIP
#include "Group1OpCodes.h"
#undef IMM_READ_METHOD
#undef MODRM_VAR
#undef IMM_SZ
#undef RM_SZ
            break;
        case 0x81:
            // The opcode 0x81 can be a few different operations. Its part of the Group 1 of opcodes
            // http://www.mlsite.net/8086/#tbl_ext
            // The reg bits in the modrm byte are what define which operation this really is
            // ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
#define MODRM_VAR       mrm
#define IMM_SZ          16
#define RM_SZ           16
#define IMM_READ_METHOD readTwoBytesIncIP
#include "Group1OpCodes.h"
#undef IMM_READ_METHOD
#undef MODRM_VAR
#undef IMM_SZ
#undef RM_SZ
            break;
        case 0x82:
#define MODRM_VAR       mrm
#define IMM_SZ          8
#define RM_SZ           8
#define IMM_READ_METHOD readByteIncIP
#include "Group1OpCodes.h"
#undef IMM_READ_METHOD
#undef MODRM_VAR
#undef IMM_SZ
#undef RM_SZ
            break;
        case 0x83:
#define MODRM_VAR       mrm
#define IMM_SZ          8
#define RM_SZ           16
#define IMM_READ_METHOD readByteIncIP
#include "Group1OpCodes.h"
#undef IMM_READ_METHOD
#undef MODRM_VAR
#undef IMM_SZ
#undef RM_SZ
            break;
        case 0x84:
            // TEST    r/m8    r8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            self->state.res = (uint8_t)rmReadValue & *(uint8_t *)regPtr;
            
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x85:
            // TEST    r/m32    r32
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            self->state.res = (uint16_t)rmReadValue & *(uint16_t *)regPtr;
            
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0x86:
            // XCHG    r8    r/m8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            temp8 = *(uint8_t *)regPtr;
            *(uint8_t *)regPtr = rmReadValue;
            *(uint8_t *)rmWritePtr = temp8;
            break;
        case 0x87:
            // XCHG    r32    r/m32
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            temp16 = *(uint16_t *)regPtr;
            *(uint16_t *)regPtr = rmReadValue;
            *(uint16_t *)rmWritePtr = temp16;
            break;
        case 0x88:
            // MOV    r/m8    r8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            *((dword_t *)rmWritePtr) = *((dword_t *)regPtr);
            break;
        case 0x89:
            // MOV    r/m16/32/64    r16/32/64
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            *((dword_t *)rmWritePtr) = *((dword_t *)regPtr);
            break;
        case 0x8a:
            // MOV    r8    r/m8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                // rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                /*
                 if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                 return INT_GPF;
                 }
                 memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                 */
                rmReadValue = [self.task userReadOneBytes:addr];
            }
            // memcpy(regPtr, rmReadPtr, sizeof(uint16_t));
            *(uint8_t *)regPtr = (uint8_t)rmReadValue;
            break;
        case 0x8b:
            // MOV    r16/32    r/m16/32
            // DBADDR(0xf7fc3421 + 1) // + 1 for opcode read
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                //CLog(@"P: %d 0x8b Mov %@, %@\n", self.task.pid.id, [CPU getRegisterString:mrm.base], [CPU getRegisterString:mrm.base]);
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                rmReadValue = [self.task userReadFourBytes:addr];
                /*
                 if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                 return INT_GPF;
                 }
                 memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                 */
                //CLog(@"P: %d 0x8b Mov %@, [%x] = %x\n", self.task.pid.id, [CPU getRegisterString:mrm.reg], modrmAddress, *((dword_t *)rmReadPtr));
            }
            *regPtr = rmReadValue;
            break;
        case 0x8c:
            // MOV    r16/32    Sreg
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            if (mrm.reg != reg_ebp) {
                self->state.eip = saved_ip;
                return INT_UNDEFINED;
            }
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            *((dword_t *)rmWritePtr) = self->state.gs;
            break;
            
            // This one is out of order because 8c and 8e are the inverse of each other
        case 0x8d:
            // LEA    r16/32    m
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                self->state.eip = saved_ip;
                return INT_UNDEFINED;
            }
            
            addr = [self getModRMAddress:mrm opSize:16];
            
            *((dword_t *)regPtr) = addr;
            break;
        case 0x8e:
            // MOV    Sreg    r16/32
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];
            if (mrm.reg != reg_ebp) {
                self->state.eip = saved_ip;
                return INT_UNDEFINED;
            }
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            }
            self->state.gs = *((dword_t *)rmReadPtr);
            break;
            
        case 0x8f:
            // POP r/m32
            // Pop esp into temp16
            // move temp16 in mrmwriteptr
            [self readByteIncIP:&modRMByte];
            // CLog(@"MODRM %x\n", modRMByte);
            mrm = [self decodeModRMByte:modRMByte];

            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            [self readFourBytesIncSP:&temp16];
            *(uint16_t *)rmWritePtr = temp16;
            break;
            
        case 0x90:
        case 0x91:
        case 0x92:
        case 0x93:
        case 0x94:
        case 0x95:
        case 0x96:
        case 0x97:
            opReg = 0x7 & firstOpByte;
            temp16 = [self getRegPointer:opReg opSize:16];
            *(uint16_t *)[self getRegPointer:opReg opSize:16] = ((uint16_t)self->state.eax);
            *(uint16_t *)&self->state.eax = temp16;
            break;
        case 0x98:
            *(uint16_t *)[self getRegPointer:reg_eax opSize:16] = (uint16_t)[self getRegisterValue:reg_eax opSize:16];
            break;
        case 0x99:
            // TODO: Remove this ternary should b -1 always right?
            // TODO: Why is this here?
            *(uint16_t *)[self getRegPointer:reg_edx opSize:16] = ([self getRegisterValue:reg_eax opSize:16] & (1 << (16 - 1)) ? (uint16_t)-1 : 0);
            break;
        case 0x9b:
            NO_ERR_UN_IMP
            break;
        case 0x9c:
            collapse_flags(&self->state);
            [self.task userWrite:(self->state.esp - 2) buf:&self->state.eflags count:2]; // sizeof(self->state.eflags)]
            self->state.esp -= 2;
            break;
        case 0x9d:
            [self.task userRead:self->state.esp buf:&self->state.eflags count:2];
            self->state.esp += 2;
            expand_flags(&self->state);
            break;
        case 0x9e:
            self->state.eflags &= 0xffffff00 | ~0b11010101;
            self->state.eflags |= self->state.ah & 0b11010101;
            expand_flags(&self->state);
            break;
            
        case 0xa0:
            [self readTwoBytesIncIP:&imm16];
            
            addr += imm16;
            
            moffs8 = [self.task.mem getPointer:addr type:MEM_READ];
            *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = *(uint8_t *)moffs8;
            break;
            
        case 0xa1:
            [self readTwoBytesIncIP:&imm16];
            
            addr += imm16;
            
            moffs16 = [self.task.mem getPointer:addr type:MEM_READ];
            *(uint16_t *)[self getRegPointer:reg_eax opSize:16] = *(uint16_t *)moffs16;
            break;
            
        case 0xa2:
            [self readTwoBytesIncIP:&imm16];
            
            addr += imm16;
            
            moffs8 = [self.task.mem getPointer:addr type:MEM_WRITE];
            *((uint8_t *)moffs8) = (uint8_t)[self getRegisterValue:reg_eax opSize:8];
            break;
            
        case 0xa3:
            [self readTwoBytesIncIP:&imm16];
            
            addr += imm16;
            
            moffs16 = [self.task.mem getPointer:addr type:MEM_WRITE];
            *moffs16 = [self getRegisterValue:reg_eax opSize:16];
            break;
            
        case 0xa4:
            *(uint8_t *)[self getRegisterPointedMemory:reg_edi registerSize:8 accessType:MEM_WRITE] = *(uint8_t *)[self getRegisterPointedMemory:reg_esi registerSize:8 accessType:MEM_READ];
            
            self->state.esi += self->state.df ? -1 : 1;
            self->state.edi += self->state.df ? -1 : 1;
            break;
            
        case 0xa5:
            *(uint16_t *)[self getRegisterPointedMemory:reg_edi registerSize:16 accessType:MEM_WRITE] = *(uint16_t *)[self getRegisterPointedMemory:reg_esi registerSize:16 accessType:MEM_READ];
            
            self->state.esi += self->state.df ? -2 : 2;
            self->state.edi += self->state.df ? -2 : 2;
            break;
            
        case 0xa6:
            self->state.cf = __builtin_sub_overflow(*(uint8_t *)[self getRegisterPointedMemory:reg_esi registerSize:8 accessType:MEM_READ], *(uint8_t *)[self getRegisterPointedMemory:reg_edi registerSize:8 accessType:MEM_READ], (uint8_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow(*(int8_t *)[self getRegisterPointedMemory:reg_esi registerSize:8 accessType:MEM_READ], *(int8_t *)[self getRegisterPointedMemory:reg_edi registerSize:8 accessType:MEM_READ], (int8_t *)&self->state.res);
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            
            self->state.esi += self->state.df ? -1 : 1;
            self->state.edi += self->state.df ? -1 : 1;
            break;
            
        case 0xa7:
            self->state.cf = __builtin_sub_overflow(*(uint16_t *)[self getRegisterPointedMemory:reg_esi registerSize:16 accessType:MEM_READ], *(uint16_t *)[self getRegisterPointedMemory:reg_edi registerSize:16 accessType:MEM_READ], (uint16_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow(*(int16_t *)[self getRegisterPointedMemory:reg_esi registerSize:16 accessType:MEM_READ], *(int16_t *)[self getRegisterPointedMemory:reg_edi registerSize:16 accessType:MEM_READ], (int16_t *)&self->state.res);
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            
            self->state.esi += self->state.df ? -2 : 2;
            self->state.edi += self->state.df ? -2 : 2;
            break;
            
        case 0xa8:
            [self readByteIncIP:&imm8];
            self->state.res = [self getRegisterValue:reg_eax opSize:8] & imm8;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
        case 0xa9:
            [self readTwoBytesIncIP:&imm16];
            self->state.res = [self getRegisterValue:reg_eax opSize:16] & imm16;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
            break;
            
        case 0xaa:
            [self.task userWrite:(uint8_t)[self getRegisterValue:reg_edi opSize:8] buf:(uint8_t *)[self getRegPointer:reg_eax opSize:8] count:1];
            self->state.edi += self->state.df ? -1 : 1;
            break;
            
        case 0xab:
            [self.task userWrite:(uint16_t)[self getRegisterValue:reg_edi opSize:16] buf:(uint16_t *)[self getRegPointer:reg_eax opSize:16] count:2];
            self->state.edi += self->state.df ? -2 : 2;
            break;
            
        case 0xac:
            [self.task userWrite:(uint8_t)[self getRegisterValue:reg_esi opSize:8] buf:(uint8_t *)[self getRegPointer:reg_eax opSize:8] count:1];
            self->state.edi += self->state.df ? -1 : 1;
            break;
            
        case 0xad:
            [self.task userWrite:(uint16_t)[self getRegisterValue:reg_esi opSize:16] buf:(uint16_t *)[self getRegPointer:reg_eax opSize:16] count:2];
            self->state.edi += self->state.df ? -2 : 2;
            break;
            
        case 0xae:
            // SCAS      m8    eA
            // Scan String
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            // regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                // This shouldnt happen?
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                die("Unexpected opcode");
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            // temp16 = [edi] == the value of what is in the memory location that edi points to
            temp16 = [self.task userReadOneBytes:(uint8_t)[self getRegisterValue:reg_edi opSize:8]];
            
            self->state.cf = __builtin_sub_overflow((uint8_t)temp16, *((uint8_t *)[self getRegPointer:reg_eax opSize:8]), (uint8_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow( (int8_t)temp16,  *((int8_t *)[self getRegPointer:reg_eax opSize:8]),  (int8_t *)&self->state.res);
            
            self->state.edi += self->state.df ? -2 : 2;
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
            
        case 0xaf:
            // SCAS      m16/32    eAX
            // SCASD     m32       EAX
            // Scan String
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            // regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                // This shouldnt happen?
                rmWritePtr = rmReadPtr  = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t)); memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                die("Unexpected opcode");
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            // temp16 = [edi] == the value of what is in the memory location that edi points to
            temp16 = [self.task userReadFourBytes:(uint16_t)[self getRegisterValue:reg_edi opSize:16]];
            
            self->state.cf = __builtin_sub_overflow((uint16_t)temp16, *((uint16_t *)[self getRegPointer:reg_eax opSize:16]), (uint16_t *)&self->state.res);
            self->state.of = __builtin_sub_overflow( (int16_t)temp16,  *((int16_t *)[self getRegPointer:reg_eax opSize:16]),  (int16_t *)&self->state.res);
            
            self->state.edi += self->state.df ? -2 : 2;
            
            self->state.af_ops = 1;
            self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
            break;
            
        case 0xb0:
        case 0xb1:
        case 0xb2:
        case 0xb3:
        case 0xb4:
        case 0xb5:
        case 0xb6:
        case 0xb7:
            [self readByteIncIP:&imm8];
            rmWritePtr = [self getRegPointer:(0x7 & firstOpByte) opSize:8];
            *(uint8_t *)rmWritePtr = (uint8_t)imm8;
            break;
            
        case 0xb8:
        case 0xb9:
        case 0xba:
        case 0xbb:
        case 0xbc:
        case 0xbd:
        case 0xbe:
        case 0xbf:
            [self readTwoBytesIncIP:&imm16];
            rmWritePtr = [self getRegPointer:(0x7 & firstOpByte) opSize:16];
            *(uint16_t *)rmWritePtr = (uint16_t)imm16;
            break;
            
        case 0xc0:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            // NOTE: In this case I am reading the 4 byte immediate value into the temp16 variable
            // which is unusal
            // I am doing this to re use code I wrote earlier for 0xd3 which will use the temp16 variable
            // as the argument for this operations
            [self readByteIncIP:&temp8];
            
            switch (mrm.reg) {
                case 0x0:
                    *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8 | (uint8_t)rmReadValue >> (8 - (uint8_t)temp8);
                    self->state.cf = (uint8_t)rmReadValue & 1;
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                    }
                case 0x1:
                    *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8 | (uint8_t)rmReadValue << (8 - temp8);
                    self->state.cf = (uint8_t)rmReadValue >> (8 - 1);
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ ((uint8_t)rmReadValue & 1);
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (8 - 1);
                    self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x5:
                    self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (temp8 - 1) & 1;
                    self->state.of = (uint8_t)rmReadValue >> (8 - 1);
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x7:
                    self->state.cf = ((uint8_t)rmReadValue >> (temp8 - 1)) & 1;
                    self->state.of = 0;
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;
            
        case 0xc1:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            // NOTE: In this case I am reading the 4 byte immediate value into the temp8 variable
            // which is unusal
            // I am doing this to re use code I wrote earlier for 0xd3 which will use the temp8 variable
            // as the argument for this operations
            [self readByteIncIP:&temp8];
            
            switch (mrm.reg) {
                case 0x0:
                    *rmWritePtr = *rmReadPtr << temp8 | *rmReadPtr >> (8 - temp8);
                    self->state.cf = *rmReadPtr & 1;
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ *rmReadPtr >> (8 - 1);
                    }
                    break;
                case 0x1:
                    *rmWritePtr = *rmReadPtr >> temp8 | *rmReadPtr << (8 - temp8);
                    self->state.cf = *rmReadPtr >> (8 - 1);
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ (*rmReadPtr & 1);
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    self->state.cf = *rmReadPtr << (temp8 - 1) >> (8 - 1);
                    self->state.of = self->state.cf ^ *rmReadPtr >> (8 - 1);
                    self->state.res = *rmWritePtr = *rmReadPtr << temp8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x5:
                    self->state.cf = *rmReadPtr << (temp8 - 1) >> (temp8 - 1) & 1;
                    self->state.of = *rmReadPtr >> (8 - 1);
                    self->state.res = *rmWritePtr = *rmReadPtr >> temp8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;                    break;
                case 0x7:
                    self->state.cf = (*rmReadPtr >> (temp8 - 1)) & 1;
                    self->state.of = 0;
                    self->state.res = *rmWritePtr = *rmReadPtr >> temp8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;
            
        case 0xc2:
            // RETN imm16
            [self readTwoBytesIncIP:&imm16];
            [self readFourBytesIncSP:&self->state.eip];
            self->state.esp += (uint16_t)imm16;
            break;
            
        case 0xc3:
            // RETN
            [self readFourBytesIncSP:&self->state.eip];
            break;
            
        case 0xc6:
            // MOV    r/m8    imm8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            [self readByteIncIP:&imm8];
            *((uint8_t *)rmWritePtr) = (uint8_t)imm8;
            break;
            
        case 0xc7:
            // MOV    r/m16/32    imm16/32
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            [self readTwoBytesIncIP:&imm16];
            *((uint16_t *)rmWritePtr) = (uint16_t)imm16;
            break;
            
        case 0xc9:
            // LEAVE    eBP
            self->state.esp = self->state.ebp;
            [self readFourBytesIncSP:&self->state.ebp];
            break;
            
        case 0xcd:
            // INT   imm8 - The SYSCALL Op - http://ref.x86asm.net/geek.html#xCD
            [self readByteIncIP:&imm8];
            return imm8;
            break;
            
        case 0xd0:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch (mrm.reg) {
                case 0x0:
                    temp8 = 1;
                    if (temp8) {
                        *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8 | (uint8_t)rmReadValue >> (8 - (uint8_t)temp8);
                        self->state.cf = (uint8_t)rmReadValue & 1;
                        if (temp8 == 1) {
                            self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                        }
                    }
                    break;
                case 0x1:
                    temp8 = 1;
                    if (temp8) {
                        *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8 | (uint8_t)rmReadValue << (8 - temp8);
                        self->state.cf = (uint8_t)rmReadValue >> (8 - 1);
                        if (temp8 == 1) {
                            self->state.of = self->state.cf ^ ((uint8_t)rmReadValue & 1);
                        }
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    temp8 = 1;
                    if (temp8) {
                        self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (8 - 1);
                        self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                        self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x5:
                    temp8 = 1;
                    if (temp8) {
                        self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (temp8 - 1) & 1;
                        self->state.of = (uint8_t)rmReadValue >> (8 - 1);
                        self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x7:
                    temp8 = 1;
                    if (temp8) {
                        self->state.cf = ((uint8_t)rmReadValue >> (temp8 - 1)) & 1;
                        self->state.of = 0;
                        self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;
            
        case 0xd1:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch (mrm.reg) {
                case 0x0:
                    temp16 = 1;
                    if (temp16) {
                        *rmWritePtr = *rmReadPtr << temp16 | *rmReadPtr >> (16 - temp16);
                        self->state.cf = *rmReadPtr & 1;
                        if (temp16 == 1) {
                            self->state.of = self->state.cf ^ *rmReadPtr >> (16 - 1);
                        }
                    }
                    break;
                case 0x1:
                    temp16 = 1;
                    if (temp16) {
                        *rmWritePtr = *rmReadPtr >> temp16 | *rmReadPtr << (16 - temp16);
                        self->state.cf = *rmReadPtr >> (16 - 1);
                        if (temp16 == 1) {
                            self->state.of = self->state.cf ^ (*rmReadPtr & 1);
                        }
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    temp16 = 1;
                    if (temp16) {
                        self->state.cf = *rmReadPtr << (temp16 - 1) >> (16 - 1);
                        self->state.of = self->state.cf ^ *rmReadPtr >> (16 - 1);
                        self->state.res = *rmWritePtr = *rmReadPtr << temp16;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x5:
                    temp16 = 1;
                    if (temp16) {
                        self->state.cf = *rmReadPtr << (temp16 - 1) >> (temp16 - 1) & 1;
                        self->state.of = *rmReadPtr >> (16 - 1);
                        self->state.res = *rmWritePtr = *rmReadPtr >> temp16;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x7:
                    temp16 = 1;
                    if (temp16) {
                        self->state.cf = (*rmReadPtr >> (temp16 - 1)) & 1;
                        self->state.of = 0;
                        self->state.res = *rmWritePtr = *rmReadPtr >> temp16;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;
            
        case 0xd2:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            temp8 = *(uint8_t *)[self getRegPointer:reg_ecx opSize:8] % 8;
            
            if (temp8 == 0) break;
            
            switch (mrm.reg) {
                case 0x0:
                    *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8 | (uint8_t)rmReadValue >> (8 - (uint8_t)temp8);
                    self->state.cf = (uint8_t)rmReadValue & 1;
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                    }
                case 0x1:
                    *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8 | (uint8_t)rmReadValue << (8 - temp8);
                    self->state.cf = (uint8_t)rmReadValue >> (8 - 1);
                    if (temp8 == 1) {
                        self->state.of = self->state.cf ^ ((uint8_t)rmReadValue & 1);
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (8 - 1);
                    self->state.of = self->state.cf ^ (uint8_t)rmReadValue >> (8 - 1);
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue << temp8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x5:
                    self->state.cf = (uint8_t)rmReadValue << (temp8 - 1) >> (temp8 - 1) & 1;
                    self->state.of = (uint8_t)rmReadValue >> (8 - 1);
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                case 0x7:
                    self->state.cf = ((uint8_t)rmReadValue >> (temp8 - 1)) & 1;
                    self->state.of = 0;
                    self->state.res = *(uint8_t *)rmWritePtr = (uint8_t)rmReadValue >> temp8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af = self->state.af_ops = 0;
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;
            
        case 0xd3:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            // temp16 = *(uint16_t *)[self getRegPointer:reg_ecx opSize:8] % 16;
            temp8 = self->state.cl % 16; // This is the shift count
            
            switch (mrm.reg) {
                case 0x0:
                    if (temp8 != 0) {
                        *rmWritePtr = *rmReadPtr << temp8 | *rmReadPtr >> (16 - temp8);
                        self->state.cf = *rmReadPtr & 1;
                        if (temp16 == 1) {
                            self->state.of = self->state.cf ^ *rmReadPtr >> (16 - 1);
                        }
                    }
                    break;
                case 0x1:
                    if (temp8 != 0) {
                        *rmWritePtr = *rmReadPtr >> temp8 | *rmReadPtr << (16 - temp8);
                        self->state.cf = *rmReadPtr >> (16 - 1);
                        if (temp8 == 1) {
                            self->state.of = self->state.cf ^ (*rmReadPtr & 1);
                        }
                    }
                    break;
                case 2:
                    self->state.eip = saved_ip;
                    break;
                case 3:
                    self->state.eip = saved_ip;
                    break;
                case 0x4:
                case 0x6:
                    if (temp8 != 0) {
                        self->state.cf = (*rmReadPtr << (temp8 - 1)) >> (16 - 1);
                        self->state.of = (self->state.cf ^ *rmReadPtr) >> (16 - 1);
                        self->state.res = *rmWritePtr = *rmReadPtr << temp8;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x5:
                    if (temp8 != 0) {
                        self->state.cf = *rmReadPtr << (temp8 - 1) >> (temp8 - 1) & 1;
                        self->state.of = *rmReadPtr >> (16 - 1);
                        self->state.res = *rmWritePtr = *rmReadPtr >> temp8;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                case 0x7:
                    if (temp8 != 0) {
                        self->state.cf = (*rmReadPtr >> (temp8 - 1)) & 1;
                        self->state.of = 0;
                        self->state.res = *rmWritePtr = *rmReadPtr >> temp8;
                        
                        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                        self->state.af = self->state.af_ops = 0;
                    }
                    break;
                default:
                    die("Reached an impossible opcode");
                    break;
            }
            break;
            
            // FPU Instructions Starts here
            
        case 0xd8:
            // http://ref.x86asm.net/coder32.html#xD8
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x2:
                    self->state.c1 = self->state.c2 = 0;
                    if (mrm.type == modrm_register) {
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.c0 = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], f80_from_double(tempfloat));
                        self->state.c0 = f80_eq(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x3:
                    self->state.c1 = self->state.c2 = 0;
                    if (mrm.type == modrm_register) {
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.c0 = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], f80_from_double(tempfloat));
                        self->state.c0 = f80_eq(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.fp[self->state.top] = f80_sub(f80_from_double(tempfloat), self->state.fp[self->state.top]);
                    }
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], f80_from_double(tempfloat));
                    }
                    break;
                case 0x7:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.fp[self->state.top] = f80_div(f80_from_double(tempfloat), self->state.fp[self->state.top]);
                    }
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xd9:
            // http://ref.x86asm.net/coder32.html#xD9
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        tempfloat80 = self->state.fp[self->state.top + mrm.rm_opcode];
                        self->state.top -= 1;
                        self->state.fp[self->state.top] = tempfloat80;
                    } else {
                        self->state.top -= 1;
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.fp[self->state.top] = f80_from_double(tempfloat);
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        tempfloat80 = self->state.fp[self->state.top];
                        self->state.fp[self->state.top] = self->state.fp[self->state.top + mrm.rm_opcode];
                        self->state.fp[self->state.top + mrm.rm_opcode] = tempfloat80;
                    } else {
                        die("Shouldnt happen");
                    }
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.fp[self->state.top] = f80_from_double(tempfloat);
                    }
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        [self.task userRead:addr buf:&tempfloat count:2];
                        self->state.fp[self->state.top] = f80_from_double(tempfloat);
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    die("Shoudlnt happen");
                    break;
                case 0x5:
                    // FCW    x87 FPU Control Word (16 bits). See Figure 8-6 in the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 1, for the layout of the x87 FPU control word.
                    // Not fxsave op but load:
                    // https://www.felixcloutier.com/x86/fxsave
                    [self.task userRead:addr buf:&self->state.fcw count:2];
                    break;
                case 0x6:
                    die("Shoudlnt happen");
                    break;
                case 0x7:
                    // fxsave
                    [self.task userWrite:addr buf:&self->state.fcw count:2];
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xda:
            // http://ref.x86asm.net/coder32.html#xDA
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch(mrm.opcode) {
                case 0x0:
                    [self.task userRead:addr buf:&temp16 count:2];
                    self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], f80_from_int(temp16));
                    break;
                case 0x1:
                    [self.task userRead:addr buf:&temp16 count:2];
                    self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], f80_from_int(temp16));
                    break;
                case 0x2:
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x3:
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    self->state.top += 1;
                    break;
                case 0x4:
                    [self.task userRead:addr buf:&temp16 count:2];
                    self->state.fp[self->state.top] = f80_sub(f80_from_int(temp16), self->state.fp[self->state.top]);
                    break;
                case 0x5:
                    [self.task userRead:addr buf:&temp16 count:2];
                    self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], f80_from_int(temp16));
                    break;
                case 0x6:
                    [self.task userRead:addr buf:&temp16 count:2];
                    self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], f80_from_int(temp16));
                    break;
                case 0x7:
                    [self.task userRead:addr buf:&temp16 count:2];
                    self->state.fp[self->state.top] = f80_div(f80_from_int(temp16), self->state.fp[self->state.top]);
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xdb:
            // http://ref.x86asm.net/coder32.html#xDB
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch(mrm.opcode) {
                case 0x0:
                    [self.task userRead:addr buf:&temp16 count:2];
                    tempfloat80 = f80_from_int(temp16);
                    self->state.top -= 1;
                    self->state.fp[self->state.top] = tempfloat80;
                    break;
                case 0x1:
                    die("shouldnt happen?");
                    break;
                case 0x2:
                    temp16 = f80_to_int(self->state.fp[self->state.top]);
                    [self.task userWrite:addr buf:&temp16 count:2];
                    break;
                case 0x3:
                    temp16 = f80_to_int(self->state.fp[self->state.top]);
                    [self.task userWrite:addr buf:&temp16 count:2];
                    self->state.top += 1;
                    break;
                case 0x4:
                    die("shouldnt happen?");
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.zf = f80_eq(self->state.fp[self->state.top + 0], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.cf = f80_lt(self->state.fp[self->state.top + 0], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.pf = 0;
                        self->state.pf_res = 0;
                    } else {
                        die("shouldnt happen?");
                    }
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.zf = f80_eq(self->state.fp[self->state.top + 0], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.cf = f80_lt(self->state.fp[self->state.top + 0], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.pf = 0;
                        self->state.pf_res = 0;
                    } else {
                        die("shouldnt happen?");
                    }
                    break;
                case 0x7:
                    [self.task userRead:addr buf:&self->state.fp[self->state.top] count:10];
                    self->state.top += 1;
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xdc:
            // http://ref.x86asm.net/coder32.html#xDC
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_add(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        tempfloat80 = f80_from_double(tempdouble);
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], tempfloat80);
                        self->state.c1 = 0;
                        self->state.c2 = 0;
                        self->state.c3 = f80_eq(self->state.fp[self->state.top], tempfloat80);
                    }
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        tempfloat80 = f80_from_double(tempdouble);
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], tempfloat80);
                        self->state.c1 = 0;
                        self->state.c2 = 0;
                        self->state.c3 = f80_eq(self->state.fp[self->state.top], tempfloat80);
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_sub(self->state.fp[self->state.top], self->state.fp[self->state.top]);
                    }
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x7:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_div(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_div(f80_from_double(tempdouble), self->state.fp[self->state.top]);
                    }
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xdd:
            // http://ref.x86asm.net/coder32.html#xDD
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        tempfloat80 = f80_from_double(tempdouble);
                        self->state.top -= 1;
                        self->state.fp[self->state.top] = tempfloat80;
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&tempdouble count:8];
                        self->state.fp[self->state.top] = f80_mul(self->state.fp[self->state.top], f80_from_double(tempdouble));
                    }
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        tempdouble = f80_to_double(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&tempdouble count:8];
                    }
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        tempdouble = f80_to_double(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&tempdouble count:8];
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.c1 = 0;
                        self->state.c2 = 0;
                        self->state.c3 = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        die("shoudlnt happen");
                    }
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.c0 = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.c1 = 0;
                        self->state.c2 = 0;
                        self->state.c3 = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        die("shoudlnt happen");
                    }
                    self->state.top += 1;
                    break;
                case 0x6:
                    die("shouldnt happen");
                    break;
                case 0x7:
                    die("shouldnt happen");
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xde:
            // http://ref.x86asm.net/coder32.html#xDE
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_add(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top] = f80_add(tempfloat80, self->state.fp[self->state.top]);;
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_mul(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_mul(tempfloat80, self->state.fp[self->state.top]);
                    }
                    self->state.top += 1;
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        self->state.eip = saved_ip;
                        return INT_UNDEFINED;
                    }
                    self->state.top += 1;
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        self->state.eip = saved_ip;
                        return INT_UNDEFINED;
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_sub(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_sub(self->state.fp[self->state.top], tempfloat80);
                    }
                    self->state.top += 1;
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_sub(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_sub(tempfloat80, self->state.fp[self->state.top]);
                    }
                    self->state.top += 1;
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_div(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_div(self->state.fp[self->state.top], tempfloat80);
                    }
                    self->state.top += 1;
                    break;
                case 0x7:
                    if (mrm.type == modrm_register) {
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_div(self->state.fp[self->state.top + mrm.rm_opcode], self->state.fp[self->state.top]);
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.fp[self->state.top + mrm.rm_opcode] = f80_div(tempfloat80, self->state.fp[self->state.top]);
                    }
                    self->state.top += 1;
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
        case 0xdf:
            // http://ref.x86asm.net/coder32.html#xDF
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch(mrm.opcode) {
                case 0x0:
                    if (mrm.type == modrm_register) {
                        self->state.top += 1;
                    } else {
                        [self.task userRead:addr buf:&temp16 count:2];
                        tempfloat80 = f80_from_int(temp16);
                        self->state.top -= 1;
                        self->state.fp[self->state.top] = tempfloat80;
                    }
                    break;
                case 0x1:
                    if (mrm.type == modrm_register) {
                        die("Shouldnt happen");
                    } else {
                        die("Shouldnt happen");
                    }
                    self->state.top += 1;
                    break;
                case 0x2:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        temp16 = f80_to_int(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&temp16 count:2];
                    }
                    self->state.top += 1;
                    break;
                case 0x3:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        temp16 = f80_to_int(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&temp16 count:2];
                    }
                    self->state.top += 1;
                    break;
                case 0x4:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        die("Could happen, just remove this if block for only the else block");
                    }
                    self->state.top += 1;
                    break;
                case 0x5:
                    if (mrm.type == modrm_register) {
                        self->state.zf = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.cf = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.pf = 0;
                        self->state.pf_res = 0;
                        self->state.top += 1;
                    } else {
                        [self.task userRead:addr buf:&temp64 count:8];
                        tempfloat80 = f80_from_int(temp64);
                        self->state.top -= 1;
                        self->state.fp[self->state.top] = tempfloat80;
                    }
                    self->state.top += 1;
                    break;
                case 0x6:
                    if (mrm.type == modrm_register) {
                        self->state.zf = f80_eq(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.cf = f80_lt(self->state.fp[self->state.top], self->state.fp[self->state.top + mrm.rm_opcode]);
                        self->state.pf = 0;
                        self->state.pf_res = 0;
                        self->state.top += 1;
                    } else {
                        die("Could happen, just remove this if block for only the else block");
                    }
                    self->state.top += 1;
                    break;
                case 0x7:
                    if (mrm.type == modrm_register) {
                        die("Could happen, just remove this if block for only the else block");
                    } else {
                        temp64 = f80_to_int(self->state.fp[self->state.top]);
                        [self.task userWrite:addr buf:&temp64 count:8];
                        self->state.top += 1;
                    }
                    self->state.top += 1;
                    break;
                default:
                    die("Reached an impossible FPU Opcode");
                    break;
            }
            break;
            
            // FPU Instructions Ends Here
            
        case 0xe3:
            // JCXZ     rel8    CX
            // JECXZ    rel8    ECX
            // Jump short if eCX register is 0
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            if (self->state.ecx == 0) {
                self->state.eip += (uint32_t)(int8_t)imm8;
            }
            break;
        case 0xe8:
            // CALL    rel16/32
            if ([self readTwoBytesIncIP:&imm16]) {
                SEGFAULT
            }
            if ([self.task userWrite:self->state.esp - 2 buf:&self->state.eip count:2]) {
                SEGFAULT
            }
            self->state.esp -= 2;
            
            self->state.eip += (uint16_t)(int16_t)imm16;
            // TODO: If this is a 16bit CALL then & eip by 0xffff after this eip += imm
            break;
            
        case 0xe9:
            // JMP    rel16/32
            if ([self readTwoBytesIncIP:&imm16]) {
                SEGFAULT
            }
            self->state.eip += (uint16_t)(int16_t)imm16;
            break;
            
        case 0xeb:
            // JMP    rel8
            if ([self readByteIncIP:&imm8]) {
                SEGFAULT
            }
            self->state.eip += (uint32_t)(int8_t)imm8;
            break;
        case 0xf6:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8];
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch (mrm.reg) {
                case 0x0:
                case 0x1:
                    // TEST    r/m8    imm8
                    [self readByteIncIP:&imm8];
                    
                    self->state.res = (uint8_t)rmReadValue & (uint8_t)imm8;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    break;
                case 0x2:
                    // NOT    r/m8
                    *(int8_t *)rmWritePtr = ~(int8_t)rmReadValue;
                    break;
                case 0x3:
                    // NEG    r/m8
                    // 2's compliment negation
                    [self readByteIncIP:&imm8];
                    
                    self->state.of = __builtin_sub_overflow((int8_t)0, (int8_t)rmReadValue, (int8_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint8_t)0, (uint8_t)rmReadValue, (uint8_t *)&self->state.res);
                    
                    *(int8_t *)rmWritePtr = (int8_t)self->state.res;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af_ops = 0;
                    break;
                case 0x4:
                    // MUL    AX    AL * r/m8
                    // Unsigned multiply
                    temp64 = (*(uint8_t *)[self getRegPointer:reg_eax opSize:8] * (uint64_t)((uint8_t)rmReadValue));
                    
                    *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = temp16;
                    *(uint8_t *)[self getRegPointer:reg_edx opSize:8] = temp16 >> 8;
                    
                    FFLog(@"\n\n\n  Check this OpCode result out! Is it correct? F6 /4    MUL r/m8   \n\n\n\n");
                    __debugbreak();
                    
                    // TODO: Was implemented as:
                    // uint64_t tmp = ((uint8_t)cpu->eax) * (uint64_t)(modrm.type == modrm_reg ? (*(uint8_t *)(((char *)cpu) + (modrm_base).reg8_id)) : ({ uint8_t val; if (!tlb_read(tlb, addr, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = addr; return INT_GPF; } val; }));
                    // *(uint8_t *)&cpu->eax = tmp;
                    // *(uint8_t *)&cpu->edx = tmp >> 8;
                    
                    self->state.cf = self->state.of = ((int16_t)temp64 != (uint16_t)temp64);
                    self->state.af = self->state.af_ops = 0;
                    self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    // IMUL    AX    AL * r/m8
                    // Signed multiply
                    
                    // TODO: This outer int64_t cast is unnecessary?
                    temp64 = (int64_t)(*(int8_t *)[self getRegPointer:reg_eax opSize:8] * (int64_t)((int8_t)rmReadValue));
                    
                    *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = temp16;
                    *(uint8_t *)[self getRegPointer:reg_edx opSize:8] = temp16 >> 8;
                    
                    FFLog(@"\n\n\n  Check this OpCode result out! Is it correct? F6 /5    IMUL r/m8   \n\n\n\n");
                    __debugbreak();
                    
                    // TODO: Does this of/cf check actually do anything?
                    self->state.cf = self->state.of = ((int16_t)temp64 != temp64);
                    self->state.af = self->state.af_ops = 0;
                    self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x6:
                    // DIV    AX    AL * r/m8
                    // Unsigned Divide
                    do {
                        divisor8 = (int8_t)rmReadValue;
                        // Divide by 0
                        if (divisor8 == 0) {
                            //break;
                            return INT_DIV;
                        }
                        
                        FFLog(@"\n\n\n  Check this op! \n\n\n");
                        __debugbreak();
                        
                        // Combine al and dl back into one 16 bit unsigned int
                        dividend16 = (*(uint8_t *)[self getRegPointer:reg_eax opSize:8]) | ((*(uint8_t *)[self getRegPointer:reg_edx opSize:8]) << 8);
                        
                        *(uint8_t *)[self getRegPointer:reg_edx opSize:8] = dividend16 % (uint8_t)rmReadValue;
                        *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = dividend16 / (uint8_t)rmReadValue;
                    } while (0);
                    break;
                case 0x7:
                    // IDIV    AX    AL * r/m8
                    // Signed Divide
                    do {
                        divisor8 = (int8_t)rmReadValue;
                        // Divide by 0
                        if (divisor8 == 0) {
                            //break;
                            return INT_DIV;
                        }
                        
                        FFLog(@"\n\n\n  Check this op! \n\n\n");
                        __debugbreak();
                        
                        // Combine al and dl back into one 16 bit unsigned int
                        dividend16 = (*(uint8_t *)[self getRegPointer:reg_eax opSize:8]) | ((*(uint8_t *)[self getRegPointer:reg_edx opSize:8]) << 8);
                        
                        *(uint8_t *)[self getRegPointer:reg_edx opSize:8] = dividend16 % (uint8_t)rmReadValue;
                        *(uint8_t *)[self getRegPointer:reg_eax opSize:8] = dividend16 / (uint8_t)rmReadValue;
                        // Should check is AL is > 0x7F of if int8_t al != uint8_t al maybe
                    } while (0);
                    break;
                default:
                    die("Impossible opcode encountered");
                    break;
            }
            break;
        case 0xf7:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch (mrm.reg) {
                case 0x0:
                case 0x1:
                    // TEST    r/m32    imm8
                    [self readTwoBytesIncIP:&imm16];
                    
                    self->state.res = (uint16_t)rmReadValue & (uint16_t)imm16;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
                    break;
                case 0x2:
                    // NOT    r/m32
                    *(int16_t *)rmWritePtr = ~(int16_t)rmReadValue;
                    break;
                case 0x3:
                    // NEG    r/m32
                    // 2's compliment negation
                    self->state.of = __builtin_sub_overflow((int16_t)0, (int16_t)rmReadValue, (int16_t *)&self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint16_t)0, (uint16_t)rmReadValue, (uint16_t *)&self->state.res);
                    
                    *(int16_t *)rmWritePtr = (int16_t)self->state.res;
                    
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    self->state.af_ops = 0;
                    break;
                case 0x4:
                    // MUL    AX    AL * r/m32
                    // Unsigned multiply
                    temp64 = (*(uint16_t *)[self getRegPointer:reg_eax opSize:16] * (uint64_t)((uint16_t)rmReadValue));
                    
                    *(uint16_t *)[self getRegPointer:reg_eax opSize:16] = temp16;
                    *(uint16_t *)[self getRegPointer:reg_edx opSize:16] = temp16 >> 8;
                    
                    FFLog(@"\n\n\n  Check this OpCode result out! Is it correct? F6 /4    MUL r/m8   \n\n\n\n");
                    __debugbreak();
                    
                    self->state.cf = self->state.of = ((int16_t)temp64 != (uint16_t)temp64);
                    self->state.af = self->state.af_ops = 0;
                    self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x5:
                    // IMUL    AX    AL * r/m32
                    // Signed multiply
                    
                    // TODO: This outer int64_t cast is unnecessary?
                    temp64 = (int64_t)(*(int16_t *)[self getRegPointer:reg_eax opSize:16] * (int64_t)((int16_t)rmReadValue));
                    
                    *(uint16_t *)[self getRegPointer:reg_eax opSize:16] = temp16;
                    *(uint16_t *)[self getRegPointer:reg_edx opSize:16] = temp16 >> 16;
                    
                    FFLog(@"\n\n\n  Check this OpCode result out! Is it correct? F6 /5    IMUL r/m8   \n\n\n\n");
                    __debugbreak();
                    
                    // TODO: Does this of/cf check actually do anything?
                    self->state.cf = self->state.of = ((int16_t)temp64 != temp64);
                    self->state.af = self->state.af_ops = 0;
                    self->state.zf = self->state.sf = self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x6:
                    // DIV    AX    AL * r/m32
                    // Unsigned Divide
                    do {
                        divisor16 = (int16_t)rmReadValue;
                        // Divide by 0
                        if (divisor16 == 0) {
                            //break;
                            return INT_DIV;
                        }
                        
                        
                        
                        // Combine al and dl back into one 16 bit unsigned int
                        dividend16 = (*(uint16_t *)[self getRegPointer:reg_eax opSize:16]) | ((*(uint16_t *)[self getRegPointer:reg_edx opSize:16]) << 16);
                        
                        *(uint16_t *)[self getRegPointer:reg_edx opSize:16] = dividend16 % (uint16_t)rmReadValue;
                        *(uint16_t *)[self getRegPointer:reg_eax opSize:16] = dividend16 / (uint16_t)rmReadValue;
                    } while (0);
                    break;
                case 0x7:
                    // IDIV    AX    AL * r/m32
                    // Signed Divide
                    do {
                        divisor16 = (int16_t)rmReadValue;
                        // Divide by 0
                        if (divisor16 == 0) {
                            //break;
                            return INT_DIV;
                        }
                        
                        FFLog(@"\n\n\n  Check this op! \n\n\n");
                        __debugbreak();
                        
                        // Combine al and dl back into one 16 bit unsigned int
                        dividend16 = (*(uint16_t *)[self getRegPointer:reg_eax opSize:16]) | ((*(uint16_t *)[self getRegPointer:reg_edx opSize:16]) << 8);
                        
                        *(uint16_t *)[self getRegPointer:reg_edx opSize:16] = dividend16 % (uint16_t)rmReadValue;
                        *(uint16_t *)[self getRegPointer:reg_eax opSize:16] = dividend16 / (uint16_t)rmReadValue;
                    } while (0);
                    break;
                default:
                    die("Impossible opcode encountered");
                    break;
            }
            break;
        case 0xfc:
            // CLD
            // Clear direction flag
            self->state.df = 0;
            break;
        case 0xfd:
            // SLD
            // Set direction flag
            self->state.df = 1;
            break;
        case 0xfe:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:8];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:8];
                rmReadPtr = [self getRegPointer:mrm.base opSize:8]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:8];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint8_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch (mrm.reg) {
                case 0x0:
                    // INC    r/m8
                    self->state.cf = __builtin_add_overflow((uint8_t)rmReadValue, (uint8_t)1, (uint8_t *)&self->state.res);
                    self->state.of = __builtin_add_overflow((int8_t)rmReadValue, (int8_t)1, (int8_t *)&self->state.res);
                    
                    *(uint8_t *)rmWritePtr = (int8_t)self->state.res;
                    
                    self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    // DEC    r/m8
                    self->state.cf = __builtin_sub_overflow((uint8_t)rmReadValue, (uint8_t)1, (uint8_t *)&self->state.res);
                    self->state.of = __builtin_sub_overflow((int8_t)rmReadValue, (int8_t)1, (int8_t *)&self->state.res);
                    
                    *(uint8_t *)rmWritePtr = (int8_t)self->state.res;
                    
                    self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                default:
                    die("Impossible opcode encountered");
                    break;
            }
            break;
        case 0xff:
            [self readByteIncIP:&modRMByte];
            mrm = [self decodeModRMByte:modRMByte];
            regPtr = [self getRegPointer:mrm.reg opSize:16];
            if (mrm.type == modrm_register) {
                rmWritePtr = [self getRegPointer:mrm.base opSize:16];
                rmReadPtr = [self getRegPointer:mrm.base opSize:16]; memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
            } else {
                addr = [self getModRMAddress:mrm opSize:16];
                if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
                    return INT_GPF;
                }
                memcpy(&rmReadValue, rmReadPtr, sizeof(uint16_t));
                rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
            }
            
            switch (mrm.reg) {
                case 0x0:
                    // INC    r/m32
                    self->state.of = __builtin_add_overflow((int16_t)rmReadValue, (int16_t)1, &self->state.res);
                    self->state.cf = __builtin_add_overflow((uint16_t)rmReadValue, (uint16_t)1, &self->state.res);
                    
                    *(uint16_t *)rmWritePtr = (int16_t)self->state.res;
                    
                    self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x1:
                    // DEC    r/m32
                    self->state.of = __builtin_sub_overflow((int16_t)rmReadValue, (int16_t)1, &self->state.res);
                    self->state.cf = __builtin_sub_overflow((uint16_t)rmReadValue, (uint16_t)1, &self->state.res);
                    
                    *(uint16_t *)rmWritePtr = (int16_t)self->state.res;
                    
                    self->state.af_ops = 0;
                    self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
                    break;
                case 0x2:
                    // CALL    r/m16/32
                    [self.task userWrite:(self->state.esp-2) buf:&self->state.eip count:2];
                    self->state.esp -= 2;
                    
                    self->state.eip = (uint16_t)rmReadValue;
                    break;
                case 0x3:
                    // CALLF    r/m16/32
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x4:
                    // JMP    r/m16/32
                    self->state.eip = (uint16_t)rmReadValue;
                    break;
                case 0x5:
                    // JMPF    r/m16/32
                    self->state.eip = saved_ip;
                    return INT_UNDEFINED;
                    break;
                case 0x6:
                    // PUSH    r/m16/32
                    [self.task userWrite:(self->state.esp-2) buf:&rmReadValue count:2];
                    self->state.esp -= 2;
                    break;
                default:
                    die("Impossible opcode encountered");
                    break;
            }
            break;
        default:
            fprintf(stderr, "Unimplemented OP %x", firstOpByte);
            die("Unimplemented OP");
            break;
    }
    
    return -1;
}


// END STEP 16

- (addr_t)getModRMAddress:(modrm)modrm opSize:(int)opSize {
    addr_t rmAddr = 0;

    if (modrm.type != modrm_register) {
        // If modrm is for:
        // [EAX]
        // [EAX]+disp8
        // [EAX]+disp32
        // rmAddr += [self getRegValue:modrm.rm opSize:opSize];
        if (modrm.base != reg_no_reg) {
            if (modrm.mode == mode_reg_only) {
                if (opSize == 32) {
                    rmAddr += (uint32_t)[self getRegisterValue:modrm.base opSize:opSize]; //TODO: opSize:opsize
                } else if (opSize == 8) {
                    rmAddr += (uint8_t)[self getRegisterValue:modrm.base opSize:opSize]; //TODO: opSize:opsize
                }
            } else {
                rmAddr += (uint32_t)[self getRegisterValue:modrm.base opSize:32];
            }
            
        }
        rmAddr += modrm.displacement;
        
        if (modrm.type == modrm_sib) {
            // If modrm is for:
            // [sib]
            // [sib]+disp8
            // [sib]+disp32
            rmAddr += [self getRegisterValue:modrm.index opSize:32] << modrm.shift; // rmAddr += [self getRegisterValue:modrm.index opSize:opSize] << modrm.shift;
        }
    }
    return rmAddr;
}

- (void)printState:(uint8_t) op {
    CPULog(@"P: %d eax: %x ebx: %x ecx: %x edx: %x esi: %x edi: %x ebp: %x esp: %x eip: %x eflags: %x res: %x\n", self.task.pid.id, self->state.eax, self->state.ebx, self->state.ecx, self->state.edx, self->state.esi, self->state.edi, self->state.ebp, self->state.esp, self->state.eip, self->state.eflags, self->state.res);
    // CPULog(@"cf_bit %d pf %d af %d zf %d sf %d tf %d if_ %d df %d of_bit %d iopl %d pf_res %d sf_res %d af_ops %d op: %x #: %d\n", self->state.cf_bit, self->state.pf, self->state.af, self->state.zf, self->state.sf, self->state.tf, self->state.if_, self->state.df, self->state.of_bit, self->state.iopl, self->state.pf_res, self->state.sf_res, self->state.af_ops, op, self->instructionCount);
}

- (dword_t)getRegisterValue:(enum reg32) reg opSize:(int)opSize {
    if (opSize == 32) {
        switch (reg) {
            case reg_eax: return self->state.eax;
            case reg_ecx: return self->state.ecx;
            case reg_edx: return self->state.edx;
            case reg_ebx: return self->state.ebx;
            case reg_esp: return self->state.esp;
            case reg_ebp: return self->state.ebp;
            case reg_esi: return self->state.esi;
            case reg_edi: return self->state.edi;
            case reg_no_reg: die("Requesting a register pointer with invalid arguments, reg none");
        }
    } else if (opSize == 16) {
        switch (reg) {
            case reg_eax: return self->state.ax;
            case reg_ecx: return self->state.cx;
            case reg_edx: return self->state.dx;
            case reg_ebx: return self->state.bx;
            case reg_esp: return self->state.sp;
            case reg_ebp: return self->state.bp;
            case reg_esi: return self->state.si;
            case reg_edi: return self->state.di;
            case reg_no_reg: die("Requesting a register pointer with invalid arguments, reg none");
        }
    } else if (opSize == 8) {
        switch (reg) {
            case reg_eax: return self->state.al;
            case reg_ecx: return self->state.cl;
            case reg_edx: return self->state.dl;
            case reg_ebx: return self->state.bl;
            case reg_esp: return self->state.ah;
            case reg_ebp: return self->state.ch;
            case reg_esi: return self->state.dh;
            case reg_edi: return self->state.bh;
            case reg_no_reg: die("Requesting a register pointer with invalid arguments, reg none");
        }
    } else {
        die("Requesting a register pointer with invalid arguments");
    }
}

- (void *)getRegisterPointedMemory:(enum reg32) reg registerSize:(int)registerSize accessType:(int)accessType {
    return [self.task.mem getPointer:[self getRegisterValue:reg opSize:registerSize] type:accessType];
}

- (void *)getRegPointer:(enum reg32) reg opSize:(int)opSize {
    if (opSize == 32) {
        switch (reg) {
            case reg_eax: return &self->state.eax;
            case reg_ecx: return &self->state.ecx;
            case reg_edx: return &self->state.edx;
            case reg_ebx: return &self->state.ebx;
            case reg_esp: return &self->state.esp;
            case reg_ebp: return &self->state.ebp;
            case reg_esi: return &self->state.esi;
            case reg_edi: return &self->state.edi;
            case reg_no_reg: die("Requesting a register pointer with invalid arguments, reg none");
        }
    } else if (opSize == 16) {
        switch (reg) {
            case reg_eax: return &self->state.ax;
            case reg_ecx: return &self->state.cx;
            case reg_edx: return &self->state.dx;
            case reg_ebx: return &self->state.bx;
            case reg_esp: return &self->state.sp;
            case reg_ebp: return &self->state.bp;
            case reg_esi: return &self->state.si;
            case reg_edi: return &self->state.di;
            case reg_no_reg: die("Requesting a register pointer with invalid arguments, reg none");
        }
    } else if (opSize == 8) {
        switch (reg) {
            case reg_eax: return &self->state.al;
            case reg_ecx: return &self->state.cl;
            case reg_edx: return &self->state.dl;
            case reg_ebx: return &self->state.bl;
            case reg_esp: return &self->state.ah;
            case reg_ebp: return &self->state.ch;
            case reg_esi: return &self->state.dh;
            case reg_edi: return &self->state.bh;
            case reg_no_reg: die("Requesting a register pointer with invalid arguments, reg none");
        }
    } else {
        die("Requesting a register pointer with invalid arguments");
    }
}

- (modrm)decodeModRMByte:(char)modRMByte {
    // https://www-user.tu-chemnitz.de/~heha/viewchm.php/hs/x86.chm/x86.htm
    // Section 9
    // Shows the different addressing modes and when to take into account the SIB byte
    //
    // Calculating the address with the modrm byte is done with the modrm byte + the sib bbyte
    // only if RM is 0b100 or 4
    // Then MOD will tell us the displacement type (the number of bytes used to describe the memory offset)
    // or if MOD == 3 then the displacement if gathered from a register
    //
    // And if you look at section 2 on that same page you can see the "x86 Instruction Format Reference"
    // The image below shows that after the 1 or 2 opcode bytes there is the modrm byte, then the sib byte
    // (only if it exists as described above), and then 0 to 4 bytes depending on the displacement size
    // gathered from the modrm byte (it could also not use displacement making it 0 bytes, or if disp32 then
    // displacement is 4 bytes for example).
    //
    // https://www.scs.stanford.edu/05au-cs240c/lab/i386/s17_02.htm
    //
    // ModRM and SIB byte tables
    // http://ref.x86asm.net/coder32.html#sib_byte_32

//    char mode = (modeRMByte & 0b11000000) >> 6;
//    char reg =  (modeRMByte & 0b00111000) >> 6;
//    char rm  =  (modeRMByte & 0b00000111) >> 6;

    modrm dec; // decoded moderm byte

    enum {
        mode_disp0,
        mode_disp8,
        mode_disp32,
        mode_reg,
    } mode = MOD(modRMByte);

    dec.type = modrm_mem;
    dec.reg = REG(modRMByte);
    dec.rm_opcode = RM(modRMByte);
    if (mode == MODE_REG) {
        // Any of these cases:
        // 11 000 register  ( al / ax / eax )
        // 11 001 register  ( cl / cx / ecx )
        // 11 010 register  ( dl / dx / edx )
        // 11 011 register  ( bl / bx / ebx )
        // 11 100 register  ( ah / sp / esp )
        // 11 101 register  ( ch / bp / ebp )
        // 11 110 register  ( dh / si / esi )
        // 11 111 register  ( bh / di / edi )
        //
        dec.type = modrm_register;
    } else if (dec.rm_opcode == RM_DISP32 && mode == MODE_DISP0) {
        // If mode and rm are:
        // MOD=00 RM[101  ß-bit Displacement-Only Mode (4)
        dec.base = reg_no_reg;
        mode = MODE_DISP32;
    } else if (dec.rm_opcode == RM_SIB && mode != MODE_REG) {
        // If mod and rm are any pf the following:
        //MOD  RM
        // 00 100 SIB  Mode
        // 01 100 SIB  +  disp8  Mode
        // 10 100 SIB  +  disp32  Mode

        uint8_t sib_byte;
        [self readByteIncIP:&sib_byte];
        dec.base = BASE(sib_byte);

        if (dec.rm_opcode == RM_DISP32) {
            if (mode == mode_disp0) {
                dec.base = reg_no_reg;
                mode = mode_disp32;
            } else {
                dec.base = reg_ebp;
            }
        }

//        // Handle the special SIB mode cases for the mod bits
//        if (BASE(sib_byte) == BASE_DISPLACEMENT_ONLY_OR_EBP) {
//            if (mode == MODE_DISP0) {
//                // If mod is no displacement then any of the following:
//                // [ reg32 + eax*n ] MOD = 00
//                // [ reg32 + ebx*n ]
//                // [ reg32 + ecx*n ]
//                // [ reg32 + edx*n ]
//                // [ reg32 + ebp*n ]
//                // [ reg32 + esi*n ]
//                // [ reg32 + edi*n ]
//                dec.base = reg_no_reg;
//                mode = MODE_DISP32;
//            } else {
//                // If the mod bits of the modrm byte was 0b01 or 0b10 then the base register is ebp
//                // mode cannot be 0b11 as determined by the outer if that also checked the SIB bits
//                dec.base = reg_ebp;
//            }
//        }

        // Otherwise in SIB mode this is just a form of indexing into memory

        // The index bits from the sib byte choose a register which will be shifted n number of times to the left depending on the scale bits
        // This is the same as multiplying the index bits register by 1, 2, 4, or 8
        dec.index = INDEX(sib_byte);

        // wSection 8.1 refers to a variable "n" which is shift here https://www-user.tu-chemnitz.de/~heha/viewchm.php/hs/x86.chm/x86.htm
        // This is also referred to as the "scale" bits which determine the number of left bit shifts to happen with the register from the index bits
        dec.shift = SCALE(sib_byte);

        if (dec.index != RM_NO_INDEX) {
            dec.type = modrm_sib;
        }

        // https://www-user.tu-chemnitz.de/~heha/viewchm.php/hs/x86.chm/x86.htm
        // says
        // Note that this addressing mode does not allow the use of the ESP register
        // as an index register. Presumably, Intel left this particular mode undefined
        // to provide the ability to extend the addressing modes in a future version of
        // the CPU.
        //
        // However there is an opcode in busybox with index of esp
        //
        // if (dec.index == ILLEGAL_SIB_INDEX) {
        //     die("Illegal SIB index used 0b100");
        // }
    }

    // Now that we have read and processed the ModRM byte and SIB byte
    // we can move onto reading the displacement byte/s if there are any
    if (mode == MODE_DISP0) {
        dec.displacement = 0;
    } else if (mode == MODE_DISP8) {
        int8_t displacement;
        [self readByteIncIP:&displacement];
        dec.displacement = displacement;
    } else if (mode == MODE_DISP32) {
        dword_t displacement;
        [self readFourBytesIncIP:&displacement];
        dec.displacement = displacement;
    }

//    TRACE("reg=%s opcode=%d ", reg32_name(dec.reg), dec.opcode);
//    TRACE("base=%s ", reg32_name(dec.base));
//    if (dec.type_of_modrm_operand != modrm_reg)
//        TRACE("offset=%s0x%x ", dec.offset < 0 ? "-" : "", dec.offset);
//    if (dec.type_of_modrm_operand == modrm_mem_si)
//        TRACE("index=%s<<%d ", reg32_name(dec.index), dec.shift);

    return dec;
}

- (modrm)decodeModRMByteFromAddress:(addr_t)ip {
    char b;
    [self.task userRead:ip buf:&b count:sizeof(char)];
    return [self decodeModRMByte:b];
}


- (void)test {
    CLog(@"test func for %d", self.task.pid.id);
    self.interrupt = [self step:0];
}

- (void)runLoop {
    
    [NSThread setThreadPriority:0.2];

    // Now that we are in the runloop grab the pthread that OSX is using underneath so I can send singals to this thread later..
    // TOOD: Just use pthreads themselves
    self.task->thread = pthread_self();

    FFLog(@"Exec: Initiating run loop with IP:%d and Entry Point:%d", self.task.pid.id, self.task->elfEntryPoint);
    
    
    // FOR DEBUGGING
    // Load up an ish trace to compare registers against:
    NSString *debugFilename = [NSString stringWithFormat:@"/Users/bbarrows/ishtrace-%d.json", self.task.pid.id];
    CPULog(@"Tracing with file: %@\n", debugFilename);
    NSString *debugFileContents = [NSString stringWithContentsOfFile:debugFilename encoding:NSUTF8StringEncoding error:nil];
    
    // first, separate by new line
    NSArray *debugJsonStringsLineSeperated = [debugFileContents componentsSeparatedByCharactersInSet: [NSCharacterSet newlineCharacterSet]];
    
    self.ishDebugState = [[NSMutableDictionary alloc] init];;
    
    for (NSString *l in debugJsonStringsLineSeperated) {
        NSData * jsonTraceData = [l dataUsingEncoding:NSUTF8StringEncoding];
        NSError * error=nil;
        NSDictionary *td = [NSJSONSerialization JSONObjectWithData:jsonTraceData options:kNilOptions error:&error];
        //self.ishOut[td[@"num"]] = td;
        NSString *k = td[@"num"];
        if (k) {
            [self.ishDebugState setValue:td forKey:k];
        }
    }
    
    
    NSString *memDebugFilename = [NSString stringWithFormat:@"/Users/bbarrows/ishmemwrite-%d.json", self.task.pid.id];
    CPULog(@"Tracing mem with file: %@\n", memDebugFilename);
    NSString *memDebugFilenameContents = [NSString stringWithContentsOfFile:memDebugFilename encoding:NSUTF8StringEncoding error:nil];
    
    // first, separate by new line
    NSArray *memDebugJsonStringsLineSeperated = [memDebugFilenameContents componentsSeparatedByCharactersInSet: [NSCharacterSet newlineCharacterSet]];
    
    self.ishMemDebugState = [[NSMutableDictionary alloc] init];;
    
    for (NSString *l in memDebugJsonStringsLineSeperated) {
        NSData * jsonTraceData = [l dataUsingEncoding:NSUTF8StringEncoding];
        NSError * error=nil;
        NSDictionary *memWriteLine = [NSJSONSerialization JSONObjectWithData:jsonTraceData options:kNilOptions error:&error];
        //self.ishOut[td[@"num"]] = td;
        NSString *insnCountKey = memWriteLine[@"insn"];
        if (insnCountKey) {
            [self.ishMemDebugState setValue:memWriteLine forKey:insnCountKey];
        }
    }
    
    
    self->instructionCount = 0;
    // END TRACING

    // Loop
    while (![self.thread isCancelled]) {
        // TODO: some stuff

        // remember always update UI objects on the main thread:
        // [self performSelector:@selector(updateUI:) onThread:[NSThread mainThread] withObject:nil waitUntilDone:NO];
        int cycleCount = 0;
        while (true) {
            // If an interrupt occurs self.interrupt will be set
            
//            lock(&cpuStepLock);
            self.interrupt = [self step:0];
//            unlock(&cpuStepLock);
            
            if (self.interrupt == INT_NONE && cycleCount++ >= NUM_CYCLES_TO_PROCESS_BEFORE_INT_TIMER) {
                cycleCount = 0;
                self.interrupt = INT_TIMER;
            }
            if (self.interrupt != INT_NONE) {
                self->state.trapno = self.interrupt;
                // read_wrunlock(&cpu->mem->lock);
                [self handleInterrupt:self.interrupt];
                // read_wrlock(&cpu->mem->lock);
                // if (tlb.mem != cpu->mem)
                //     tlb.mem = cpu->mem;
                // if (cpu->mem->changes != changes) {
                //     tlb_flush(&tlb);
                //     changes = cpu->mem->changes;
                // }
            }
//            sleep(1);  // works
//            [NSThread sleepForTimeInterval:0.01]; // works with value as small as 0.01
            pthread_yield_np(); // does NOT work but doing it just in case
            
        }

        pthread_yield_np();
    }

    // De-init
    self.thread = nil;
}

+ (NSString *)getRegisterString:(enum reg32)reg {
    switch (reg) {
        case reg_eax: return @"eax";
        case reg_ecx: return @"ecx";
        case reg_edx: return @"edx";
        case reg_ebx: return @"ebx";
        case reg_esp: return @"esp";
        case reg_ebp: return @"ebp";
        case reg_esi: return @"esi";
        case reg_edi: return @"edi";
        default:
            return @"NoReg";
    }
    return @"None";
}

@end

