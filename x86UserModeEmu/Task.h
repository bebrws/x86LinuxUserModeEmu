// This is all obviously from Ish

#import <Foundation/Foundation.h>
#include <stddef.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#import "debug.h"
#import "misc.h"
#import "elf.h"
#import "signal.h"
#import "AnyArgs.h"
#import "CPU.h"
#import "Pid.h"
#import "SigInfo.h"
#import "SigHandler.h"
#import "SigQueue.h"
#import "SigSet.h"

#import "ThreadGroup.h"

#import "time.h"

//#import "Memory.h"
//#import "CPU.h"
//#import "FileDescriptor.h"
#import "FileSystem.h"


#define MAX_GROUPS 32
#define MAX_PID (1 << 15) // oughta be enough
#define superuser() (current != NULL && current->euid == 0)

// open flags
#define O_ACCMODE_ 3
#define O_RDONLY_ 0
#define O_WRONLY_ (1 << 0)
#define O_RDWR_ (1 << 1)
#define O_CREAT_ (1 << 6)
#define O_EXCL_ (1 << 7)
#define O_NOCTTY_ (1 << 8)
#define O_TRUNC_ (1 << 9)
#define O_APPEND_ (1 << 10)
#define O_NONBLOCK_ (1 << 11)
#define O_DIRECTORY_ (1 << 16)
#define O_CLOEXEC_ (1 << 19)

// generic ioctls
#define FIONREAD_ 0x541b
#define FIONBIO_ 0x5421

#define N_SYMLINK_FOLLOW 1
#define N_SYMLINK_NOFOLLOW 2
#define N_PARENT_DIR_WRITE 4


extern __thread sigjmp_buf unwind_buf;
extern __thread bool should_unwind;
static inline int sigunwind_start() {
    if (sigsetjmp(unwind_buf, 1)) {
        should_unwind = false;
        return 1;
    } else {
        should_unwind = true;
        return 0;
    }
}
static inline void sigunwind_end() {
    should_unwind = false;
}



#define SS_ONSTACK_ 1
#define SS_DISABLE_ 2
#define MINSIGSTKSZ_ 2048

struct stack_t_ {
    addr_t stack;
    dword_t flags;
    dword_t size;
};


// ----------- Signal handler structs
// thanks kernel for giving me something to copy/paste
struct sigcontext_ {
    word_t gs, __gsh;
    word_t fs, __fsh;
    word_t es, __esh;
    word_t ds, __dsh;
    dword_t di;
    dword_t si;
    dword_t bp;
    dword_t sp;
    dword_t bx;
    dword_t dx;
    dword_t cx;
    dword_t ax;
    dword_t trapno;
    dword_t err;
    dword_t ip;
    word_t cs, __csh;
    dword_t flags;
    dword_t sp_at_signal;
    word_t ss, __ssh;
    
    dword_t fpstate;
    dword_t oldmask;
    dword_t cr2;
};

struct ucontext_ {
    uint_t flags;
    uint_t link;
    struct stack_t_ stack;
    struct sigcontext_ mcontext;
    sigset_t_ sigmask;
} __attribute__((packed));

struct fpreg_ {
    word_t significand[4];
    word_t exponent;
};

struct fpxreg_ {
    word_t significand[4];
    word_t exponent;
    word_t padding[3];
};

struct xmmreg_ {
    uint32_t element[4];
};

struct fpstate_ {
    /* Regular FPU environment.  */
    dword_t cw;
    dword_t sw;
    dword_t tag;
    dword_t ipoff;
    dword_t cssel;
    dword_t dataoff;
    dword_t datasel;
    struct fpreg_ st[8];
    word_t status;
    word_t magic;
    
    /* FXSR FPU environment.  */
    dword_t _fxsr_env[6];
    dword_t mxcsr;
    dword_t reserved;
    struct fpxreg_ fxsr_st[8];
    struct xmmreg_ xmm[8];
    dword_t padding[56];
};

struct sigframe_ {
    addr_t restorer;
    dword_t sig;
    struct sigcontext_ sc;
    struct fpstate_ fpstate;
    dword_t extramask;
    char retcode[8];
};

struct rt_sigframe_ {
    addr_t restorer;
    int_t sig;
    addr_t pinfo;
    addr_t puc;
    union {
        siginfo_ info;
        char __pad[128];
    };
    struct ucontext_ uc;
    char retcode[8];
};

// On a 64-bit system with 32-bit emulation, the fpu state is stored in extra
// space at the end of the frame, not in the frame itself. We store the fpu
// state in the frame where it should be, and ptraceomatic will set this. If
// they are set we'll add some padding to the bottom to the frame to make
// everything align.
extern int xsave_extra;
extern int fxsave_extra;





//#ifndef TASK_H
//#define TASK_H


// this structure is allocated on the stack of the parent's clone() call
// TODO This came from kernel/task.h
struct vfork_info {
    bool done;
    NSCondition *cond;
    NSLock *lock;
};


@class ThreadGroup;
@class SigInfo;
@class SigHandler;
@class SigQueue;
@class Memory;
@class Pid;
@class CPU;
@class FileDescriptor;
@class FileSystem;
@class EnvArgs;
@class ArgArgs;
@class Task;
@class FileDescriptorTable;
@class SigSet;





@interface Task : NSObject {
    @public addr_t elfEntryPoint;
    @public pthread_rwlock_t memLock;
    @public lock_t generalLock;
    @public pthread_t thread;
    @public bool hasSavedMask;
    @public addr_t stackStartAddress;
    
    @public addr_t vdsoAddress; // immutable
    @public addr_t startBrkAddress; // immutable
    @public addr_t brkAddress;
    
    // These start and end points are addresses in the task's virtual memory
    // where these strings or lists of strings start and end
    @public addr_t argvStartAddress;
    @public addr_t argvEndAddress;
    @public addr_t envStartAddress;
    @public addr_t envEndAddress;
    
    // @public pid_t pid; // Get this from self.pid.id
    @public pid_t tgid; // immutable
    @public uid_t_ uid;
    @public uid_t_ gid;
    @public uid_t_ euid;
    @public uid_t_ egid;
    
    @public uid_t_ suid;
    @public uid_t_ sgid;
    
    // The atomic operations need to be doen with special functions or macros:
    // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/OSAtomicIncrement32.3.html#//apple_ref/doc/man/3/OSAtomicIncrement32
    // TODO: Does this need to be a atomic property
    @public atomic_uint mmRefCount;
    // @property (nonatomic, assign) atomic_uint mmRefCount;
    
    @public unsigned int ngroups;
    @public int changes;
    @public int exit_signal;
    
    // locked by pids_lock
    @public dword_t exitCode;
    @public bool zombie;
    @public bool exiting;
    
    @public struct vfork_info vfork;
    
    @public lock_t waitingLock;
    @public lock_t waitingConditionLock;
    @public cond_t waitingCondition;
//    @public pthread_rwlock_t generalLock;
    
    @public addr_t clear_tid;
    @public addr_t robust_list;
}

@property (nonatomic, strong) SigSet *savedBlockedSignals;
@property (nonatomic, strong) SigSet *blockedSignals;
@property (nonatomic, strong) SigSet *pendingSignals;
@property (nonatomic, strong) SigSet *waitingSignals;

@property (nonatomic, strong) SigHandler *sigHandler;
@property (nonatomic, strong) SigQueue   *sigQueue;

@property (nonatomic, strong) Pid *pid;
@property (nonatomic, strong) FileDescriptorTable *filesTable;
@property (nonatomic, assign) bool didExec;

@property (nonatomic, strong) FileSystem *fs;
@property (nonatomic, strong) CPU *cpu;

@property (nonatomic, strong) NSDictionary *pageTableEntryLookup;
@property (nonatomic, strong) Memory *mem;

// File descriptor for the file being executed
@property (nonatomic, strong) FileDescriptor *exeFile;

@property (nonatomic, strong) ThreadGroup *group;
@property (nonatomic, strong) NSMutableArray *groupLinks;
@property (nonatomic, strong) NSMutableArray *groups;
@property (nonatomic, strong) NSMutableString *command; // The command issued to execve to create this task

// locked by pids_lock
@property (nonatomic, assign) Task *parent;
@property (nonatomic, strong) NSMutableArray *children; // Array of Tasks
@property (nonatomic, strong) NSMutableArray *siblings; // Array of Tasks

// lock for anything that needs locking but is not covered by some other lock
// right now, just comm

@property (nonatomic, strong) NSMutableArray *elfEntryVMemInfo;

// current condition/lock, so it can be notified in case of a signal
//@property (nonatomic, strong) NSCondition *waitingCond;
//@property (nonatomic, strong) NSLock *waitingCondLock;

- (uint8_t)userReadOneBytes:(addr_t)addr;
- (uint32_t)userReadFourBytes:(addr_t)addr;

- (id)initWithParentTask:(Task *)parent;
- (void)start;
- (void)closeCloExecFDs;
- (int)userCopyStringToStack:(addr_t)sp string:(const char *)string;
- (int)userCopyArgsIntoStack:(addr_t)sp args:(id <AnyArgs>)args;
- (int)userWriteString:(addr_t)addr buf:(const char *)buf;
- (int)userStrlen:(addr_t)addr;
- (int)userMemset:(addr_t)addr val:(byte_t)val count:(size_t)len;
- (int)userReadString:(addr_t)addr buf:(char *)buf max:(size_t)max;
- (int)userWrite:(addr_t)addr buf:(char *)buf count:(size_t)count;
- (int)userRead:(addr_t)addr buf:(char *)buf count:(size_t)count;
- (int)userWriteTaskFromBuffer:(addr_t)addr buf:(char *)buf count:(size_t)count;
- (int)userReadTaskIntoBuffer:(addr_t)addr buf:(char *)buf count:(size_t)count;
- (Boolean)isSuperuser;
//- (id)initWithFS:(FileSystem *)fs;
- (int) doExecve:(NSString *)file argv:(ArgArgs *)argv envp:(EnvArgs *)envp;
- (int) elfExec:(FileDescriptor *)fd file:(NSString *)file argv:(ArgArgs *)argv envp:(EnvArgs *)envp;
- (int) formatExec:(FileDescriptor *)fd file:(NSString *)file argv:(ArgArgs *)argv envp:(EnvArgs *)envp;
- (int) shebangExec:(FileDescriptor *)fd file:(NSString *)file argv:(ArgArgs *)argv envp:(EnvArgs *)envp;
- (int) readHeader:(FileDescriptor *)fd header:(struct elf_header *)header;
- (int) readPrgHeaders:(FileDescriptor *)fd header:(struct elf_header)header ph_out:(struct prg_header **)ph_out;
- (int) loadEntry:(FileDescriptor *)fd ph:(struct prg_header)ph bias:(int)bias;

// Signals
- (int) waitForIgnoreSignals:(cond_t *)cond lock:(lock_t *)lock timeout:(struct timespec *)timeout;
- (void) sendSignalTo:(Task *)task signal:(int)signal sigInfo:(SigInfo*)sigInfo;
- (void) deliverSignalTo:(Task *)task signal:(int)signal sigInfo:(SigInfo*)sigInfo;
- (void) recieveSignals;
- (void) recieveSignal:(SigInfo *)si;

@end

//#endif
