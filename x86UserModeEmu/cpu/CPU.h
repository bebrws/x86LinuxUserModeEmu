#import <Foundation/Foundation.h>
#import <pthread.h>
#include <stddef.h>
#include "misc.h"
#include "float80.h"
//#include "emu/memory.h"
 #include "bits.h"


// ------------ Interrupts


// Intel standard interrupts
// Any interrupt not handled specially becomes a SIGSEGV
#define INT_NONE -1
#define INT_DIV 0
#define INT_DEBUG 1
#define INT_NMI 2
#define INT_BREAKPOINT 3
#define INT_OVERFLOW 4
#define INT_BOUND 5
#define INT_UNDEFINED 6
#define INT_FPU 7 // do not try to use the fpu. instead, try to realize the truth: there is no fpu.
#define INT_DOUBLE 8 // interrupt during interrupt, i.e. interruptception
#define INT_GPF 13
#define INT_TIMER 32
#define INT_SYSCALL 0x80



#define NUM_CYCLES_TO_PROCESS_BEFORE_INT_TIMER 100000



#define MODE_DISP0  0
#define MODE_DISP8  1
#define MODE_DISP32 2
#define MODE_REG    3


#define MOD(byte) ((byte & 0b11000000) >> 6)
#define REG(byte) ((byte & 0b00111000) >> 3)
#define RM(byte)  ((byte & 0b00000111) >> 0)

#define SCALE(byte) ((byte & 0b11000000) >> 6)
#define INDEX(byte) ((byte & 0b00111000) >> 3)
#define BASE(byte)  ((byte & 0b00000111) >> 0)


// ----------- ModRM Byte representated as a struct

enum reg32 {
    reg_eax = 0, reg_ecx=1, reg_edx=2, reg_ebx=3, reg_esp=4, reg_ebp=5, reg_esi=6, reg_edi=7, reg_no_reg=8
};


// ----------- The source and destination operands representated as a struct

typedef struct {
    // byte_t mod_rmbyte; // Was considering saving the SIB byte becuase I thought there might be a use case for all the parts below together
    union {
        enum reg32 reg;
        int opcode;
    };
    
    // https://paul.bone.id.au/blog/2018/09/05/x86-addressing/
    // Types are
    // value into or out of a register
    // value into or out of an address in a register + some displacement (displacement could be 0 or not in the opcode)
    // value into or out of an address in a register + register * scale + some displacement (displacement could be 0 or not in the opcode)
    enum {
        modrm_register, modrm_mem, modrm_sib
    } type;
    
    union {
        // enum reg32 rm;
        enum reg32 base;
        int rm_opcode;
    };
    
    enum {
        mode_disp_0,
        mode_disp_8,
        mode_disp_32,
        mode_reg_only
    } mode;
    
    // byte_t sib_byte; // Was considering saving the SIB byte becuase I thought there might be a use case for all the parts below together
    
    int32_t displacement;
    enum reg32 index;
    enum {
        times_1 = 0,
        times_2 = 1,
        times_4 = 2,
    } shift;

} modrm;

// Unnamed enums are a way to set a constat with a variable WITHOUT having that variable take up memory
// or be addressable
// https://stackoverflow.com/questions/7147008/the-usage-of-anonymous-enums
//enum {
//    rm_sib = reg_esp, // 0b100 or 4
//    rm_none = reg_esp, // 0b100 or 4
//    rm_disp32 = reg_ebp, // 0b101 or 5
//};

#define RM_SIB       4 // 0b100 or 4
#define RM_NO_INDEX      4 // 0b100 or 4
#define RM_DISP32    5 // 0b101 or 5


#define ILLEGAL_SIB_INDEX 4 // 0b100 or 4
#define BASE_DISPLACEMENT_ONLY_OR_EBP 5 // 0b101 or 5


// ------------ CPU state


struct cpu_state;

union xmm_reg {
    qword_t qw[2];
    dword_t dw[4];
    // TODO more forms
};

struct cpu_state {
    struct mem *mem;
    struct jit *jit;

    // assumes little endian (as does literally everything)
#define _REG(n) \
    union { \
        dword_t e##n; \
        word_t n; \
    };
#define _REGX(n) \
    union { \
        dword_t e##n##x; \
        word_t n##x; \
        struct { \
            byte_t n##l; \
            byte_t n##h; \
        }; \
    };
    _REGX(a);
    _REGX(b);
    _REGX(c);
    _REGX(d);
    _REG(si);
    _REG(di);
    _REG(bp);
    _REG(sp);
#undef _REGX
#undef _REG

    union xmm_reg xmm[8];

    dword_t eip;

    // flags
    union {
        dword_t eflags;
        struct {
            bits cf_bit:1;
            bits pad1_1:1;
            bits pf:1;
            bits pad2_0:1;
            bits af:1;
            bits pad3_0:1;
            bits zf:1;
            bits sf:1;
            bits tf:1;
            bits if_:1;
            bits df:1;
            bits of_bit:1;
            bits iopl:2;
        };
        // for asm
#define PF_FLAG (1 << 2)
#define AF_FLAG (1 << 4)
#define ZF_FLAG (1 << 6)
#define SF_FLAG (1 << 7)
#define DF_FLAG (1 << 10)
    };
    // please pretend this doesn't exist
    dword_t df_offset;
    // for maximum efficiency these are stored in bytes
    byte_t cf;
    byte_t of;
    // whether the true flag values are in the above struct, or computed from
    // the stored result and operands
    dword_t res, op1, op2;
    union {
        // Any of these flags ending in _res mean to check the state.res variable to determine if the flag is set
        // for ex. zf_res , if 1, is saying to check if res == 0 to determine if the zero flag is set
        struct {
            bits pf_res:1;
            bits zf_res:1;
            bits sf_res:1;
            bits af_ops:1;
        };
        // for asm
#define PF_RES (1 << 0)
#define ZF_RES (1 << 1)
#define SF_RES (1 << 2)
#define AF_OPS (1 << 3)
        byte_t flags_res;
    };

    // fpu
    float80 fp[8];
    
    // The 16-bit x87 FPU status register (see Figure 8-4) indicates the current state of the x87 FPU. The flags in the x87
    // FPU status register include the FPU busy flag, top-of-stack (TOP) pointer, condition code flags, error summary
    // status flag, stack fault flag, and exception flags. The x87 FPU sets the flags in this register to show the results of
    // operations.
    union {
        word_t fsw;
        struct {
            bits ie:1; // invalid operation
            bits de:1; // denormalized operand
            bits ze:1; // divide by zero
            bits oe:1; // overflow
            bits ue:1; // underflow
            bits pe:1; // precision
            bits stf:1; // stack fault
            bits es:1; // exception status
            bits c0:1;
            bits c1:1;
            bits c2:1;
            unsigned top:3;
            bits c3:1;
            bits b:1; // fpu busy (?)
        };
    };
    
    // The 16-bit x87 FPU control word (see Figure 8-6) controls the precision of the x87 FPU and rounding method used.
    // It also contains the x87 FPU floating-point exception mask bits. The control word is cached in the x87 FPU control
    // register. The contents of this register can be loaded with the FLDCW instruction and stored in memory with the
    // FSTCW/FNSTCW instructions.
    union {
        word_t fcw;
        struct {
            bits im:1;
            bits dm:1;
            bits zm:1;
            bits om:1;
            bits um:1;
            bits pm:1;
            bits pad4:2;
            bits pc:2;
            bits rc:2;
            bits y:1;
        };
    };

    // for the page fault handler
    addr_t segfault_addr;
    
    addr_t tls_ptr;
    word_t gs;

    dword_t trapno;
};

// flags
#define ZF (cpu->zf_res ? cpu->res == 0 : cpu->zf)
#define SF (cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf)
#define CF (cpu->cf)
#define OF (cpu->of)
#define PF (cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf)
#define AF (cpu->af_ops ? ((cpu->op1 ^ cpu->op2 ^ cpu->res) >> 4) & 1 : cpu->af)

static inline void collapse_flags(struct cpu_state *cpu) {
    cpu->zf = ZF;
    cpu->sf = SF;
    cpu->pf = PF;
    cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
    cpu->of_bit = cpu->of;
    cpu->cf_bit = cpu->cf;
    cpu->af = AF;
    cpu->af_ops = 0;
    cpu->pad1_1 = 1;
    cpu->pad2_0 = cpu->pad3_0 = 0;
    cpu->if_ = 1;
}

static inline void expand_flags(struct cpu_state *cpu) {
    cpu->of = cpu->of_bit;
    cpu->cf = cpu->cf_bit;
    cpu->zf_res = cpu->sf_res = cpu->pf_res = cpu->af_ops = 0;
}

static inline const char *reg32_name(enum reg32 reg) {
    switch (reg) {
        case reg_eax: return "eax";
        case reg_ecx: return "ecx";
        case reg_edx: return "edx";
        case reg_ebx: return "ebx";
        case reg_esp: return "esp";
        case reg_ebp: return "ebp";
        case reg_esi: return "esi";
        case reg_edi: return "edi";
        case reg_no_reg: return "?";
    }
}


@class Task;

//// Represents the struct in emu/memory.h mem

@class CPU;

// Represent the mem struct from memory.h
//`
@interface CPU : NSObject {
    @public struct cpu_state state;
    
    // DEBUG:
    @public long instructionCount;
}

- (int)step16;
- (int)step;
- (void)collapseFlags;
- (id)initWithTask:(Task *)task;
- (void)start;

// syscalls
- (uint32_t)sysSetThreadArea:(addr_t) u_info_addr;
- (uint32_t)sysSetTIDAddress:(addr_t) tid_addr;
- (uint32_t)sysSetThreadArea:(addr_t) u_info_addr;
- (uint32_t)taskSetThreadArea:(addr_t) u_info_addr;


@property (nonatomic, strong) NSThread *thread;
@property (nonatomic, strong) Task *task;
@property (nonatomic, assign) int interrupt;
@property (nonatomic, assign) uint32_t syscall;


// DEBUG
@property (nonatomic, strong) NSMutableDictionary *ishDebugState;
@property (nonatomic, strong) NSArray *debugJsonStringsLineSeperated;
@property (nonatomic, strong) NSDictionary *parsedData;
@end
