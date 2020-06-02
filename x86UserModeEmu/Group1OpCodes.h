
#define GRP1_T(type, sz) type##sz##_t
#define GP1UINT(sz) GRP1_T(uint, sz)
#define GP1INT(sz)  GRP1_T(int, sz)

#define IMMV_CALLEE(size) imm ## size
#define IMMV(size) IMMV_CALLEE(size)

#define TEMPV_CALLEE(size) temp ## size
#define TEMPV(size) TEMPV_CALLEE(size)

// Operands are in groups
// http://www.mlsite.net/8086/#tbl_ext

//int asdf() {
#ifdef BDEBUG
CLog(@"Handling Group1 sizes: rm %d imm %d\n", RM_SZ, IMM_SZ);
#endif

if ([self readByteIncIP:&modRMByte]) { SEGFAULT }
mrm = [self decodeModRMByte:modRMByte];
if ([self IMM_READ_METHOD:&IMMV(IMM_SZ)]) { SEGFAULT }

if (mrm.type == modrm_register) {
    rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:RM_SZ];
    if (!rmReadPtr) {
        return 13;
    }
    memcpy(&rmReadValue, rmReadPtr, sizeof(GP1UINT(RM_SZ)));
//    CLog(@" Reg %@ ", [CPU getRegisterString:mrm.base]);
} else {
    addr_t modrmAddress = [self getModRMAddress:mrm opSize:RM_SZ];
//    CLog(@" Addr 0x%x ", modrmAddress);
    rmReadPtr  = [self.task.mem getPointer:modrmAddress type:MEM_READ];
    if (!rmReadPtr) {
        return 13;
    }
    memcpy(&rmReadValue, rmReadPtr, sizeof(GP1UINT(RM_SZ)));
    // when modrm.reg == 0x7 this is a CMP opcode and the modrm byte is not used to write to just read from
    if (mrm.reg != 7) {
        rmWritePtr = [self.task.mem getPointer:modrmAddress type:MEM_WRITE];
    }
}

IMMV(RM_SZ) = (GP1INT(RM_SZ))(GP1UINT(RM_SZ))((GP1INT(IMM_SZ))IMMV(IMM_SZ));

//imm32 = (GP1INT(RM_SZ))(GP1UINT(RM_SZ))((GP1INT(IMM_SZ))IMMV(IMM_SZ));

switch (mrm.reg) {
        // TODO Implement all logic under http://ref.x86asm.net/coder32.html#x83
    case 0x0:
//        CLog(@"ADD rm %d imm %d\n", RM_SZ, IMM_SZ);
        // ADD
        
        // This function will return true if an overflow was detected while carrying out the add
        // There is a list of similar functions
        // https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html
        // that perform simple arithmetic operations together with checking whether the operations overflowed.
    
        // self->state.cf = __builtin_add_overflow((GP1UINT(RM_SZ))rmReadValue, (GP1UINT(IMM_SZ))IMMV(RM_SZ), (GP1UINT(RM_SZ) *)rmWritePtr);
        self->state.cf = __builtin_add_overflow((GP1UINT(RM_SZ))rmReadValue, (uint32_t)imm32, (GP1UINT(RM_SZ) *)rmWritePtr);
        self->state.res = *(GP1INT(RM_SZ) *)rmWritePtr;
        // self->state.of = __builtin_add_overflow(*((GP1INT(RM_SZ) *) rmReadPtr), (GP1INT(IMM_SZ)) IMMV(RM_SZ), &TEMPV(RM_SZ));
        self->state.of = __builtin_add_overflow(*((GP1INT(RM_SZ) *) rmReadPtr), (int32_t)imm32, &TEMPV(RM_SZ));
        
        // set the auxillary flag
        self->state.af_ops = 1;
        // set zero flag, sign flag, parity flag
        self->state.zf_res = 1;
        self->state.sf_res = 1;
        self->state.pf_res = 1;
        break;
    case 0x1:
        // OR
        CLog(@"OR rm(%d):%x imm(%d):%x\n", RM_SZ, *((GP1UINT(RM_SZ) *)rmReadPtr), IMM_SZ, (uint32_t)imm32);
        // self->state.res = *((GP1UINT(RM_SZ) *)rmWritePtr) = *((GP1UINT(RM_SZ) *)rmReadPtr) | (GP1UINT(IMM_SZ))IMMV(RM_SZ);
        self->state.res = *((GP1UINT(RM_SZ) *)rmWritePtr) = *((GP1UINT(RM_SZ) *)rmReadPtr) | (uint32_t)imm32;
        
        self->state.cf = self->state.of = self->state.af = self->state.af_ops = 0;
        self->state.zf_res = self->state.sf_res = self->state.pf_res = 1;
        break;
    case 0x2:
        // ADC
//        CLog(@"ADC rm %x imm %x\n", RM_SZ, IMM_SZ);
        // This is just the ADD instruction but with the carry flag added onto the immediate value
        // if (*((dword_t *)rmReadPtr) + imm > UINT8_MAX)
        // *((dword_t *)rmWritePtr) = *((dword_t *)rmReadPtr) + imm;
        
        // This function will return true if an overflow was detected while carrying out the add
        // There is a list of similar functions
        // https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html
        // that perform simple arithmetic operations together with checking whether the operations overflowed.
        // TODO: Are these | statements necessary for setting overflow and carry flags? Wont the __builtin_add_overflow
        // TODO: functions set the flags correctly?
        // self->state.of = __builtin_add_overflow((GP1INT(RM_SZ))rmReadValue, (GP1INT(IMM_SZ))IMMV(RM_SZ) + self->state.cf, (GP1INT(RM_SZ) *)rmWritePtr);
        self->state.of = __builtin_add_overflow((GP1INT(RM_SZ))rmReadValue, (int32_t)imm32 + self->state.cf, (GP1INT(RM_SZ) *)rmWritePtr);
        self->state.res = *((GP1INT(RM_SZ) *)rmWritePtr);
        //             |=    carry flag AND      imm == 0b01111111111111111111111111111111 or 0x7fffffff
        self->state.of |= (self->state.cf && (uint32_t)imm32 == ((uint8_t)-1) / 2);
        //self->state.of |= (self->state.cf && ((GP1UINT(IMM_SZ))IMMV(RM_SZ)) == ((uint8_t)-1) / 2);
        // self->state.cf = __builtin_add_overflow((GP1UINT(RM_SZ))rmReadValue, (GP1UINT(IMM_SZ))IMMV(RM_SZ) + self->state.cf, &TEMPV(RM_SZ));
        self->state.cf = __builtin_add_overflow((GP1UINT(RM_SZ))rmReadValue, (uint32_t)imm32 + self->state.cf, &TEMPV(RM_SZ));
        //             |=    carry flag AND      imm == 0b11111111111111111111111111111111 or 0xffffffff
        //self->state.cf |= (self->state.cf && ((GP1UINT(IMM_SZ))IMMV(RM_SZ)) == (uint8_t)-1);
        self->state.cf |= (self->state.cf && (uint32_t)imm32 == (uint8_t)-1);
        
        
        
        // set the auxillary flag
        self->state.af_ops = 1;
        // set zero flag, sign flag, parity flag
        self->state.zf_res = 1;
        self->state.sf_res = 1;
        self->state.pf_res = 1;
        break;
    case 0x3:
        // SBB
//        CLog(@"SBB rm %x imm %x\n", RM_SZ, IMM_SZ);
        // Adds the source operand (second operand) and the carry (CF) flag, and subtracts the result
        // from the destination operand (first operand).
        // Similar to the ADC but the operation is substract the source op + carry flag value
        
        // This function will return true if an overflow was detected while carrying out the add
        // There is a list of similar functions
        // https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html
        // that perform simple arithmetic operations together with checking whether the operations overflowed.
        // TODO: Are these | statements necessary for setting overflow and carry flags? Wont the __builtin_add_overflow
        // TODO: functions set the flags correctly?
        // self->state.of = __builtin_sub_overflow((GP1INT(RM_SZ))rmReadValue, (GP1INT(IMM_SZ))IMMV(RM_SZ) + self->state.cf, (GP1INT(RM_SZ) *)rmWritePtr);
        self->state.of = __builtin_sub_overflow((GP1INT(RM_SZ))rmReadValue, (int32_t)imm32 + self->state.cf, (GP1INT(RM_SZ) *)rmWritePtr);
        self->state.res = *((GP1INT(RM_SZ) *)rmWritePtr);
        //             |=    carry flag AND      imm == 0b01111111111111111111111111111111 or 0x7fffffff
        // self->state.of |= (self->state.cf && ((GP1UINT(IMM_SZ))IMMV(RM_SZ)) == ((uint8_t)-1) / 2);
        self->state.of |= (self->state.cf && (uint32_t)imm32 == ((uint8_t)-1) / 2);
        // self->state.cf = __builtin_sub_overflow((GP1UINT(RM_SZ))rmReadValue, (GP1UINT(IMM_SZ))IMMV(RM_SZ) + self->state.cf, &TEMPV(RM_SZ));
        self->state.cf = __builtin_sub_overflow((GP1UINT(RM_SZ))rmReadValue, (uint32_t)imm32 + self->state.cf, &TEMPV(RM_SZ));
        //             |=    carry flag AND      imm == 0b11111111111111111111111111111111 or 0xffffffff
        // self->state.cf |= (self->state.cf && ((GP1UINT(IMM_SZ))IMMV(RM_SZ)) == (uint8_t)-1);
        self->state.cf |= (self->state.cf && (uint32_t)imm32 ==-1);
        // TODO: This line needed?
        
        
        
        // set the auxillary flag
        self->state.af_ops = 1;
        // set zero flag, sign flag, parity flag
        self->state.zf_res = 1;
        self->state.sf_res = 1;
        self->state.pf_res = 1;
        break;
    case 0x4:
        // AND
//        CLog(@"AND rm %x imm %x\n", RM_SZ, IMM_SZ);
        // self->state.res = *((GP1UINT(RM_SZ) *)rmWritePtr) = *((GP1UINT(RM_SZ) *)rmReadPtr) & (GP1UINT(RM_SZ))IMMV(RM_SZ);
        self->state.res = *((GP1UINT(RM_SZ) *)rmWritePtr) = *((GP1UINT(RM_SZ) *)rmReadPtr) & (uint32_t)imm32;
        // Clears the carry flag, overflow flag, auxillary flag
        self->state.cf = 0;
        self->state.of = 0;
        self->state.af = 0;
        self->state.af_ops = 0;
        // set zero flag, sign flag, parity flag
        self->state.zf_res = 1;
        self->state.sf_res = 1;
        self->state.pf_res = 1;
        break;
    case 0x5:
        // SUB
//        CLog(@"SUB rm %x imm %x\n", RM_SZ, IMM_SZ);
        // Subtracts the second operand (source operand) from the first operand (destination operand)
        // and stores the result in the destination operand
        
        // This function will return true if an overflow was detected while carrying out the add
        // There is a list of similar functions
        // https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html
        // that perform simple arithmetic operations together with checking whether the operations overflowed.
        // TODO: Are these | statements necessary for setting overflow and carry flags? Wont the __builtin_add_overflow
        // TODO: functions set the flags correctly?
        // self->state.of = __builtin_sub_overflow((GP1INT(RM_SZ))rmReadValue, (GP1INT(IMM_SZ))IMMV(RM_SZ), (GP1INT(RM_SZ) *)rmWritePtr);
        self->state.of = __builtin_sub_overflow((GP1INT(RM_SZ))rmReadValue, (int32_t)imm32, (GP1INT(RM_SZ) *)rmWritePtr);
        self->state.res = *((GP1INT(RM_SZ) *)rmWritePtr);
        // self->state.cf = __builtin_sub_overflow((GP1UINT(RM_SZ))rmReadValue, (GP1UINT(IMM_SZ))IMMV(RM_SZ), &TEMPV(RM_SZ));
        self->state.cf = __builtin_sub_overflow((GP1UINT(RM_SZ))rmReadValue, (uint32_t)imm32, &TEMPV(RM_SZ));
        
        // set the auxillary flag
        self->state.af_ops = 1;
        // set zero flag, sign flag, parity flag
        self->state.zf_res = 1;
        self->state.sf_res = 1;
        self->state.pf_res = 1;
        break;
    case 0x6:
        // XOR
//        CLog(@"XOR rm %x imm %x\n", RM_SZ, IMM_SZ);
        // self->state.res = *((GP1UINT(RM_SZ) *)rmWritePtr) = *((GP1UINT(RM_SZ) *)rmReadPtr) ^ (GP1UINT(IMM_SZ))IMMV(RM_SZ);
        self->state.res = *((GP1UINT(RM_SZ) *)rmWritePtr) = *((GP1UINT(RM_SZ) *)rmReadPtr) ^ (uint32_t)imm32;
        
        // Clears the carry flag, overflow flag, auxillary flag
        self->state.cf = 0;
        self->state.of = 0;
        self->state.af = 0;
        self->state.af_ops = 0;
        // set zero flag, sign flag, parity flag
        self->state.zf_res = 1;
        self->state.sf_res = 1;
        self->state.pf_res = 1;
        break;
    case 0x7:
        // CMP
//        CLog(@"CMP rm %x imm %x\n", RM_SZ, IMM_SZ);
        // Identical to the SUB operation but does not effect operands
        // and stores the result in the destination operand
        // This function will return true if an overflow was detected while carrying out the add
        // There is a list of similar functions
        // https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html
        // that perform simple arithmetic operations together with checking whether the operations overflowed.
        // TODO: Are these | statements necessary for setting overflow and carry flags? Wont the __builtin_add_overflow
        // TODO: functions set the flags correctly?
        self->state.cf = __builtin_sub_overflow((GP1UINT(RM_SZ))rmReadValue, (GP1UINT(IMM_SZ))IMMV(RM_SZ), (GP1UINT(32) *)&self->state.res);
        // self->state.cf = __builtin_sub_overflow((GP1UINT(RM_SZ))rmReadValue, (uint32_t)imm32, (GP1UINT(32) *)&self->state.res);
        self->state.of = __builtin_sub_overflow((GP1INT(RM_SZ))rmReadValue, (GP1INT(IMM_SZ))IMMV(RM_SZ), (GP1INT(32) *)&self->state.res);
        // self->state.of = __builtin_sub_overflow((GP1INT(RM_SZ))rmReadValue, (int32_t)imm32, (GP1INT(32) *)&self->state.res);
        
        // set the auxillary flag
        self->state.af_ops = 1;
        // set zero flag, sign flag, parity flag
        self->state.zf_res = 1;
        self->state.sf_res = 1;
        self->state.pf_res = 1;
        break;
    default:
        UNDEFINED_OP
        break;
}



#undef IMM_READ_METHOD
#undef MODRM_VAR
#undef IMM_SZ
