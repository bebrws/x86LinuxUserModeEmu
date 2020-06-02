# TODO




offsetof(struct cpu_state, ecx)
24 or 0x18









Error with path 
    "T/sbin/init"
    







Def replace my JSON DB with https://realm.io/docs/objc/latest
    U can do all kinds of fancy queries
    Better persistence / tooling
    Tested
    


??? For debugging and introspection -- Create a context class
    Has a dict where any key value can be
        Has setter and getter by key or a setter getter for each special context no dict?
    Usecases are storing things like current filename being read by the task
    Error code - This is how I could return a nil FileDescriptor and then look up the error code later if needed
    Storing current opcode being read and other things I may want to log or debug on in other unrelated methods
    ? How to make thread safe for virtual thread ?
    

WAY TO DEBUG - Use something like Aspects - a swizzling /monkey patching tool
    https://github.com/steipete/Aspects
    
    Then have a method I call from init in some static debug class that hooks all the methods I want to change for this debugging run
    



TODO : replace char with : typedef uint8_t byte_t;
    to show I am working with a single byte at a time regardless of cpu

I AM SKIPPING THE TLB - unnecessary

Could have just kept all FS work in one Class and just done FileDescriptors using inheritance..



The FileSystem OPs are all mostly Fake -> Real operations
The FileDescriptor OPs are all mostly just Real operations with the exception of the Fake FileDescriptor operations all being Real except for the readdir function
        There are NO fake fd_ops functions actually EXCEPT readdir




## Possible issues found in ish

case 0x6a:
__use(0);
imm = ({ uint8_t val; if (!tlb_read(tlb, cpu->eip, &val, 8/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->eip; return 13; } val; });
cpu->eip += 8 / 8;
__use(0, (long long)imm);
imm = (int8_t)(uint8_t)imm;
({ uint32_t _val = ((uint32_t) imm); if (!tlb_write(tlb, cpu->esp - 32/8, &_val, 32/8)) { cpu->eip = saved_ip; cpu->segfault_addr = cpu->esp - 32/8; return 13; } });
cpu->esp -= 32 / 8;

IS this reading an 8 bit number but writing a 32 bit value to the stack?
op is 
6A            01+                    PUSH    imm8    
