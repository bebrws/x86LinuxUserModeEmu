# x86UserModeEmu - An interpreted, hopefully minimal, dumbed down copy of the [Ish - x86 User Mode Linux Emulator](https://github.com/tbodt/ish)

## What is this?
Hopefully this is going to be a less useful/impressive version of [Ish](https://github.com/tbodt/ish).

## That's dumb, why would you do that?
I have always been interested in Operating Systems, Compilers, Languages, Linux, Emulators, etc etc.. I always thought it would be cool to write an emulator, an OS.. But there really isn't a ton of information about how to go from knowing nothing to writing any one of these things. At least including the intermediate subjects. At some point I guess we really just have to and are expected to read source code.

I read over a bunch of similar projects, learning about how these things were working from a high level. I really delved into JSLinux for example. It was taking a lot of time though and I wasn't very happy with what I thought I was getting out of it. I thought it would be nice to focus my efforts on something that I can actually use and that has unobfuscated code, some documentation, a community, etc.

Ish met these standards. It is also easy to debug and instrument which was helpful.

At some point I realized that Ish is way more than just an emulator. It, in my humble opinion, is really almost like an entire x86 user mode emulator and an entire Linux kernel (running on top of the iOS API) all in one (kind of crossing off 2 items from the list of things I was interested in). It is really amazing that the vast majority of this was written by one person.

Reading though Ish and looking for a place to start.. learning.. doing anything was tough at first. I realized that the JIT was just beyond me at this point (although I got the basic concepts, I wouldn't be able to write my own from what I read). I found that an interpreted version of Ish was still included in the code that didn't seemed to be in use any more and decided I would try to write my own interpreted Ish from this.

I set out with a few goals. Try to document with easily readable code/data structures and use few macros.

An important part was *use a minimal amount of macros*. This probably was stupid because now I have probably 12,000 lines of code or so just in one file (CPU.m) that is 65% duplicate (maybe inline functions or something at a later point..). 

Oh ya, I made the mistake of trying to re write this in a few languages before sticking with Objective C. C definitely makes the most sense but I have learned a lot about both languages from trying to do this.

### Interesting stuff?

Well studying everything I read as I went along I learned that the TLB (Translation Lookaside Buffer) is actually unnecessary. I wonder if Ish could remove it as well? Unless maybe there is some security reason I am missing to keep an emulated TLB in place? 

I can understand why a hardware TLB would be an improvement. A small cache for commonly used addresses makes since versus "walking the page tables" for every address.

I also decided to ditch the classic page table hiearchy of multi layered page directories and page tables to just use a simple array. And it works! I thought this would be great in this case because it also showed how simple the whole page table architecture really can be. Or maybe the real point of it. It simply is a way to let humans break up memory in constantly sized chunks and quickly retrieve the location (and attributes) of that memory chunk for any given address.

At first I thought that the Page Directories and Page Tables served some greater purpose. Maybe there were important attributes related to memory protection or something that was housed in these structures? But I realized all the different page table implementations all really are trying to accomplish the same thing. Find the same page page table entry for any address.

The easiest way to do this is go about picking a page size. If you do this in powers of 2 its is great because you can simply mask out the offset bits from an address and then you have your page table entry key. In 32 bit environments 4096 bytes is a common page table size. 0 -> 4095 can be counted using the first 12 bits. Therefore we can find any offset into a page by anding an address by 0b111111111111 (or 0xFFF) 
    
    uint32_t offset = addr & 0b111111111111; 

and we can find the 32 bit page table entry key by anding the address by 0xFFFFFFFFFFFFF000.

    uint32_t page = addr & 0xFFFFFFFFFFFFF000; 

Using a page table is simple and easy.. my address lookup times are also fast. To lookup a page I just cut off the first 12 bits and index into my PageTableEntry array to find the correct page table entry. And again, no need to hassle with state of the TLB which is nice and saves some time (and I would love to find out if it was much of a speed improvement).

This is all pretty simple stuff but it felt good realizing that these data structures were not as complicated as I had once assumed them to be.

### Readability

There is really only a handful of opcodes I broke down and used macros for. And that could be helpful for learning macros for someone anyway if they were having a hard time finding a project they could read through easily.

I have also messed with Ish enough that I was able to output a few JSON files with the CPU state for each process for every instruction/tick. (I might just push up a branch with the build of Ish I have been using to debug this project with at some point).

I have actually verified that "my" implementation (in quotes because I had been referencing Ish while working on this, although minimally I hoped, and I cannot really call anything mine here) executes correctly up until the first syscall. That is something like 12,000 operations.

I have made a bunch of other small changes as well, mostly just to challenge myself so that I didn't just copy and paste code from Ish over into a new project. My goal was to be able to describe what any particular line of code did, not to be able to write this on my own necessarily. I also thought it would be nice if I could document the code to a ridiculous standard so that it may provide useful for anyone else who was having a hard time finding material.

Some other interesting code would be in the setup for any instruction:

    [self readByteIncIP:&modRMByte];
    mrm = [self decodeModRMByte:modRMByte];
    regPtr = [self getRegPointer:mrm.reg opSize:32];
    if (mrm.type == modrm_register) {
        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
    } else {
        addr = [self getModRMAddress:mrm opSize:32];
        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
            return 13;
        }
        memcpy(&rmReadValue, rmReadPtr, sizeof(uint32_t));
        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
    }
    
    regPtr = [self getRegPointer:mrm.reg opSize:32];

and:

    [self readFourBytesIncIP:&imm32];


I thought this turned out be fairly readable, even with the hacks I had to add in to make this block re usable in all situations (the hack I am referring to is the use of memcpy which I will explain).

Many op codes operate on some combination of a register, whatever the "MODRM" byte says to operate on, or an immediate value.

That first block of code is executed after the first opcode byte has been read and we have figured out which opcode we are parsing bytes for. Then that code above starts out by reading in the MODRM byte. This byte will say whether or not it will be effecting an address or a register. This is why there is an if statement there.

The nice part about this code is that regardless of the branch of logic we take we end up with 2 pointers rmWritePtr and rmReadPtr. Both of which can be used regardless of whether the MODRM byte decided that this was a register operation or a memory operation. This way the code actually performing the operations doesn't need to check the MODRM byte or worry about this difference. When writing the code for a MODRM operation I can just use 

    \*(uint32_t \*)rmWritePtr 

whenever I need to set a r/m (MODRM) value and 

    \*(uint32_t \*)rmReadPtr 

whenever I need to read a r/m (MODRM) value.

For example if I had an operation like:

    ADD r16/32 r/m16/32  

This would be asking me to add the value from the register specified in the opcode with with MODRM value and store it in the MODRM location.

I could get the (dumbed down) result with:

    \*(uint32_t \*)rmWritePtr = (uint32_t)rmReadValue + \*(uint32_t \*)regPtr

I thought this would lead to very readable opcodes.

And I showed above how easy it is to read a few bytes from eip to grab an immediate already.

I added the memcpy in there because I was getting errors about alignment. This meant that the MODRM addresses were resulting in pointers whose addresses were not 4 byte aligned (divisible evenly by 4) for uint32_t's for example. However, now that I think about it, that may and most likely was a bug so hopefully I can remove that ugly code and get it back to:

    [self readByteIncIP:&modRMByte];
    mrm = [self decodeModRMByte:modRMByte];
    regPtr = [self getRegPointer:mrm.reg opSize:32];
    if (mrm.type == modrm_register) {
        rmWritePtr = rmReadPtr = [self getRegPointer:mrm.base opSize:32];
        rmReadValue = *(uint32_t *)rmReadPtr;
    } else {
        addr = [self getModRMAddress:mrm opSize:32];
        if (!(rmReadPtr = [self.task.mem getPointer:addr type:MEM_READ])) {
            return 13;
        }
        rmReadValue = *(uint32_t *)rmReadPtr;
        rmWritePtr = [self.task.mem getPointer:addr type:MEM_WRITE];
    }
    
    regPtr = [self getRegPointer:mrm.reg opSize:8];

or just remove the rmReadValue altogether which I had originally and always use \*(uint32_t \*)rmReadPtr in place of needing the line/s:

    rmReadValue = *(uint32_t *)rmReadPtr;

This is probably correct and I am now pretty sure a previous operation had just resulted in an address being off by a few bytes resulting in this mis alignment and leading to the need for memcpy.

### Finishing up

The goal would be to get a terminal up if time allows. I would prefer not to hurry through the syscall/Linux kernel aspects of Ish. (I really want to play around with some different virtual memory ideas and to see if removing things like the TLB helps much). For that reason the syscalls may just end up copied over from Ish directly for now but I hope I have time later to learn more about how they work.

The x86 emulation part is running up until the point where the first syscall is executed. This was verified by comparing against the state of Ish. However I am sure there are still bugs in there, especially in the 16 bit version of the opcodes. These have had very little coverage.

The majority of the rest of the work to getting a terminal up (when I would be happy with this) probably lays in finishing off all the syscalls.


### Thanks Ish

Ish is an amazing project and I am glad that the author has open sourced it. I have learned a lot from reading through it and creating my broken clone. Thank you
