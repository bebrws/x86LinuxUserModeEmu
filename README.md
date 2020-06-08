# x86UserModeEmu - An interpreted, hopefully minimal, dumbed down [Ish - x86 User Mode Linux Emulator](https://github.com/tbodt/ish)

I have always been interested in Operating Systems, Compilers, Languages, Linux, Emulators, etc etc.. But there really isn't a ton of information about how to go from knowing nothing to writing any one of these things. At least including the intermediate subjects. At some point, I guess we really just have to and are expected to read source code.

I read over a bunch of similar projects, learning about how these things were working from a high level. I really delved into JSLinux for example. It was taking a lot of time though and I wasn't very happy with what I thought I was getting out of it. I thought it would be nice to focus my efforts on something that I can actually use and that has unobfuscated code, some documentation, etc.

Ish met these standards. It is also easy to debug and instrument which was helpful.

At some point I realized that Ish is way more than just an emulator. It, in my humble opinion, is really almost like an entire x86 user mode emulator and an entire Linux kernel (running on top of the iOS API) all in one (kind of crossing off 2 items from the list of things I was interested in). It is really amazing that the vast majority of this was written by one person.

Reading though Ish and looking for a place to start.. learning.. doing anything was tough at first. I realized that the JIT was just beyond me at this point (although I got the basic concepts, I wouldn't be able to write my own from what I read). I found that an interpreted version of Ish was still included in the code that didn't seemed to be in use any more and decided I would try to write my own interpreted Ish from this.

I set out with a few goals. To understand how this worked, the different data structures/algorithms in use, to comment in places I felt might be useful and also to use few macros.

An important part was *use a minimal amount of macros*. This probably was stupid because now I have probably 12,000 lines of code or so just in one file (CPU.m) that is 65% duplicate (maybe inline functions or something at a later point..).

### Interesting stuff?

Studying everything I read as I went along I learned that the TLB (Translation Lookaside Buffer) could actually be unnecessary. While a hardware TLB, dedicated hardware that is a small cache for commonly used addresses and meta data, makes sense to me I do not think it is necessary to emulate in this case.. I am hoping to find out if there are any speed improvements from removing it. 

I also decided to ditch the classic multi layered page table hierarchy at this point to just use a simple array. I thought this would be great in this case because it showed me how simple the whole page table architecture really can be. That it is just a way to let humans break up memory into consistently sized pieces, re-usably re-locating them in different processes' virtual address space. It also is used to add meta data to these chunks of "real" memory so that when a process needs to perform a specific operation different protections and optimizations (like copy on write) can be performed.

To retrieve a "real"/final physical address, the most significant bits are always used to locate the page table entry. This leads to a physical memory address with the least significant bits being an offset into this "page" of memory.

In 32 bit environments 4096 bytes is a common page table size. 0 -> 4095 can be counted using the first 12 bits. Therefore we can find any offset into a page by masking an address by 0b111111111111 (or 0xFFF) 
    
    uint32_t offset = addr & 0b111111111111; 

and we can find the 32 bit page table entry key by anding the address by 0xFFFFFFFFFFFFF000.

    uint32_t page = addr & 0xFFFFFFFFFFFFF000; 

With this simple array as a page table you could just cut off the first 12 bits to find the correct page table entry. And again, no need to hassle with state of the TLB which is nice and saves some time (and I would love to find out if it was much of a speed improvement).

This is all probably pretty simple stuff but it felt good realizing that these data structures did not need to be as complicated as I had once assumed them to be.

### Readability

There is really only a handful of opcodes I used macros for. And that could be helpful for learning macros for someone anyway if they were having a hard time finding a project they could read through easily.

I have also messed with Ish enough that I was able to output a few JSON files with the CPU state for each process for every instruction/tick. (I might just push up a branch with the build of Ish I have been using to debug this project with at some point).

I have actually verified that "my" implementation (in quotes because I had been referencing Ish while working on this, although minimally I hoped) executes correctly up until the first syscall. That is something like 12,000 operations.

I have made a bunch of other small changes as well, mostly just to challenge myself so that I didn't just copy and paste code from Ish over into a new project. My goal was to be able to describe what any particular line of code did, not to be able to write this on my own necessarily. I also thought it would be nice if I could add comments throughout. Particularly in places I thought might be useful, that required me to search for more information, or where I just felt like adding comments.

Here is some code that may or may not end up with comments. More importantly I thought it was easy to read and helped with the MODRM abstraction by removing the need to consider whether or not the the MODRM byte was referencing memory or a register. It shows the use of what most operations involve. Some combination of a register, whatever the "MODRM" byte says to operate on, and an immediate value.

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

and this dangling code block which can sometimes be found after the code above:

    [self readFourBytesIncIP:&imm32];

That first block of code is executed after the first opcode byte has been read and we have figured out which opcode we are parsing bytes for. Then that code above starts out by reading in the MODRM byte. This byte will specify the register or the address of the data that will be read or written to (in some cases this address is the value to be used itself which is seen in the LEA operation).

The nice part about this code is that regardless of the branch of logic we take we end up with 2 pointers rmWritePtr and rmReadPtr (this is disregarding the LEA case mentioned above, which is covered by the line assigning the addr variable). Both of which can be used regardless of whether the MODRM byte decided that this was a register operation or a memory operation. This way the code actually performing the operations doesn't need to check the MODRM byte or worry about this difference. When writing the code for a MODRM operation I can just use:

    \*(uint32_t \*)rmWritePtr 

whenever I need to set a R/M OR MODRM value and 

    \*(uint32_t \*)rmReadPtr 

whenever I need to read a r/m value.

For example if I had an operation like:

    ADD r16/32 r/m16/32  

This would be asking me to add the value from the register specified in the opcode with with MODRM value and store it in the MODRM location.

I could get the (dumbed down) result with:

    \*(uint32_t \*)rmWritePtr = (uint32_t)rmReadValue + \*(uint32_t \*)regPtr

I thought this would lead to very readable opcodes.

And I showed above how easy it is to read a few bytes from eip to grab an immediate value already.

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

This is probably correct and I am now pretty sure a previous operation had just resulted in an address being off by a few bytes resulting in this mis-alignment and leading to the need for memcpy.

### Finishing up

The goal would be to get a terminal up if time allows. I would prefer not to hurry through the syscall/Linux kernel aspects of Ish. (I really want to play around with some different virtual memory ideas and to see if removing things like the TLB helps much). For that reason the syscalls may just end up copied over from Ish directly for now but I hope I have time later to learn more about how they work.

The x86 emulation part is running up until the point where the first syscall is executed. This was verified by comparing against the state of Ish. However I am sure there are still bugs in there, especially in the 16 bit version of the opcodes. These have had very little coverage.

The majority of the rest of the work to getting a terminal up (when I would be happy with this) probably lays in finishing off all the syscalls.


### Thanks Ish

Ish is an amazing project and I am glad that the author has open sourced it. I have learned a lot from reading through it and creating my broken clone. Thank you

### License?

I believe that Ish is licensed GNU GPL Version 3 so I will include a copy of that license here in LICENSE.ISH. There are a few files here that are even direct copies from Ish such as:

    time.h
    timer.c
    timer.h
    cpuid.h
    float80.c - added some code for debugging
    float80.h

Note: that these files might be slightly modified, refer to the original repository.