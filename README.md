# x86UserModeEmu - An interpreted, hopefully minimal, dumbed down copy of the [Ish - x86 User Mode Linux Emulator](https://github.com/tbodt/ish)

## What is this?
Hopefully this is going to be a less useful/impressive version of [Ish](https://github.com/tbodt/ish).

## That's dumb, why would you do that?
I have always been interested in Operating Systems, Compilers, Languages, Linux, Emulators, etc etc.. I always thought it would be cool to write an emulator, an OS.. But there really isn't a ton of information about how to go from knowing nothing to writing any one of these things. At least including the intermediate subjects. At some point I guess we really just have to and are expected to read source code.

I read over a bunch of similar projects, learning about how these things were working from a high level. I really delved into JSLinux for example. It was taking a lot of time though and I wasn't very happy with what I thought I was getting out of it. I thought it would be nice to focus my efforts on something that I can actually use and that has unobfuscated code, some documentation, a community, etc.

Ish met these standards. It is also easy to debug and instrument which was helpful.

At some point I realized that Ish is way more than just an emulator. It, in my humble opinion, is really almost like an entire x86 user mode emulator and an entire Linux Kernel (running on top of the iOS API) all in one (kind of crossing off 2 items from the list of things I was interested in). It is really amazing that the vast majority of this was written by one person.

Reading though Ish and looking for a place to start.. learning.. doing anything from was tough at first. I realized that the Jit was just beyond me at this point (although I got the basic concepts, I wouldn't be able to write my own from what I read). I found that an interpreted version of Ish was still included in the code that didn't seemed to be in use any more and decided I would try to write my own interpreted Ish from this.

I set out with a few goals. Try to document with easily readable code/data structures and use few macros.

An important part was *use a minimal amount of macros*. This probably was stupid because now I have probably 12,000 lines of code or so just in one file (CPU.m) that is 65% duplicate (maybe inline functions or something at a later point..). 

Oh ya, I made the mistake of trying to re write this in a few languages before sticking with Objective C. C definitely makes the most sense but I have learned a lot about both languages from trying to do this.

## Anything interesting here?

Well studying everything I read as I went along I learned that the TLB (Translation Lookaside Buffer) is actually unnecessary. I wonder if Ish could remove it as well?? Unless maybe there is some security reason I am missing to keep an emulated TLB in place? 

I can understand why a hardware TLB would be an improvement. A small cache for commonly used addresses makes since versus "walking the page tables" for every address.

I also decided to ditch the classic page table hiearchy of multi layered page directories and page tables to just use a simple 1D array. And it works!

This way my address lookup times are fast. To lookup a page I just cut off the first 12 bits and index into my PageTableEntry array to find the correct page table entry. No need to hassle with state of the TLB which is nice and save some time (and I would love to find out if it was much of a speed improvement).

## Anything else?

There is really only a handful of opcodes I broke down and used Macros for. And that could be helpful for learning macros for someone anyway if they were having a hard time finding a project they could read through easily.

I have also messed with Ish enough that I was able to output a few JSON files with the CPU state for each process for every instruction/tick. (I might just push up a branch with the build of Ish I have been using to debug this project with at some point).

I have actually verified that "my" implementation (in quotes because I had been referencing Ish while working on this, although minimally I hoped, and I cannot really call anything mine here) executes correctly up until the first syscall. That is something like 12,000 operations.


I have made a bunch of other small changes as well, mostly just to challenge myself so that I didn't just copy and paste code from Ish over into a new project. My goal was to be able to describe what any particular line of code did, not to be able to write this on my own necessarily. I also thought it would be nice if I could document the code to a ridiculous standard so that it may provide useful for anyone else who was having a hard time finding material.


## What's going on with it now?

I am trying not to give up now that I am relatively close to getting a terminal up.. I am close only if I try and just hurry through the syscall/Linux kernel aspects of Ish. (I really want to play around with some different virtual memory ideas and to see if removing things like the TLB helps much). For that reason the syscalls may just end up copied over from Ish directly for now but I hope I have time later to learn more about how they work.

In summary the x86 emulation part is done up until the point where all opcodes needed to get to the first syscall execute correctly and are verified by comparing against the state of Ish. However I am sure there are still bugs in there, especially in the 16 bit version of the opcodes. These have had very little coverage.

The majority of the rest of the work to getting a terminal up (when I will be happy with this) probably lays in finishing off all the syscalls.

## Thanks Ish

Ish is an amazing project and I am glad that the author has open sourced it. I have learned a lot from reading through it and creating my broken clone. Thank you