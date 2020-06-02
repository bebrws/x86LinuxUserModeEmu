#import <Foundation/Foundation.h>
#import <stddef.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

// For random
#ifdef __APPLE__
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonRandom.h>
#else
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/random.h>
#endif

#import "NSArray+Blocks.h"

#import "misc.h"
#import "Pid.h"
#import "Task.h"
#import "Globals.h"
#import "FileDescriptor.h"
#import "FileDescriptorTable.h"
#import "FileDescriptorAndError.h"
#import "errno.h"
#import "FileSystem.h"
#import "PageTableEntry.h"
#import "Mount.h"
#import "ArgArgs.h"
#import "EnvArgs.h"
#import "CPU.h"
#import "dev.h"
#import "Memory.h"
#import "SigInfo.h"
#import "SigHandler.h"
#import "SigQueue.h"
#import "ThreadGroup.h"
#import "SigAction.h"
#import "MountLookup.h"

#include "elf.h"
#include "log.h"
#import "vdso.h"
#import "debug.h"
#import "misc.h"


@class ThreadGroup;

static void timeval_add(struct timeval_ *dst, struct timeval_ *src) {
    dst->sec += src->sec;
    dst->usec += src->usec;
    if (dst->usec >= 1000000) {
        dst->usec -= 1000000;
        dst->sec++;
    }
}

void rusage_add(struct rusage_ *dst, struct rusage_ *src) {
    timeval_add(&dst->utime, &src->utime);
    timeval_add(&dst->stime, &src->stime);
}


int get_random(char *buf, size_t len)
{
#ifdef __APPLE__
    return CCRandomGenerateBytes(buf, len) != kCCSuccess;
#else
    return syscall(SYS_getrandom, buf, len, 0) < 0;
#endif
}

@implementation Task

// ------------------------------------------ Memory helpers

- (int)userStrlen:(addr_t)addr {
    size_t i = 0;
    char c;
    do {
        if ([self userRead:(addr + i) buf:&c count:sizeof(c)]) return -1;
        i++;
    } while (c != '\0');
    return i - 1;
}

- (int)userMemset:(addr_t)addr val:(byte_t)val count:(size_t)count {
    addr_t p = addr;
    while (p < addr + count) {
        // Write a page at a time
        addr_t chunk_end = (PAGE(p) + 1) << PAGE_BITS;
        if (chunk_end > addr + count) {
            chunk_end = addr + count;
        }
        // The reason we need to know if this is a read or write is to determine if we need
        // to duplicate the page because it could be a Copy On Write page being shared with
        // other processes. On write we create a new copy of the page to write to, mapping that
        // new page copy's physical address into the page tables for the current process making the
        // write
        char *ptr = [self.mem getPointer:p type:MEM_WRITE];
        if (ptr == NULL) {
            return 1;
        }
        memset(ptr, val, chunk_end-p);
        p = chunk_end;
    }
    return 0;
}

- (int)userReadTaskIntoBuffer:(addr_t)addr buf:(char *)buf count:(size_t)count {
    addr_t p = addr;
    while (p < addr + count) {
        // Read a page at a time
        // Increment the page by adding 0b00000000000000000001000000000000 which is  0x00001000
        // The first 12 bits in a virtual address are the offset into a 4096 byte
        // page and the remaining bits are used to refer to which page this
        // address is indexing into. So I just ignore the first 12 bits and
        // add 1 to the number starting with the 13th bit.
        addr_t addr_plus_count_or_end_of_page = (0xfffff000 & addr) + 0x00001000;
        // addr_t chunk_end = (PAGE(p) + 1) << PAGE_BITS;
        
        if (addr_plus_count_or_end_of_page > addr + count) {
            addr_plus_count_or_end_of_page = addr + count;
        }
        const char *ptr = [self.mem getPointer:p type:MEM_READ];
        
        PageTableEntry *pe = [self.mem getPageTableEntry:PAGE(addr)];
        // NSLog(@"getPointer: FOR - Pg:%x Off:%x  -   RESULT  -  Real:%x MemOff  %x RealBase  %x", PAGE(p), PGOFFSET(p), ptr, pe.offsetIntoMappedMemory, pe.mappedMemory.data);
        
        if (ptr == NULL) return 1;
        memcpy(&buf[p - addr], ptr, addr_plus_count_or_end_of_page - p);
        
        // Point p to the end of the page just read in case we are going to read the next page
        // on the next iteration of this while loop
        p = addr_plus_count_or_end_of_page;
    }
    return 0;
}

- (int)userWriteTaskFromBuffer:(addr_t)addr buf:(char *)buf count:(size_t)count {
    const char *cbuf = (const char *)buf;
    addr_t p = addr;
    while (p < addr + count) {
        // Write a page at a time
        addr_t chunk_end = (PAGE(p) + 1) << PAGE_BITS;
        if (chunk_end > addr + count) chunk_end = addr + count;
        // The reason we need to know if this is a read or write is to determine if we need
        // to duplicate the page because it could be a Copy On Write page being shared with
        // other processes. On write we create a new copy of the page to write to, mapping that
        // new page copy's physical address into the page tables for the current process making the
        // write
        char *ptr = [self.mem getPointer:p type:MEM_WRITE];
        if (ptr == NULL) {
            return 1;
        }
        memcpy(ptr, &cbuf[p - addr], chunk_end - p);
        p = chunk_end;
    }
    return 0;
}

- (uint8_t)userReadOneBytes:(addr_t)addr {
    uint8_t buf;
    int res = [self userReadTaskIntoBuffer:addr buf:&buf count:1];
    if (res) {
        FFLog("Memory Error: userReadTaskIntoBuffer with address: %x return > 0", addr);
    }
    return buf;
}

- (uint32_t)userReadFourBytes:(addr_t)addr {
    uint32_t buf;
    int res = [self userReadTaskIntoBuffer:addr buf:&buf count:4];
    if (res) {
        FFLog("Memory Error: userReadTaskIntoBuffer with address: %x return > 0", addr);
    }
    return buf;
}

- (int)userRead:(addr_t)addr buf:(char *)buf count:(size_t)count {
//    read_wrlock(&self.mem->lock);
    int res = [self userReadTaskIntoBuffer:addr buf:buf count:count];
    if (res) {
        FFLog("Memory Error: userReadTaskIntoBuffer with address: %x return > 0", addr);
    }
//    char *debugStr = malloc(sizeof(char) * count + 1);
//    memcpy(debugStr, buf, count);
//    debugStr[count] = '\0';
//    FFLog(@"userRead read bytes count: %d as str: %s 1st as hex: %x", count, debugStr, count ? buf[0] : 0);
    
//    read_wrunlock(&self.mem->lock);
    return res;
}

- (int)userWrite:(addr_t)addr buf:(char *)buf count:(size_t)count {
//    read_wrlock(&self.mem->lock);
    int res = [self userWriteTaskFromBuffer:addr buf:buf count:count];
//    read_wrunlock(&self.mem->lock);
    return res;
}

- (int)userWriteString:(addr_t)addr buf:(const char *)buf {
    if (addr == 0) return 1;
//    read_wrlock(&self.mem->lock);
    size_t i = 0;
    do {
        if ([self userWriteTaskFromBuffer:(addr + i) buf:&buf[i] count:sizeof(buf[i])]) {
            read_wrunlock(&self.mem->lock);
            return 1;
        }
        i++;
    } while (buf[i - 1] != '\0');
//    read_wrunlock(&self.mem->lock);
    return 0;
}

- (int)userCopyStringToStack:(addr_t)sp string:(const char *)string {
    sp -= strlen(string) + 1;

    if ([self userWriteString:sp buf:string]) return 0;
    return sp;
}

// TODO Remove the whole exec_args struct
- (int)userCopyArgsIntoStack:(addr_t)sp args:(id <AnyArgs>)args {
    struct exec_args ea;
    [args writeExecArgs:&ea];
    size_t size = [args getArgStringLength];
    sp -= size;
    if ([self userWrite:sp buf:ea.args count:size]) return 0;
    return sp;
}

- (int)userReadString:(addr_t)addr buf:(char *)buf max:(size_t)max {
    if (addr == 0) return 1;
//    read_wrlock(&self.mem->lock);
    size_t i = 0;
    while (i < max) {
        // TODO How does this work?
        if ([self userReadTaskIntoBuffer:(addr + i) buf:&buf[i] count:sizeof(buf[i])]) {
//            read_wrunlock(&self.mem->lock);
            return 1;
        }
        if (buf[i] == '\0') break;
        i++;
    }
//    read_wrunlock(&self.mem->lock);
    return 0;
}

// ------------------------------------------ Memory helpers end

- (Boolean)isSuperuser {
    return self->euid == 0;
}

- (int)readHeader:(FileDescriptor *)fd header:(struct elf_header *)header {
    int err;
    // Seek to the beginning of the file
    // http://man7.org/linux/man-pages/man3/errno.3.html
    if ([fd.fdOps lseek:fd off:0 whence:SEEK_SET]) return _EIO;

    // Read the header from the fd
    int readSizeOrError = [fd.fdOps read:fd buf:header bufSize:sizeof(*header)];
    if (readSizeOrError != sizeof(*header)) {
        FFLog("Task Error: During Elf Exec the header read failed. Expected size: %d. Got size: %d", sizeof(*header), readSizeOrError);
        if (err < 0) return _EIO;

        // ENOEXEC         Exec format error
        return _ENOEXEC;
    }

    // Copy in the ELF Magic bytes to the header and then check the header values
    if (memcmp(&header->magic, ELF_MAGIC, sizeof(header->magic)) != 0
        || (header->type != ELF_EXECUTABLE && header->type != ELF_DYNAMIC)
        || header->bitness != ELF_32BIT
        || header->endian != ELF_LITTLEENDIAN
        || header->elfversion1 != 1
        || header->machine != ELF_X86) return _ENOEXEC;
    return 0;
}

- (int)readPrgHeaders:(FileDescriptor *)fd header:(struct elf_header) header ph_out:(struct prg_header **)ph_out {
    //static int readPrgHeaders(struct fd *fd, struct elf_header header, struct prg_header **ph_out) {
    ssize_t ph_size = sizeof(struct prg_header) * header.phent_count;
    struct prg_header *ph = malloc(ph_size);
    if (ph == NULL) return _ENOMEM;

    if ([fd.fdOps lseek:fd off:header.prghead_off whence:SEEK_SET] < 0) {
        free(ph);
        return _EIO;
    }
    if ([fd.fdOps read:fd buf:ph bufSize:ph_size] != ph_size) {
        free(ph);
        if (errno != 0) return _EIO;
        return _ENOEXEC;
    }

    *ph_out = ph;
    return 0;
}

- (int)loadEntry:(FileDescriptor *)fd ph:(struct prg_header) ph bias:(int)bias debugString:(NSString *)debugString{
    int err;

    addr_t addr = ph.vaddr + bias;
    addr_t offset = ph.offset;
    addr_t memsize = ph.memsize;
    addr_t filesize = ph.filesize;

    FFLog(@"Task ELF: Loading entry for address  %x  offset %x  memsize  %x filesize  %x", addr, offset, memsize, filesize);
    
    int flags = P_READ;
    if (ph.flags & PH_W) {
        flags |= P_WRITE;
    }

    int numPagesNeeded = PAGE_ROUND_UP(filesize + PGOFFSET(addr));
    
    // https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#Program_header
    // In the program header we use
    //     p_offset    Offset of the segment in the file image.
    //     p_vaddr    Virtual address of the segment in memory.
    // When memory is addressed into at the vaddr address the offset into memory will
    // be PGOFFSET(vaddr) which is the first 12 bits
    // Take the offset into the file, where we will want to start reading from, and subtract the
    // offset part of the address to get the offset that will be used when mapping the page table
    // to its memory
    err = [self mmap:fd pageStart:PAGE(addr) numPages:numPagesNeeded offset:offset - PGOFFSET(addr) protectionFlags:flags flags:MMAP_PRIVATE debugString:debugString]; //[NSString stringWithFormat:@"Loading entry for program header with offset %x - info: %@", offset, debugString]];

    [self.elfEntryVMemInfo addObject:@[[NSNumber numberWithInt:addr], [NSNumber numberWithInt:filesize], [NSNumber numberWithInt:numPagesNeeded], [NSData dataWithBytes:&ph length:sizeof(struct prg_header)]]];

    if (err < 0) {
        return err;
    }

    // Keep track of the FileDescriptor object used to mmap the memory used by these page table entries
    [self.mem getPageTableEntry:PAGE(addr)].mappedMemory.fd = fd;
    
    FFLog(@"Task ELF: First page for entry %x", PAGE(addr));
    
    [fd incrementRefCount];
    
    // If this is being mapped into memory allocated not ona page boundary there will be some number of bytes
    // before the start of the, this number of bytes is PGOFFSET(addr)
    // The offset from the elf header was based off of the file starting and index 0 and here
    // we could be starting from x%0xfff bytes into a page
    [self.mem getPageTableEntry:PAGE(addr)].mappedMemory.fileOffset = offset - PGOFFSET(addr);
    
    FFLog(@"TASK ELF: Modified 1st page's memory file offset to  %x",offset - PGOFFSET(addr));

    if (memsize > filesize) {
        // put zeroes between addr + filesize and addr + memsize, call that bss
        dword_t bss_size = memsize - filesize;

        // first zero the tail from the end of the file mapping to the end
        // of the load entry or the end of the page, whichever comes first
        addr_t file_end = addr + filesize;
        dword_t tail_size = PAGE_SIZE - PGOFFSET(file_end);
        if (tail_size == PAGE_SIZE)
            // if you can calculate tail_size better and not have to do this please let me know
            tail_size = 0;

        // TODO Is this userMemset coming up necessary since mapEmptyMemory should 0 out all this anyway?
        if (tail_size != 0) {
            // Unlock and lock the mem because the user functions must be
            // called without locking mem.
//            write_wrunlock(&self.mem->lock);
            
            [self userMemset:file_end val:0 count:tail_size];
//            write_wrlock(&self.mem->lock);
        }
        if (tail_size > bss_size) tail_size = bss_size;

        // then map the pages from after the file mapping up to and including the end of bss
        if (bss_size - tail_size != 0) err = [self.mem mapEmptyMemory:PAGE_ROUND_UP(addr + filesize) numPages:PAGE_ROUND_UP(bss_size - tail_size) flags:flags];
        if (err < 0) return err;
    }
    return 0;
}

- (int)formatExec:(FileDescriptor *)fd file:(NSString *)file argv:(ArgArgs *)argv envp:(EnvArgs *)envp {
    return [self elfExec:fd file:file argv:argv envp:envp];
}

- (int)shebangExec:(FileDescriptor *)fd file:(NSString *)file argv:(ArgArgs *)argv envp:(EnvArgs *)envp {
    // read the first 128 bytes to get the shebang line out of

    // This just sets the file offset to the beginning of the file for read or write operations coming up
    if ([fd.fdOps lseek:fd off:0 whence:SEEK_SET]) return _EIO;

    char header[128];
    int size = [fd.fdOps read:fd buf:header bufSize:sizeof(header) - 1];
    if (size < 0) return _EIO;
    header[size] = '\0';

    // only look at the first line
    char *newline = strchr(header, '\n');
    if (newline == NULL) return _ENOEXEC;
    *newline = '\0';

    // format: #![spaces]interpreter[spaces]argument[spaces]
    char *p = header;
    if (p[0] != '#' || p[1] != '!') return _ENOEXEC;

    NSString *headerStr = [NSString stringWithCString:p encoding:NSUTF8StringEncoding];
    NSArray *headerComponents = [headerStr componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *interpreterStr = [headerComponents objectAtIndex:0];

    ArgArgs *aa = [argv clone];
    for (NSString *a in headerComponents) {
        [aa addArgToFront:a];
    }

    FileDescriptor *interpreterFD = [self.fs genericOpen:interpreterStr flags:O_RDONLY_ mode:0 currentTask:self];
    if (interpreterFD.err) {
        return interpreterFD.err;
    }
    int err = [self formatExec:interpreterFD file:interpreterStr argv:aa envp:envp];
    [interpreterFD close];
    return err;
}

- (addr_t)findHoleForElf:(struct elf_header *)header ph:(struct prg_header *)ph {
    struct prg_header *first = NULL, *last = NULL;
    for (int i = 0; i < header->phent_count; i++) {
        if (ph[i].type == PT_LOAD) {
            if (first == NULL) first = &ph[i];
            last = &ph[i];
        }
    }
    pages_t size = 0;
    if (first != NULL) {
        pages_t a = PAGE_ROUND_UP(last->vaddr + last->memsize);
        pages_t b = PAGE(first->vaddr);
        size = a - b;
    }
    PageTableEntry *elfHole = [self.mem findNextPageTableEntryHole:size];
    // return address of elf hole, not the page number
    return (dword_t)(elfHole.pageIndex << PAGE_BITS);
}

- (int)elfExec:(FileDescriptor *)fd file:(NSString *)file argv:(ArgArgs *)argv envp:(EnvArgs *)envp {
    int err = 0;
    
    self.elfEntryVMemInfo = [NSMutableArray new];
    

    NSString *debugString = file;
    
    char tmpBuf[MAX_PATH];
    int ferr = fcntl(fd.realFD, F_GETPATH, tmpBuf);
    FFLog(@"Task ELF: File path for open: %s", tmpBuf);
    debugString = [NSString stringWithFormat:@"%s", tmpBuf];
    

    // read the headers
    struct elf_header header;
    if ((err = [self readHeader:fd header:&header]) < 0) return err;
    struct prg_header *ph;
    if ((err = [self readPrgHeaders:fd header:header ph_out:&ph]) < 0) return err;

    // The elf section header is not used at run time it sounds like
    // https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

    // look for an interpreter
    char *interp_name = NULL;
    FileDescriptor *interp_fd;
    struct elf_header interp_header;
    struct prg_header *interp_ph = NULL;
    // ph stands for program header ?
    // https://medium.com/@MrJamesFisher/understanding-the-elf-4bd60daac571
    // Or best resource is wiki and https://upload.wikimedia.org/wikipedia/commons/e/e4/ELF_Executable_and_Linkable_Format_diagram_by_Ange_Albertini.png
    //
    // http://man7.org/linux/man-pages/man5/elf.5.html
    //
    for (unsigned i = 0; i < header.phent_count; i++) {
        if (ph[i].type != PT_INTERP) continue;
        if (interp_name) {
            // can't have two interpreters
            return _EINVAL;
        }

        interp_name = calloc(ph[i].filesize, sizeof(char));
        if (interp_name == NULL) return _ENOMEM;
        else if (strlen(interp_name) > 0) {
            debugString = [NSString stringWithFormat:@"%@ -itp - %s", debugString, interp_name];
        }

        // read the interpreter name out of the file
        if ([fd.fdOps lseek:fd off:ph[i].offset whence:SEEK_SET] < 0) return _EIO;
        if ([fd.fdOps read:fd buf:interp_name bufSize:ph[i].filesize] != ph[i].filesize) return _EIO;

        // open interpreter and read headers
        interp_fd = [self.fs genericOpen:[NSString stringWithCString:interp_name encoding:NSUTF8StringEncoding] flags:O_RDONLY mode:0 currentTask:self];
        if (interp_fd.err) {
            return interp_fd.err;
        }
        if ((err = [self readHeader:interp_fd header:&interp_header]) < 0) {
            if (err == _ENOEXEC) return _ELIBBAD;
        }
        if ((err = [self readPrgHeaders:interp_fd header:interp_header ph_out:&interp_ph]) < 0) {
            if (err == _ENOEXEC) return _ELIBBAD;
        }
    }

    // free the process's memory.
    // from this point on, if any error occurs the process will have to be
    // killed before it even starts. please don't be too sad about it, it's
    // just a process.

//    [self decrementRefCount];
//        task_set_mm(current, mm_new());
//    write_wrlock(&self->memLock);
//    [fd incrementRefCount];
    self.exeFile = fd;

    addr_t loadAddr; // used for AX_PHDR
    bool loadAddrSet = false;
    addr_t bias = 0; // offset for loading shared libraries as executables

    // map dat shit!
    for (unsigned i = 0; i < header.phent_count; i++) {
        if (ph[i].type != PT_LOAD) continue;

        if (!loadAddrSet && header.type == ELF_DYNAMIC) {
            // see giant comment in linux/fs/binfmt_elf.c, around line 950
            if (interp_name)
                bias = 0x56555000; // I have no idea how this number was arrived at
            else
                bias = [self findHoleForElf:&header ph:ph];
        }

        if ((err = [self loadEntry:fd ph:ph[i] bias:bias debugString:[NSString stringWithFormat:@"%@ ph[i]:%d", debugString, i]]) < 0) {
//            write_wrunlock(&self->memLock);
            return err;
        }

        // load_addr is used to get a value for AX_PHDR et al
        if (!loadAddrSet) {
            loadAddr = bias + ph[i].vaddr - ph[i].offset;
            loadAddrSet = true;
        }

        // we have to know where the brk starts
        addr_t brkAddress = bias + ph[i].vaddr + ph[i].memsize;
        if (brkAddress > self->startBrkAddress) self->startBrkAddress = self->brkAddress = BYTES_ROUND_UP(brkAddress);
    }

    if (self->elfEntryPoint != 0) {
        die("Loading an ELF with multiple entry points. This probably is just fine and this can be removed");
    }
    
    self->elfEntryPoint = bias + header.entry_point;
    FFLog(@"Task ELF: Entry point before Interpreter base %x  entry point %x", bias + header.entry_point);
    
    addr_t interpBase = 0;

    // TODO: Should this be a strlen?
    if (interp_name) {
        // map dat shit! interpreter edition
        interpBase = [self findHoleForElf:&interp_header ph:interp_ph];
        for (int i = interp_header.phent_count - 1; i >= 0; i--) {
            if (interp_ph[i].type != PT_LOAD) continue;
            if ((err = [self loadEntry:interp_fd ph:interp_ph[i] bias:interpBase debugString:debugString]) < 0)
//                    write_wrunlock(&self->memLock);
                return err;
        }
        
        FFLog(@"ELF: Interpreter base %x  entry point %x", interpBase, interp_header.entry_point);
        
        self->elfEntryPoint = interpBase + interp_header.entry_point;
    }

    // map vdso
    err = _ENOMEM;
    
    // TODO: IMPORTANT: Double chekc this
    pages_t vdsoPageLength = 1;
    //    pages_t vdsoPageLength = sizeof(vdso_data) >> PAGE_BITS;
    
    // FIXME disgusting hack: musl's dynamic linker has a one-page hole, and
    // I'd rather not put the vdso in that hole. so find a two-page hole and
    // add one.
    // TODO Why use a 2 page hole here?
    PageTableEntry *vdsoPageTableEntry = [self.mem findNextPageTableEntryHole:vdsoPageLength + 1];
    page_t vdsoPageTableEntryIndex = vdsoPageTableEntry.pageIndex;
    if (!vdsoPageTableEntry) {
//        write_wrunlock(&self->memLock);
        return err;
    }
    
    
    vdsoPageTableEntryIndex += 1;
    // There really should be a check here to make sure that this didn't just push the 2 page table long set out past
    // the ends of the page table entry list
    if (vdsoPageTableEntryIndex + vdsoPageLength >= NUM_PAGE_TABLE_ENTRIES) {
        die("Should prob just find another hole for vdso. This hole was too close to the end of the PTE array and is index out of bounds.");
    }
    
    
    err = [self.mem mapMemory:vdsoPageTableEntryIndex numPages:vdsoPageLength memory:(void *)vdso_data offset:0 flags:0 debugString:@"vdso"];
    if (err < 0) {
//        write_wrunlock(&self->memLock);
        return err;
    }
    [self.mem getPageTableEntry:vdsoPageTableEntryIndex].mappedMemory.name = @"[vdso]";
    self->vdsoAddress = vdsoPageTableEntryIndex << PAGE_BITS;
    addr_t vdsoEntry = self->vdsoAddress + ((struct elf_header *)vdso_data)->entry_point;

    // map 3 empty "vvar" pages to satisfy ptraceomatic
    // What is vvar?
    // Check out:
    // https://lwn.net/Articles/615809/
    // More at
    // https://stackoverflow.com/questions/42730260/unable-to-access-contents-of-a-vvar-memory-region-in-gdb
    #define NUM_VVAR 3
    PageTableEntry *vvarPageTableEntry = [self.mem findNextPageTableEntryHole:NUM_VVAR];
    if (!vvarPageTableEntry) {
//        write_wrunlock(&self->memLock);
        return err;
    }
    err = [self.mem mapEmptyMemory:vvarPageTableEntry.pageIndex numPages:NUM_VVAR flags:P_WRITE];
    if (err < 0) {
//        write_wrunlock(&self->memLock);
        return err;
    }
    vvarPageTableEntry.mappedMemory.name = @"[vvar]";

    // STACK TIME!

    // allocate 1 page of stack at 0xffffd, and let it grow down
    err = [self.mem mapEmptyMemory:0xffffd numPages:1 flags:P_WRITE | P_GROWSDOWN];
    if (err < 0) {
//        write_wrunlock(&self->memLock);
        return err;
    }
    // that was the last memory mapping
//    write_wrunlock(&self.mem->lock);
    dword_t sp = 0xffffe000;
    // on 32-bit linux, there's 4 empty bytes at the very bottom of the stack.
    // on 64-bit linux, there's 8. make ptraceomatic happy. (a major theme in this file)
    sp -= sizeof(void *);

    err = _EFAULT;
    // first, copy stuff pointed to by argv/envp/auxv
    // filename, argc, argv
    // Stack layout
    // https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html
    addr_t file_addr = sp = [self userCopyStringToStack:sp string:[file UTF8String]];
    if (sp == 0) {
//        write_wrunlock(&self->memLock);
        return err;
    }

    addr_t envp_addr = sp = [self userCopyArgsIntoStack:sp args:envp];
    if (sp == 0) {
//        write_wrunlock(&self->memLock);
        return err;
    }
    self->argvEndAddress = sp;
    addr_t argv_addr = sp = [self userCopyArgsIntoStack:sp args:argv];
    if (sp == 0) {
//        write_wrunlock(&self->memLock);
        return err;
    }
    self->argvStartAddress = sp;
    sp = sp & ~0xf; // align_stack

    addr_t platform_addr = sp = [self userCopyStringToStack:sp string:"i686"];
    if (sp == 0) {
//        write_wrunlock(&self->memLock);
        return err;
    }
    // 16 random bytes so no system call is needed to seed a userspace RNG
    char random[16] = {};
    get_random(random, sizeof(random)); // if this fails, eh, no one's really using it
    addr_t random_addr = sp -= sizeof(random);
    if ([self userWrite:sp buf:&random count:sizeof(random)]) {
//        write_wrunlock(&self->memLock);
        return err;
    }

    // the way linux aligns the stack at this point is kinda funky
    // calculate how much space is needed for argv, envp, and auxv, subtract
    // that from sp, then align, then copy argv/envp/auxv from that down

    // declare elf aux now so we can know how big it is
    struct aux_ent aux[] = {
        { AX_SYSINFO,      vdsoEntry                     },
        { AX_SYSINFO_EHDR, self->vdsoAddress              },
        { AX_HWCAP,        0x00000000                    }, // suck that
        { AX_PAGESZ,       PAGE_SIZE                     },
        { AX_CLKTCK,       0x64                          },
        { AX_PHDR,         loadAddr + header.prghead_off },
        { AX_PHENT,        sizeof(struct prg_header)     },
        { AX_PHNUM,        header.phent_count            },
        { AX_BASE,         interpBase                    },
        { AX_FLAGS,        0                             },
        { AX_ENTRY,        bias + header.entry_point     },
        { AX_UID,          0                             },
        { AX_EUID,         0                             },
        { AX_GID,          0                             },
        { AX_EGID,         0                             },
        { AX_SECURE,       0                             },
        { AX_RANDOM,       random_addr                   },
        { AX_HWCAP2,       0                             }, // suck that too
        { AX_EXECFN,       file_addr                     },
        { AX_PLATFORM,     platform_addr                 },
        { 0,               0                             }
    };
    sp -= (([argv count] + 1) + ([envp count] + 1) + 1) * sizeof(dword_t);
    sp -= sizeof(aux);
    sp &= ~0xf;

    // now copy down, start using p so sp is preserved
    addr_t p = sp;

    // argc
    int argvCount = [argv count];
    if ([self userWrite:p buf:&argvCount count:sizeof(argvCount)]) return _EFAULT;
    p += sizeof(dword_t);

    // argv
    while (argvCount-- > 0) {
        if ([self userWrite:p buf:&argv_addr count:sizeof(argv_addr)]) return _EFAULT;
        argv_addr += [self userStrlen:argv_addr] + 1;
        p += sizeof(dword_t); // null terminator
    }
    p += sizeof(dword_t); // null terminator

    // envp
    size_t envc = [envp count];
    while (envc-- > 0) {
        if ([self userWrite:p buf:&envp_addr count:sizeof(envp_addr)]) return _EFAULT;
        envp_addr += [self userStrlen:envp_addr] + 1;
        p += sizeof(dword_t);
    }
    p += sizeof(dword_t); // null terminator

    // copy auxv
    if ([self userWrite:p buf:&aux count:sizeof(aux)]) {
//        write_wrunlock(&self->memLock);
        return err;
    }
    p += sizeof(aux);

    self->stackStartAddress = sp;
    self.cpu->state.esp = sp;
    self.cpu->state.eip = self->elfEntryPoint;
    self.cpu->state.fcw = 0x37f;

    // From ish:
    // This code was written when I discovered that the glibc entry point
    // interprets edx as the address of a function to call on exit, as
    // specified in the ABI. This register is normally set by the dynamic
    // linker, so everything works fine until you run a static executable.
    self.cpu->state.eax = 0;
    self.cpu->state.ebx = 0;
    self.cpu->state.ecx = 0;
    self.cpu->state.edx = 0;
    self.cpu->state.esi = 0;
    self.cpu->state.edi = 0;
    self.cpu->state.ebp = 0;
    [self.cpu collapseFlags];
    self.cpu->state.eflags = 0;
//    write_wrunlock(&self->memLock);
    return 0;
//
//        err = 0;
//    out_free_interp:
//        if (interp_name != NULL)
//            free(interp_name);
//        if (interp_fd.fd != NULL && !interp_fd.err)
//            fd_close(interp_fd);
//        if (interp_ph != NULL)
//            free(interp_ph);
//    out_free_ph:
//        free(ph);
//        return err;
//
//    beyond_hope:
//        // TODO force sigsegv
//        write_wrunlock(&current->mem->lock);
//        goto out_free_interp;
//    }
}

//int __do_execve(const char *file, struct exec_args argv, struct exec_args envp) {
- (int)doExecve:(NSString *)file argv:(ArgArgs *)argv envp:(EnvArgs *)envp {
    FileDescriptor *fd = [self.fs genericOpen:file flags:O_RDONLY mode:0 currentTask:self];
    if (fd.err) {
        return fd.err;
    }

    struct statbuf stat;
    int err = [self.fs.fsOps fstat:fd stat:&stat];
    if (fd.err) {
        [fd close];
        return fd.err;
    }

    // if nobody has permission to execute, it should be safe to not execute
    // 0111 has all the execute bits set for user group and other
    // NOTE: Preceed any number by 0 to write in octal notation
    // 111 in octal is all execute bits: https://chmod-calculator.com/
    if (!(stat.mode & 0111)) {
        [fd close];
        return _EACCES;
    }

    err = [self formatExec:fd file:file argv:argv envp:envp];
    if (err == _ENOEXEC) err = [self shebangExec:fd file:file argv:argv envp:envp];
    [fd close];
    if (err < 0) return err;

    // setuid/setgid
    if (stat.mode & S_ISUID) {
        self->suid = self->euid;
        self->euid = stat.uid;
    }
    if (stat.mode & S_ISGID) {
        self->sgid = self->egid;
        self->egid = stat.gid;
    }

    // save current->comm
    lock(&self->generalLock);

    NSArray *pathComponents = [file pathComponents];
    if (pathComponents.count > 1) {
        self.command = [pathComponents objectAtIndex:pathComponents.count - 1];
    } else {
        self.command = file;
    }
//
//    char *basename = strrchr(file, '/');
//
//    if (basename == NULL)
//        basename = file;
//    else
//        basename++;
//
//    strncpy(current->comm, basename, sizeof(current->comm));
    unlock(&self->generalLock);
//
//    // set the thread name
//    char threadname[16];
//    strncpy(threadname, current->comm, sizeof(threadname)-1);
//    threadname[15] = '\0';
//#if __APPLE__
//    pthread_setname_np(threadname);
//#else
//    pthread_setname_np(pthread_self(), threadname);
//#endif
//    [[NSThread currentThread] setName:self.command];
//
    [self.filesTable closeCloExecFDs];

    // TODO Implement: Signals
//
//    // reset signal handlers
//    lock(&current->sighand->lock);
    for (int sig = 0; sig < NUM_SIGS; sig++) {
        SigAction *action = self.sigHandler->actions[sig];
        if (action->handler != SIG_IGN_)
            action->handler = SIG_DFL_;
    }
//    current->sighand->altstack = 0;
//    unlock(&current->sighand->lock);
//
    self.didExec = true;
//    vfork_notify(current);
    return 0;
}

- (void)incrementRefCount {
    self->mmRefCount++;
}

- (void)decrementRefCount {
    self->mmRefCount--;
    if (!self->mmRefCount) {
        if (self.exeFile) [self.exeFile close];
        [self.mem unmapMemory:0 numPages:NUM_PAGE_TABLE_ENTRIES];
    }
}

- (Task *)cloneTask {
    Task *newTask = [[Task alloc] initWithParentTask:NULL];

    newTask.exeFile = self.exeFile;
    newTask->startBrkAddress = self->startBrkAddress;
    newTask->brkAddress = self->brkAddress;
//    newTask.taskMemoryRefCount = 1;

    if (newTask.exeFile) {
        [newTask.exeFile close];
    }

    Memory *newMem = [[Memory alloc] init];

    self.mem.changesToMemory = 0;

//    write_wrlock(&self.mem->lock);
    [self.mem copyPageTableEntryOnWriteTo:newMem pageStart:0 pageCount:NUM_PAGE_TABLE_ENTRIES];
//    write_wrunlock(&self.mem->lock);

    newTask.mem = newMem;
    newMem.task = newTask;

    return newTask;
}

//- (int)mmap:(FileDescriptor *)fd pageStart:(pages_t)pageStart numPages:(pages_t)numPages offset:(size_t)offset protectionFlags:(int)protectionFlags flags:(unsigned)flags {
//    return [self mmap:fd pageStart:pageStart numPages:numPages offset:offset protectionFlags:protectionFlags flags:flags debugString:@""];
//}

- (int)mmap:(FileDescriptor *)fd pageStart:(pages_t)pageStart numPages:(pages_t)numPages offset:(size_t)offset protectionFlags:(int)protectionFlags flags:(unsigned)flags debugString:(NSString *)debugString {
    if (numPages == 0) return 0;

    FFLog(@"Task MMAP - page start  %x   num pages  %x     offset  %x  ", pageStart,  numPages, offset);
    
    int mmap_flags = 0;

    // Convert from this projects bit mask to the system's mask
    if (flags & MMAP_PRIVATE) mmap_flags |= MAP_PRIVATE;
    if (flags & MMAP_SHARED) mmap_flags |= MAP_SHARED;

    int mmapProtectionFlags = PROT_READ;
    if (protectionFlags & P_WRITE) mmapProtectionFlags |= PROT_WRITE;

    off_t real_offset = (offset / get_real_page_size()) * get_real_page_size();
    off_t correction = offset - real_offset;

    if (offset != real_offset) {
        die("mmap page sizes");
    }

    char *memory = mmap(NULL, (numPages * PAGE_SIZE) + correction,
                        mmapProtectionFlags, mmap_flags, fd.realFD, real_offset);
    FFLog(@"Task MMAP: Mapping memory ptr %x to page %x  real offset %x", memory, pageStart, real_offset);
    if (numPages) {
        FFLog(@"Task MMAP - First bytes from mmap %x %x %x %x %x %x", memory[0], memory[1], memory[2], memory[3], memory[4], memory[5]);
    } else {
        FFLog(@"Task MMAP - Didnt allocate a whole page");
    }
    
    return [self.mem mapMemory:pageStart numPages:numPages memory:memory offset:correction flags:protectionFlags debugString:debugString];
}

- (dword_t)sysGetRandom:(addr_t)buf_addr len:(dword_t)len flags:(dword_t)flags {
    if (len > 1 << 20) return _EIO;
    char *buf = malloc(len);
    if (get_random(buf, len) != 0) {
        free(buf);
        return _EIO;
    }

    if ([self userWrite:buf_addr buf:buf count:len]) {
        free(buf);
        return _EFAULT;
    }
    free(buf);
    return len;
}

- (int)devOpen:(int)major minor:(int)minor type:(int)type fd:(FileDescriptor *)fd {
    Class dev = NULL;
    if (type == DEV_BLOCK) {
    } else {
    }

    // Set the blocked and waiting signals to all be empty
    // If thse arrays have any non 0 value at the index of the signal later
    // we will know that we are blocking or waiting on that
    for (int i = 0; i < NUM_SIGS; i++) {
        [self.blockedSignals clear];
        [self.waitingSignals clear];
    }
    if (dev == NULL) return _ENXIO;

    // TODO Implement
//    fd->ops = &dev->fd;
//    if (!dev->open)
//        return 0;
//
//    return dev->open(major, minor, fd);
    return 0;
}

-(NSString *)description {
    return [[NSString alloc] initWithFormat:@"Pid: %d\nSigHandler: %@\nSigQueue: %@\nBlocked Signals: %@\nWaiting Signals: %@\nPending Signals: %@\nSaved Signals: %@\nThread Group: %@\nCPU: %@\nMem: %@\nGroups: %@\nFileSystem: %@\nFileDescTable: %@\nElf Load: %@\n", self.pid.id, self.sigHandler, self.sigQueue, self.blockedSignals, self.waitingSignals, self.pendingSignals, self.savedBlockedSignals, self.group, self.cpu, self.mem, self.groups, self.fs, self.filesTable, self.elfEntryVMemInfo];
}

- (id)initWithParentTask:(Task *)parent {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    static int current_pid = 1;
    while (current_pid < MAX_PID) {
        if (![pids objectForKey:[NSString stringWithFormat:@"%d", current_pid]]) {
            break;
        } else {
            current_pid += 1;
        }
        
        if (current_pid >= MAX_PID) {
            current_pid = 0;
        }
    }
    
    // http://man7.org/linux/man-pages/man2/fork.2.html
    // Child tasks' pending signals is an empty list
    self.sigQueue = [[SigQueue alloc] init];
    
    Pid *newPid = [[Pid alloc] init];
    newPid.id = current_pid;
    newPid.task = self;
    
    NSString *pidString = [NSString stringWithFormat:@"%d", current_pid];
    [pids setValue:newPid forKey:pidString];

    self.pid = newPid;
    
    // Copy over all relevant info form the parent task
    // TODO: Copy parent task - The entire task struct is mostly copied over in linux
    if (parent) {
        self.fs = parent.fs;
        
        // The child task does inherit the parent's signal handlers
        self.sigHandler = [[SigHandler alloc] initWith:parent.sigHandler];
        
        self.blockedSignals = [[SigSet alloc] initWithSigSet:parent.blockedSignals->mask];
        self.waitingSignals = [[SigSet alloc] initWithSigSet:parent.waitingSignals->mask];
        self.pendingSignals = [[SigSet alloc] initWithSigSet:parent.pendingSignals->mask];
        self.savedBlockedSignals = [[SigSet alloc] initWithSigSet:parent.savedBlockedSignals->mask];
    } else {
        // This must be the initial task, no parent to inherit from
        self.sigHandler = [[SigHandler alloc] init];
        
        self.blockedSignals = [[SigSet alloc] init];
        self.waitingSignals = [[SigSet alloc] init];
        self.pendingSignals = [[SigSet alloc] init];
        self.savedBlockedSignals = [[SigSet alloc] init];
    }
    
    self.group = [[ThreadGroup alloc] initWithLeaderTask:self];

    self.cpu = [[CPU alloc] initWithTask:self];
    self.filesTable = [FileDescriptorTable new];
    self.didExec = false;
//    self.generalLock = [NSLock new];
//    self.memLock = [NSLock new];
//    self.waitingLock = [NSLock new];

    self.mem = [[Memory alloc] init]; // TODO: FIX: When creating a new child task it stops here
    
    self.groups = [NSMutableArray arrayWithCapacity:MAX_GROUPS];
    self->mmRefCount = 1;
    return self;
}

- (void)start {
    [self.cpu start];
}








// -------------------- Signals -------------------------------------

- (int) waitForIgnoreSignals:(cond_t *)cond lock:(lock_t *)lock timeout:(struct timespec *)timeout {
    //if (current) {
    lock(&self->waitingConditionLock);
    self->waitingCondition = *cond;
    self->waitingLock = *lock;
    unlock(&self->waitingConditionLock);
    //}
    int rc = 0;

    if (!timeout) {
        pthread_cond_wait(&cond->cond, &lock->m);
    } else {
        rc = pthread_cond_timedwait_relative_np(&cond->cond, &lock->m, timeout);
    }

    
//    if (current) {
    lock(&self->waitingConditionLock);
//    self->waitingCondition = nil;
//    self->waitingLock = nil;
    unlock(&self->waitingConditionLock);
//    }
    if (rc == ETIMEDOUT)
        return _ETIMEDOUT;
    return 0;
}

- (void) deliverSignalTo:(Task *)task signal:(int)signal sigInfo:(SigInfo*)sigInfo {
    
    // Keep track of the signal that caused this signal as well as any other meta data that was
    // attached to the siginfo object
    sigInfo->info.sig = signal;
    
    
    // One of the most important parts of this method is that we add the SigInfo object to the task's
    // SigQueue
    SigInfo *newSigInfo = [[SigInfo alloc] init];
    newSigInfo->info = sigInfo->info;
    [self.sigQueue add:newSigInfo];
    
    // Check if the task is blocked for a specific signal or if it is waiting for a specific
    // signal and if the signal itself is blockable in the first place
    // SIGKILL and SIGSTOP are unblockable signals
    SigSet *blockedAndNotWaiting = [[SigSet alloc] initWithSigSet:(task.blockedSignals->mask & ~task.waitingSignals->mask)];
    if ([blockedAndNotWaiting has:signal] && signal != SIGKILL_ && signal != SIGSTOP_) {
        // If this task is waiting on this signal and its blocked
        // and its a blockable signal then just return
        return;
    }
    
    if (self != task) {
        // If this signal is not being sent from it's own task then send a real pthread_kill SIGUSR1 signal
        pthread_kill(task->thread, SIGUSR1);
        
        // Now do some crazy locking to wait until the task is not waiting
        
        /*
         // wake up any pthread condition waiters
         // actual madness, I hope to god it's correct
         // must release the sighand lock while going insane, to avoid a deadlock
         unlock(&task->sighand->lock);
         retry:
         lock(&task->waiting_cond_lock);
         if (task->waiting_cond != NULL) {
         bool mine = false;
         if (pthread_mutex_trylock(&task->waiting_lock->m) == EBUSY) {
         if (pthread_equal(task->waiting_lock->owner, pthread_self()))
         mine = true;
         if (!mine) {
         unlock(&task->waiting_cond_lock);
         goto retry;
         }
         }
         notify(task->waiting_cond);
         if (!mine)
         unlock(task->waiting_lock);
         }
         unlock(&task->waiting_cond_lock);
         lock(&task->sighand->lock);
         */
        // TODO: Notify
         
    }
    //self.sigQueue
}

- (struct rusage_) getCurrentRusage {
    struct rusage_ rusage;
//#if __linux__
//    struct rusage usage;
//    int err = getrusage(RUSAGE_THREAD, &usage);
//    assert(err == 0);
//    rusage.utime.sec = usage.ru_utime.tv_sec;
//    rusage.utime.usec = usage.ru_utime.tv_usec;
//    rusage.stime.sec = usage.ru_stime.tv_sec;
//    rusage.stime.usec = usage.ru_stime.tv_usec;
//#elif __APPLE__
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    thread_info(mach_thread_self(), THREAD_BASIC_INFO, (thread_info_t) &info, &count);
    rusage.utime.sec = info.user_time.seconds;
    rusage.utime.usec = info.user_time.microseconds;
    rusage.stime.sec = info.system_time.seconds;
    rusage.stime.usec = info.system_time.microseconds;
//#endif
    return rusage;
}

- (Task *)findNewParent {
    for (Task *task in self.group.threads) {
        if (!task->exiting) {
            return task;
        }
    }
    
    // If no non exiting tasks were found in the group then init is the parent
    return [pids objectForKey:@"0"];
}

- (bool) exitThreadGroup {
    self.groupLinks = [NSMutableArray new];
    bool group_dead = [self.group.threads count] == 0;
    if (group_dead) {
        // Then the group is dead
        // TODO: free timer
        //if (group->timer)
        //    timer_free(group->timer);
    }
    return group_dead;
}

- (void) doExit:(int)status {
    if (self->clear_tid) {
        pid_t_ zero = 0;
        if ([self userWrite:self->clear_tid buf:&zero count:sizeof(zero)] == 0) {
            // TODO: Futex
            // futex_wake(clear_tid, 1);
        }
    }
    
    // TODO: release all our resources
    // mm_release(current->mm);
    // fdtable_release(current->files);
    // fs_info_release(current->fs);
    
    // sighand must be released below so it can be protected by pids_lock
    // since it can be accessed by other threads
    
    // save things that our parent might be interested in
    self->exitCode = status; // FIXME locking
    struct rusage_ rusage = [self getCurrentRusage];
    // lock(&current->group->lock);
    rusage_add(&self.group->rusage, &rusage);
    struct rusage_ group_rusage = self.group->rusage;
    // unlock(&current->group->lock);
    
    // the actual freeing needs pids_lock
    // lock(&pids_lock);
    self->exiting = true;
    // release the sighand
    // sighand_release(current->sighand);
    
    [self.sigQueue.queue removeAllObjects];
    // for (SigInfo *si in self.sigQueue.queue) {
    //     [self.sigQueue remove:si];
    // }

    Task *leader = self.group.leader;
    
    // reparent children
    Task *newParent = [self findNewParent];
    for (Task *child in self.children) {
        child.parent = newParent;
        child.siblings = [NSMutableArray new];
        [newParent.children addObjectsFromArray:child.siblings];
    }
    
    if ([self exitThreadGroup]) {
        // notify parent that we died
        Task *parent = leader.parent;
        if (!parent) {
            // init died
            // TODO: halt_system();
            [self haltSystem];
        } else {
            leader->zombie = true;
            // TODO: notify
            // notify(&parent->group->child_exit);
            SigInfo *si = [[SigInfo alloc] init];
            siginfo_ info = {
                .code = SI_KERNEL_,
                .child.pid = self.pid.id,
                .child.uid = self->uid,
                .child.status = self->exitCode,
                .child.utime = clock_from_timeval(group_rusage.utime),
                .child.stime = clock_from_timeval(group_rusage.stime),
            };
            si->info = info;
            if (leader->exit_signal != 0) {
                [self sendSignalTo:parent signal:leader->exit_signal sigInfo:si];
            }
        }
        
        // TODO: Implement introsepctive exit_hook here?
        //if (exit_hook != NULL)
        //    exit_hook(current, status);
    }
    
    // TODO: Implement vfork_notify
    //vfork_notify(current);
    // TODO: Implement  Destroy self/task
    // if (current != leader)
    //    task_destroy(current);
    // unlock(&pids_lock);
    
    pthread_exit(NULL);
}

- (void) haltSystem {
    FFLog(@"Halting system");
    for (NSString *pidKeyString in pids) {
        Pid *pid = pids[pidKeyString];
        if (pid && pid.task && pid.id >= 2) {
            FFLog(@"Halting system - Killing pid %x", pid.id);
            pthread_kill(pid.task->thread, SIGKILL);
        }
    }
    
    // lock(&mounts_lock);
    MountLookup *ml = self.fs.mounts;
    for (NSString *point in ml.mountsByPoint) {
        FFLog(@"Halting system - Unmounting mount point %@", point);
        Mount *mount = ml.mountsByPoint[point];
        // [self.fs umount:mount];
        // [mount remove];
        [ml.mountsByPoint removeObjectForKey:point];
    }
    FFLog(@"Halting system - Done with halt.");
    // unlock(&mounts_lock);
}

- (void) doExitGroup:(int)status {
    // lock(&pids_lock);
    // lock(&group->lock);
    if (!self.group.doingGroupExit) {
        self.group.doingGroupExit = true;
        self.group.groupExitCode = status;
    } else {
        status = self.group.groupExitCode;
    }
    
    for (Task *task in self.group.threads) {
        [self deliverSignalTo:task signal:SIGKILL_ sigInfo:get_siginfo_nil()];
        task.group.stopped = false;
        // TODO: Notify
        // [self notify:task.group->stopped_cond];
    }
    
    // unlock(&group->lock);
    // unlock(&pids_lock);
    [self doExit:status];
}

- (void) recieveSignal:(SigInfo *)si {
    int sig = si->info.sig;
    FFLog(@"Recieving signal %d", sig);
    
    [self.pendingSignals del:sig];
    
    switch([self.sigHandler getSignalAction:sig]) {
        case SIGNAL_IGNORE:
            FFLog(@"Recieved Ignore signal");
            return;
        case SIGNAL_STOP:
            FFLog(@"Recieved Signal stop");
            // lock(&current->group->lock);
            self.group.stopped = true;
            // 0x7f is 0b01111111
            self.group.groupExitCode = sig << 8 | 0x7f;
            // unlock(&current->group->lock);
            return;
        case SIGNAL_KILL:
            FFLog(@"Recieved Signal kill");
            // unlock(&sighand->lock); // do_exit must be called without this lock
            [self doExitGroup:sig];
    }
    

    // If we didnt kill the process then we are going to have the task call the signal handler
    SigAction *action = self.sigHandler->actions[sig];
    bool need_siginfo = action->flags & SA_SIGINFO_;
    
    // setup the frame
    union {
        struct sigframe_ sigframe;
        struct rt_sigframe_ rt_sigframe;
    } frame = {};
    size_t frame_size;
    
    // Setup signal frame
    // rt_sigreturn is an advanced variant of sigreturn which supports enlarged signal type for real time signal
    if (need_siginfo) {
        frame.rt_sigframe.restorer = [self sigreturn_trampoline:"__kernel_rt_sigreturn"];
        frame.rt_sigframe.sig = si->info.sig;
        frame.rt_sigframe.info = si->info;
        frame.rt_sigframe.uc.flags = 0;
        frame.rt_sigframe.uc.link = 0;
        // TODO: altstack_to_user
        // altstack_to_user(current->sighand, &frame->uc.stack);
        // TODO: setup_sigcontext
        // setup_sigcontext(&frame.rt_sigframe.uc.mcontext, &current->cpu);
        // TODO: Convert blocked array to mask
        // frame->uc.sigmask = self.blocked;
        
        static const struct {
            uint8_t mov;
            uint32_t nr_rt_sigreturn;
            uint16_t int80;
            uint8_t pad;
        } __attribute__((packed)) rt_retcode = {
            .mov = 0xb8,
            .nr_rt_sigreturn = 173,
            .int80 = 0x80cd,
        };
        memcpy(frame.rt_sigframe.retcode, &rt_retcode, sizeof(rt_retcode));
        
        frame_size = sizeof(frame.rt_sigframe);
    } else {
        frame.sigframe.restorer = [self sigreturn_trampoline:"__kernel_sigreturn"];
        frame.sigframe.sig = si->info.sig;
        // TODO: setup_sigcontext
        //setup_sigcontext(&frame.sigframe.sc, &self.cpu);
        // TODO: Convert blocked array to mask
        frame.sigframe.extramask = self.blockedSignals->mask >> 32;
        
        static const struct {
            uint16_t popmov;
            uint32_t nr_sigreturn;
            uint16_t int80;
        } __attribute__((packed)) retcode = {
            .popmov = 0xb858,
            .nr_sigreturn = 113,
            .int80 = 0x80cd,
        };
        memcpy(frame.sigframe.retcode, &retcode, sizeof(retcode));
        
        frame_size = sizeof(frame.sigframe);
    }
    
    // set up registers for signal handler
    self.cpu->state.eax = si->info.sig;
    SigAction *sa = self.sigHandler->actions[si->info.sig];
    self.cpu->state.eip = sa->handler;
    
    dword_t sp = self.cpu->state.esp;
    // If the stack is already in the stack handlers stack then move it past the stacl
    if ([self isInAltStack]) {
        sp = self.sigHandler->altstack + self.sigHandler->altstack_size;
    }
    if (xsave_extra) {
        // do as the kernel does
        // this is superhypermega condensed version of fpu__alloc_mathframe in
        // arch/x86/kernel/fpu/signal.c
        sp -= xsave_extra;
        sp &=~ 0x3f;
        sp -= fxsave_extra;
    }
    sp -= frame_size;
    // align sp + 4 on a 16-byte boundary because that's what the abi says
    sp = ((sp + 4) & ~0xf) - 4;
    self.cpu->state.esp = sp;
    
    // Update the mask. By default the signal will be blocked while in the
    // handler, but sigaction is allowed to customize this.
    if (!(action->flags & SA_NODEFER_)) {
        [self.blockedSignals add:sig];
    }
    self.blockedSignals->mask |= action->mask;
    
    // these have to be filled in after the location of the frame is known
    if (need_siginfo) {
        frame.rt_sigframe.pinfo = sp + offsetof(struct rt_sigframe_, info);
        frame.rt_sigframe.puc = sp + offsetof(struct rt_sigframe_, uc);
        self.cpu->state.edx = frame.rt_sigframe.pinfo;
        self.cpu->state.ecx = frame.rt_sigframe.puc;
    }
    
    // install frame
    // (void) user_write(sp, &frame, frame_size);
    if (![self userWrite:sp buf:&frame count:frame_size]) {
        die("Failed to write signal handler frame to stack");
    }
    // nothing we can do if that fails
    // TODO do something other than nothing, like printk maybe
}

- (addr_t) sigreturn_trampoline:(const char *)name {
    die("TODO Implement using vdso_symbol address");
    // TODO: vdso_symbol
    addr_t sigreturn_addr = 0; //vdso_symbol(name);
    if (sigreturn_addr == 0) {
        die("sigreturn not found in vdso, this should never happen");
    }
    
    return self->vdsoAddress + sigreturn_addr;
}




- (bool) isInAltStack {
    // Return true if the current stack pointer is within the signal handlers stack bounds
    return self.sigHandler->altstack && self.cpu->state.esp > self.sigHandler->altstack && self.cpu->state.esp <= self.sigHandler->altstack + self.sigHandler->altstack_size;
}

// This could also be called something like handleSignals
// This is called to process all signals that occured during the interpretation steps
- (void) recieveSignals {
    
    // lock(&current->group->lock);
    bool wasStopped = self.group.stopped;
    // unlock(&current->group->lock);
    
    //struct sighand *sighand = self->sighand;
    // lock(&sighand->lock);
    
    // TODO: Refactor initWithSigSet to initWithSigSetMask?
    SigSet *currentBlockedSignals = [[SigSet alloc] initWithSigSet:self.blockedSignals->mask];
    if (self->hasSavedMask) {
        // TODO: Refactor these mask operations into methods on SigSet
        currentBlockedSignals->mask &= self.savedBlockedSignals->mask;
        self->hasSavedMask = false;
        self.blockedSignals->mask &= self.savedBlockedSignals->mask;
    }
    
    // Iterate over all signal types in the queue and if we are not blocking those signal types
    // then recieve a signal
    for (SigInfo *si in self.sigQueue.queue) {
        if ([currentBlockedSignals has:si->info.sig]) {
            continue;
        }
        
        [self recieveSignal:si];
        
        // Important I remove the SigInfo object AFTER the recieveSignals call so that the SigInfo object is not
        // Garbage Collected
        [self.sigQueue.queue removeObject:si];
    }
        
    if (!wasStopped) {
        // lock(&current->group->lock);
        bool nowStopped = self.group.stopped;
        // unlock(&current->group->lock);
        if (nowStopped) {
            // lock(&pids_lock);
            // TODO: parent
            // [self.notify self.parent.group.child_exit];
            // [self.sendSignal self.parent exitSignal:self.group.leader.exitSignal sigInfo:SIGINFO_NIL];
            // unlock(&pids_lock);
        }
    }
    
}

// This task can send signals to another task or to itself
- (void) sendSignalTo:(Task *)task signal:(int)signal sigInfo:(SigInfo*)sigInfo {
    if (signal == 0 || task->zombie) {
        return;
    }
    
    if ([task.sigHandler getSignalAction:signal] != SIGNAL_IGNORE) {
        [task deliverSignalTo:task signal:signal sigInfo:sigInfo];
    }

    // TODO: Signals
    if (signal == SIGCONT || signal == SIGKILL_) {
//        lock(&task->group->lock);
        // Mark this task group as not stopped and then call notify on the groups
        // stopped conditional lock which just calls pthread_cond_broadcast
        // https://pubs.opengroup.org/onlinepubs/009695399/functions/pthread_cond_broadcast.html
        // The pthread_cond_broadcast() function shall unblock all threads currently blocked on the specified condition variable cond.
        // task.group.stopped = false;`
        // notify(&task.group   ->stopped_cond);
//        unlock(&task->group->lock);
        int r = 1;
    }
}




@end
