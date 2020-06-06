//
//  FD.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stddef.h>
#include <dirent.h>
#import "FileDescriptor.h"
#import "RFileDescriptorOperations.h"
#import "Mount.h"
#import "errno.h"

@implementation FileDescriptor

- (int)setFlags:(dword_t)flags {
    // if (fd.fdOps setFlags) {
    
    // - (int)setflags:(FileDescriptor *)fd flags:(dword_t)flags;
    if ([[self.fdOps class] instancesRespondToSelector:@selector(setflags:flags:)]) {
    
        return [self.fdOps setflags:self flags:flags];
    }
    self->flags = (self->flags & ~FD_ALLOWED_FLAGS) | (flags & FD_ALLOWED_FLAGS);

    
    return 0;
}


-(NSString *)description {
    return [NSString stringWithFormat:@"%@ rl:%d flgs:%d off:%d err:%d", self.originalPath, self->realFD, self->flags, self->offset, self->err];
}

- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    // By default use the Real File Descriptor
    self.fdOps = [[RFileDescriptorOperations alloc] init];
    self->closeOnExec = false;
    self->err = 0;
    self->flags = 0;
    self->offset = 0;
    
    return self;
}

// TODO
- (int)close {
    int err = 0;
    
    //if (self.refCount == 0)  {
//        lock(&fd->poll_lock);
        // This is related to keeping sockets open in ios
//        struct poll_fd *poll_fd, *tmp;
//        list_for_each_entry_safe(&fd->poll_fds, poll_fd, tmp, polls) {
//            lock(&poll_fd->poll->lock);
//            list_remove(&poll_fd->polls);
//            list_remove(&poll_fd->fds);
//            unlock(&poll_fd->poll->lock);
//            free(poll_fd);
//        }
//        unlock(&fd->poll_lock);
        
        // see comment in close in kernel/fs.h
        // This if was
        // if (fd.mount && fd.mount->fs->close && fd->mount->fs->close != fd->ops->close) {
        // or use
        // if ([self respondsToSelector:@selector(methodName:closeFD:)]) {
        // NOTE I made the type specific close method named closeFD here
//        if ([self isKindOfClass:[RealFileDescriptor class]]) {
//            int new_err = [self closeFD: fd];
//            if (new_err < 0)
//                err = new_err;
//        }
        
//        if (self.inode)
//            inode_release(fd->inode);
    if (self.mount) {
            [self.mount releaseMount];
    }
    //}
    
    return err;
}


@end


