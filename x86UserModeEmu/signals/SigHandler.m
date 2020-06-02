//
//  SigHandler.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

// Each task will have a SigHandler which will be used to register signal handling actions against
// and to lookup signal handling actions

#import "SigHandler.h"
#import "Task.h"
#import "misc.h"
#import "SigAction.h"

@class SigAction;

@implementation SigHandler

- (id)init {
    self = [super init];
    if (self) {
        for (int i = 0; i < NUM_SIGS; i++) {
            SigAction *newAction = [[SigAction alloc] init];
            newAction->handler = SIG_DFL_;
            self->actions[i] = newAction;
        }
        // self.actions = [[NSMutableArray alloc] init];
    }
    return self;
}

- (id)initWith:(SigHandler *)sigHandlerFromParent {
    self = [self init];
    if (self) {
        for (int i = 0; i < NUM_SIGS; i++) {
            self->actions[i] = sigHandlerFromParent->actions[i] ;
        }
        // self.actions = [NSMutableArray arrayWithArray:sigHandlerFromParent.actions];
    }
    return self;
}

- (int)getSignalAction:(int)signal {
    // if singal is blockable
    if (signal != SIGKILL_ && signal != SIGSTOP_) {
        // Then get the sigaction for this signal
        SigAction *sigAction = self->actions[signal];
        
        // and return which type of signal action should take place
        // Either we ignore this singal or we call the signal handler that may be in place
        
        // If it is signal ignore and its blockable then just ignore
        if (sigAction->handler == SIG_IGN_) {
            return SIGNAL_IGNORE;
        } else if (sigAction->handler != SIG_DFL_) {
            return SIGNAL_CALL_HANDLER;
        }
    }
    
    
    switch (signal) {
        // If its not "blockable" but on of the following the ignore:
        case SIGURG_:
        case SIGCONT_:
        case SIGCHLD_:
        case SIGIO_:
        case SIGWINCH_:
            return SIGNAL_IGNORE;
            
        // If it is a SIGSTOP relative then send SIGNAL_STOP
        case SIGSTOP_:
        case SIGTSTP_:
        case SIGTTIN_:
        case SIGTTOU_:
            return SIGNAL_STOP;
            
        // Otherwise send a kill signal
        default:
            return SIGNAL_KILL;
    }
}

-(NSString *)description {
    NSMutableString *ms = [@"" mutableCopy];
    for (int i = 0; i < NUM_SIGS; i++) {
        SigAction *sa = self->actions[i];
        if (sa->handler != SIG_DFL_) {
            [ms appendFormat:@"%d - [%d] %@ ", i, sa->handler, sa];
        }
    }
    return ms;
}


@end
