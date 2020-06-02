//
//  SigInfo.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "SigInfo.h"

@implementation SigInfo


-(NSString *)description {
    return [NSString stringWithFormat:@"Sig:%d SErr:%d Cde:%d ChdPid:%d", self->info.sig, self->info.sig_errno, self->info.code, self->info.child.pid];
}

@end
