//
//  SigHandler.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "misc.h"
#include <pthread.h>
#import "sys/sync.h"

@interface SigHandler : NSObject {
    @public id actions[NUM_SIGS];
    @public atomic_uint refcount;
    @public addr_t altstack;
    @public dword_t altstack_size;
    @public lock_t lock;
}
// @property (nonatomic, strong) NSMutableArray *actions; //This is an array of SigActions, the length is constant NUM_SIGS
- (int)getSignalAction:(int)signal;
- (id)initWith:(SigHandler *)sigHandlerFromParent;
- (id)init;
@end
