//
//  SigAction.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "misc.h";
#import "Memory.h";


@interface SigAction : NSObject {
    @public addr_t handler;
    @public dword_t flags;
    @public addr_t restorer;
    @public sigset_t_ mask;
}

@end
