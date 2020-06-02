//
//  NSObject+ExecArgs.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/12/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <AppKit/AppKit.h>


#import <Foundation/Foundation.h>
#import "AnyArgs.h"


@class ArgArgs;

@interface ArgArgs : NSObject <AnyArgs> {
    char *argsCString;
    struct exec_args execArgsStruct;
}


@property (nonatomic, strong) NSMutableArray *args;

- (int)count;
-(void)dealloc;
- (id)init;
- (id)initWithArgs:(NSArray *)args;
//- (void)_updateArgsString;
- (void)writeExecArgs:(struct exec_args *)ea;
- (void)_writeArgvStringTo:(char *)dest;
- (int)getArgStringLength;
- (NSString *)asString;
- (void)addArgToFront:(NSString *)arg;
- (void)addArgToEnd:(NSString *)arg;
- (NSString *)argAtIndex:(NSUInteger)index;
- (id)clone;
@end
