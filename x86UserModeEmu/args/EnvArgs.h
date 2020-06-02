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

@class EnvArgs;

@interface EnvArgs : NSObject <AnyArgs> {
    char *argsCString;
    struct exec_args execArgsStruct;
}


@property (nonatomic, strong) NSMutableDictionary *args;
- (int)count;
-(void)dealloc;
- (id)init;
- (id)initWithArgs:(NSDictionary *)args;
//- (void)_updateArgsString;
- (void)writeExecArgs:(struct exec_args *)ea;
- (void)writeArgvStringTo:(char *)dest;
- (int)getArgStringLength;
- (NSString *)asString;
- (void)addKey:(NSString *)key value:(NSString *)value;
- (void)valueFromKey:(NSString *)key;
- (void)removeKey:(NSString *)key;
- (id)clone;
@end
