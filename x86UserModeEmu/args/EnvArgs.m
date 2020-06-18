//
//  NSObject+ExecArgs.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/12/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "EnvArgs.h"
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import "log.h"

@implementation EnvArgs


-(void)dealloc {
    FFLog(@"In ExecArgs dealloc");
    free(self->argsCString);
}

- (id)clone {
    EnvArgs *newArgs = [[EnvArgs alloc] initWithArgs:self.args];
    return newArgs;
}

- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.args = [NSMutableDictionary new];
    
    return self;
}

- (id)initWithArgs:(NSDictionary *)args {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.args = [NSMutableDictionary dictionaryWithDictionary:args];

    [self _updateArgsString];
    
    return self;
}

- (void)_updateArgsString {
    int len = [self getArgStringLength];
    self->argsCString = malloc(sizeof(char) * len + 1);
    FFLog(@"Allocated %d", len);
    [self writeArgvStringTo:self->argsCString];
}

- (int)count {
    return [self.args count];
}

- (void)writeExecArgs:(struct exec_args *)ea {
    if (self.args.count) {
        ea->count = self.args.count;
        ea->args = self->argsCString;
    } else {
        ea->count = 0;
        ea->args = NULL;
    }
}

- (void)writeArgvStringTo:(char *)dest {
    for (NSString *key in self.args) {
        NSString *value = [self.args objectForKey:key];
        int writeLen = [key length];
        memcpy(dest, [key UTF8String], writeLen);
        dest += writeLen;
        
        //dest++;
        *dest = '=';
        
        dest++;
        writeLen = [value length];
        memcpy(dest, [value UTF8String], writeLen);
        dest += writeLen;
        dest++;
        *dest = '\0';
    }
    *dest = '\0';
}

- (int)getArgStringLength {
    int len = 1; // Start at 1 for the lst '\0';
    for (NSString *key in self.args) {
        NSString *argValue = [self.args objectForKey:key];
        len += key.length + 1 + argValue.length + 1;
    }
    return len;
}

- (NSString *)asString {
    NSString *env = @"";
    for (NSString *key in self.args) {
        NSString *value = [self.args objectForKey:key];
        env=[NSString stringWithFormat:@"%@%@=%@ ", env, key, value];
    }
    
    return env;
}

- (void)addKey:(NSString *)key value:(NSString *)value {
    [self.args setValue:value forKey:key];
    [self _updateArgsString];
}
- (void)valueFromKey:(NSString *)key {
    [self.args objectForKey:key];
}
- (void)removeKey:(NSString *)key {
    [self.args removeObjectForKey:key];
    [self _updateArgsString];
}
@end
