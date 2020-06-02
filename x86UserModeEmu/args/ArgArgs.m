//
//  NSObject+ExecArgs.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/12/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "ArgArgs.h"
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import "log.h"


@implementation ArgArgs

-(void)dealloc
{
    FFLog(@"In ExecArgs dealloc");
    if (self->argsCString) {
        free(self->argsCString);
    }
}

- (int)count {
    return [self.args count];
}

- (id)clone {
    ArgArgs *newArgs = [[ArgArgs alloc] initWithArgs:self.args];
    return newArgs;
}

- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.args = [NSMutableArray new];
    
    char endString = '\0';
    self->argsCString = malloc(sizeof(endString));
    memcpy(self->argsCString, &endString, sizeof(endString));
    
    return self;
}

- (id)initWithArgs:(NSArray *)args {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.args = [NSMutableArray arrayWithArray:args];

    [self _updateArgsString];
    
    return self;
}

- (void)_updateArgsString {
    if (self->argsCString) {
        free(self->argsCString);
    }
    
    int len = [self getArgStringLength];
    self->argsCString = malloc(sizeof(char) * len + 1);
    FFLog(@"Allocated %d", len);
    [self _writeArgvStringTo:self->argsCString];
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

- (void)_writeArgvStringTo:(char *)dest {
    for (NSString *arg in self.args) {
        int writeLen = [arg length];
        memcpy(dest, [arg UTF8String], writeLen);
        dest += writeLen;
        
        *dest = '\0';
        dest++;
    }
    *dest = '\0';
}

- (int)getArgStringLength {
    int len = 0;
    for (NSString *arg in self.args) {
        len += arg.length + 1;
    }
    if (len) {
        len += 1; // for the last '\0';
    }
    return len;
}

- (NSString *)asString {
    NSString *argString = @"";
    for (NSString *arg in self.args) {
        argString=[NSString stringWithFormat:@"%@ %@", argString, arg];
    }
    
    return argString;
}

- (void)addArgToFront:(NSString *)arg {
    [self.args insertObject:arg atIndex:0];
    [self _updateArgsString];
}

- (void)addArgToEnd:(NSString *)arg {
    [self.args insertObject:arg atIndex:self.args.count];
    [self _updateArgsString];
}

- (NSString *)argAtIndex:(NSUInteger)index {
    return [self.args objectAtIndex:index];
}

@end
