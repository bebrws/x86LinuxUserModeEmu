//
//  ViewController.m
//  x86UserModeEmu
//
//  Created by bradbarrows on 2/15/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#define UPDATE_INTERVAL_IN_SECONDS 0.1

#import "ViewController.h"

//#import "init.h"

#import "Globals.h"
#import "Task.h"
#import "Pid.h"

typedef void (^UpdateBlock)(void);

void repeat_block(void *vcc) {
    UpdateBlock updateBlock = ^{
        NSMutableString *updateInfo = [NSMutableString stringWithString:@""];
        NSArray *keys = [pids allKeys];
        for (NSString *k in keys) {
            Pid *p = pids[k];
            [updateInfo appendString:[NSString stringWithFormat:@"Pid: %@ Insn # %d  \n", k, p.task.cpu->instructionCount]];
            [updateInfo appendString:[p.task.cpu description]];
            [updateInfo appendString:@"\n"];
        }
        
        ViewController *v = (__bridge ViewController *)vcc;
        v.EmuInfoTextField.stringValue = updateInfo;
        
        repeat_block(vcc);
    };
    

    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, UPDATE_INTERVAL_IN_SECONDS * NSEC_PER_SEC), dispatch_get_main_queue(), updateBlock);
}


@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    repeat_block((__bridge void *)self);
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}


@end
