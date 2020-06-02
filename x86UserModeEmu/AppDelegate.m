//
//  AppDelegate.m
//  x86UserModeEmu
//
//  Created by bradbarrows on 2/15/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//
#include <signal.h>

#import "AppDelegate.h"
#import "FileSystem.h"
#import "Task.h"
#import "ArgArgs.h"
#import "EnvArgs.h"
#import "Globals.h"
#import "FakeFSStore.h"
#import "log.h"


@interface AppDelegate ()

@end

@implementation AppDelegate

void app_sigusr1_handler() {
}

static void establish_signal_handlers() {
    extern void sigusr1_handler(int sig);
    struct sigaction sigact;
    sigact.sa_handler = app_sigusr1_handler;
    sigact.sa_flags = 0;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGUSR1);
    sigaction(SIGUSR1, &sigact, NULL);
    signal(SIGPIPE, SIG_IGN);
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    
    
    CPUStepLock = [[NSLock alloc] init];
    // pids = [[NSMutableArray alloc] initWithCapacity:MAX_PID];
    pids = [NSMutableDictionary new];
    
    // Insert code here to initialize your application
    NSArray *alpinePathArray = [NSArray arrayWithObjects:[NSBundle mainBundle].resourcePath, @"alpine", nil];
    NSString* alpineBasePath = [NSString pathWithComponents:alpinePathArray];
    
    FFLog(@"Alpine bases path is %@", alpineBasePath);
    
    const char *csAlpinePath = [alpineBasePath UTF8String];
    
    DIR* dir = opendir(csAlpinePath);
    if (dir) {
        /* Directory exists. */
        closedir(dir);
    } else if (ENOENT == errno) {
        /* Directory does not exist. */
        die("Directory contianing the alpine real FS is missing");
    } else {
        /* opendir() failed for some other reason. */
        die("Opendir() failed for some other reason on the alpine real FS dir");
    }
    
    
    NSArray *alpineDataPathArray = [NSArray arrayWithObjects:[NSBundle mainBundle].resourcePath, @"alpine", @"data", nil];
    NSString* alpineDataPath = [NSString pathWithComponents:alpineDataPathArray];
    const char *csAlpineDataPath = [alpineDataPath UTF8String];
    
    Task *initTask = [[Task alloc] initWithParentTask:NULL];
    
    FileSystem *fs = [[FileSystem alloc] init];
    [fs mountRoot:alpineDataPath currentTask:initTask];
    
    initTask.fs = fs;
    
    establish_signal_handlers();
    
    // Stack layout is
    // https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html
//    char argv[4096];
//    const char *envp = "TERM=xterm-256color\0";
//    NSString *init_command = @"/sbin/init";
    ArgArgs *argv = [[ArgArgs alloc] initWithArgs:@[@"/sbin/init"]];
    EnvArgs *env = [[EnvArgs alloc] initWithArgs:@{@"TERM": @"xterm-256color"}];
    int err = [initTask doExecve:@"/sbin/init" argv:argv envp:env];
//    [initTask doExecve:@"/bin/firstTest" argv:argv envp:env];
    
    if (err) {
        die("Failed to exec");
    }
    
    // This is task_start in task.c and spawns a thread running the main execution/interp loop
    // where the linux executabe is translated/interp
    [initTask start]; // This is task_start in ish
    
    
    Task *loginTask = [[Task alloc] initWithParentTask:initTask];
    loginTask->clear_tid = 0;
    // loginTask->vfork = nil;
    // loginTask->blocked = loginTask->pending = loginTask->waiting = 0;
    ArgArgs *argv2 = [[ArgArgs alloc] initWithArgs:@[@"/bin/login", @"-f", @"root"]];
    EnvArgs *env2 = [[EnvArgs alloc] initWithArgs:@{@"TERM": @"xterm-256color"}];
    int err2 = [loginTask doExecve:@"/bin/login" argv:argv2 envp:env2];
    if (err2) {
        die("Failed to exec P2");
    }
                     
                     
     printf("BEB Starting login task\n");
     [loginTask start];
                     
    
    
//    NSString *p=@"////test/p/d/s";
//    NSString *t = [p stringByDeletingLastPathComponent];
//    NSArray<NSString *> *cs = [p pathComponents];
//
//    NSString *p2=@"/../test/p/d/s";
//    NSString *t2 = [p2 stringByDeletingLastPathComponent];
//    NSArray<NSString *> *cs2 = [p2 pathComponents];
//
//    NSString *p3=@"../test/p/d/s";
//    NSString *t3 = [p3 stringByDeletingLastPathComponent];
//    NSArray<NSString *> *cs3 = [p3 pathComponents];
//
//    NSString *p4=@"..///test/p/d/s";
//    NSString *t4 = [p4 stringByDeletingLastPathComponent];
//    NSArray<NSString *> *cs4 = [p4 pathComponents];
    
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
}


@end
