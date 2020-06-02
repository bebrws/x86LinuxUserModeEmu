//
//  main.m
//  CmdLineTest
//
//  Created by Brad Barrows on 3/22/20.
//  Copyright © 2020 bbarrows. All righrts reserved.
//

#import <Foundation/Foundation.h>


#include <dirent.h>
#include <errno.h>
#include <signal.h>

#import "AppDelegate.h"
#import "FileSystem.h"
#import "Task.h"
#import "ArgArgs.h"
#import "EnvArgs.h"
#import "Globals.h"
#import "FakeFSStore.h"
#import "log.h"


void main_sigusr1_handler() {
}

static void establish_signal_handlers() {
    extern void sigusr1_handler(int sig);
    struct sigaction sigact;
    sigact.sa_handler = main_sigusr1_handler;
    sigact.sa_flags = 0;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGUSR1);
    sigaction(SIGUSR1, &sigact, NULL);
    signal(SIGPIPE, SIG_IGN);
}


int main(int cargc, const char * cargv[]) {
    @autoreleasepool {
        // insert code here...
        NSLog(@"Running from main.m");
    
        
        // pids = [[NSMutableArray alloc] initWithCapacity:MAX_PID];
        pids = [NSMutableDictionary new];
        
        NSArray *alpineDataPathArray = [NSArray arrayWithObjects:[NSBundle mainBundle].resourcePath, @"alpine", @"data", nil];
        NSString* alpineDataPath = [NSString pathWithComponents:alpineDataPathArray];

        FFLog(@"Alpine base data dir file path is %@", alpineDataPath);
        DIR* dir = opendir([alpineDataPath UTF8String]);
        if (dir) {
            /* Directory exists. */
            closedir(dir);
        } else if (ENOENT == errno) {
            /* Directory does not exist. */
            die("Directory contianing the alpine FS is missing");
        } else {
            /* opendir() failed for some other reason. */
            die("Opendir() failed for some other reason");
        }
        

        
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
    
        
        ArgArgs *argv1 = [[ArgArgs alloc] initWithArgs:@[@"/sbin/init"]];
        EnvArgs *env1 = [[EnvArgs alloc] initWithArgs:@{@"TERM": @"xterm-256color"}];
        int err1 = [initTask doExecve:@"/sbin/init" argv:argv1 envp:env1];
        if (err1) {
            die("Failed to exec P1");
        }
        
        
        Task *loginTask = [[Task alloc] initWithParentTask:initTask];
        loginTask->clear_tid = 0;
        loginTask->vfork = NULL;
        // loginTask->blocked = loginTask->pending = loginTask->waiting = 0;
        ArgArgs *argv2 = [[ArgArgs alloc] initWithArgs:@[@"/bin/login", @"-f", @"root"]];
        EnvArgs *env2 = [[EnvArgs alloc] initWithArgs:@{@"TERM": @"xterm-256color"}];
        int err2 = [loginTask doExecve:@"/bin/login" argv:argv2 envp:env2];
        if (err2) {
            die("Failed to exec P2");
        }
                         
                
                         
        printf("BEB Starting init task\n");
        [initTask start]; // This is task_start in ish
        printf("BEB Starting login task\n");
        [loginTask start];
                         
//        [initTask doExecve:@"/bin/firstTest" argv:argv envp:env];
        
        // This is task_start in task.c and spawns a thread running the main execution/interp loop
        // where the linux executabe is translated/interp
        
        
        while(1) {
            // [[NSThread mainThread] sleep]
            [NSThread sleepForTimeInterval:1];
            NSLog(@"Main thread after sleep");
        }
    }
    
    return 0;
}
