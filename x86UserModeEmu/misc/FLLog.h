//
//  NSObject+FLLog.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/13/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <AppKit/AppKit.h>


#import <Foundation/Foundation.h>

#define FLLog(args...) _FLL(@"DEBUG ", __FILE__,__LINE__,__PRETTY_FUNCTION__,args);
@interface FLL : NSObject
    void _FLL(NSString *prefix, const char *file, int lineNumber, const char *funcName, NSString *format,...);
@end
