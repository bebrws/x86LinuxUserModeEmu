//
//  NSString+NSString_BinaryRepresentation.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 4/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (BinaryRepresentation)

+ (NSString *)binaryStringRepresentationOfInt:(long)value;
+ (NSString *)binaryStringRepresentationOfInt:(long)value numberOfDigits:(unsigned int)length chunkLength:(unsigned int)chunkLength;

@end

