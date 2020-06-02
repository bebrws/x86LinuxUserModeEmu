//
//  main.c
//  float
//
//  Created by Brad Barrows on 5/2/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#include <stdio.h>
#include "float80.h"


//typedef struct {
//    uint64_t signif;
//    union {
//        uint16_t signExp;
//        struct {
//            unsigned exp:15;
//            unsigned sign:1;
//        };
//    };
//} float80;

typedef struct {
    union {
        float80 f;
        long double d;
    };
} ld;


int main(int argc, const char * argv[]) {
    // insert code here...
    printf("Float comparisons\n");
    
    float80 f = f80_from_int(7);

    ld seven = { 7.0f };
    
    
    printf("biased 63: %d\n", bias(63));
    
    
    printf("%llu == %llu\n" ,f.signif, seven.f.signif);
    printf("sizes %d == %d\n", sizeof(float80), sizeof(long double));
    
    printf("float80:\n");
    print_struct_binary((void *)&f, 10, true);
    // 0000000000000000000000000000000000000000000000000000000000000111 1000000000000010
    // 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000111 10000000 00000010
    printf("f.signif: %llu\n", f.signif);
    print_struct_binary((void *)&f.signif, 8, true);
    printf("f.exp: %lu\n", f.exp);
    print_struct_binary((void *)&f.signExp, 2, true);
    printf("f.sign: %d\n", f.sign);
    
    
    printf("float80 no normalize test:\n\n");
    
    f.signif=7;
    f.exp=16446;
    f.sign=0;
    f = f80_normalize(f);
    printf("double: %f\n", f80_to_double(f));
    // print_struct_binary((void *)&seven, sizeof(long double), true);
    
    
    printf("\n\n\nbbfloat80:\n\n");
    float80 bf = f80_from_int(7);
    debug_print_bbfloat80(bf);
    
    
    return 0;
}
