
#include "../include/blake/blake3.h"

#include <stdio.h>


static const uint32_t blake3_iv[] = 
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void test_print_iv (void)
{
    for (int i = 0; i < sizeof(blake3_iv)/sizeof(uint32_t); i++) {

        printf("%08x\n", blake3_iv[i]);
    }
    
}