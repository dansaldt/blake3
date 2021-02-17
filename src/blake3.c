
#include "../include/blake/blake3.h"

#include <stdio.h>
#include <string.h>


static const uint32_t blake3_iv[] = 
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};


static inline get_uint32 (const void *src)
{
    return *((uint32_t *)src);
}

static inline int blake3_init0 (nc_blake3_state_t *s)
{
    memset(s, 0, sizeof(nc_blake3_state_t));

    int i;
    for (i = 0; i < sizeof(blake3_iv)/sizeof(uint32_t); ++i) {
        s->h[i] = blake3_iv[i];
    }
    

    return 0;
}

int nc_blake3_init (nc_blake3_state_t *s, size_t digestlen)
{
    nc_blake3_param_t p[1];

    /* bad func args */
    if ( !s || digestlen == 0 || digestlen > NC_BLAKE3_DIGEST_BYTES )
        return -1;

    memset(p, 0, sizeof(p));

    p->digest_length = digestlen;
    p->fanout        = 2;           /* binary tree structure */
    p->depth         = 255;         /* unlimited tree depth */
    p->leaf_length   = 1024;        /* chunks w/ 1024 bytes */

    return nc_blake3_init_param(s, p); 
}

int nc_blake3_init_param (nc_blake3_state_t *s, nc_blake3_param_t *p)
{
    /* bad func args */
    if ( !s || !p ) return -1;

    int i;
    uint8_t *pp;

    blake3_init0(s);

    pp = (uint8_t *) p;
    for (i = 0; i < 8; ++i) {
        s->h[i] = get_uint32( pp + (sizeof(s->h[i]) * i) );
    }

    return 0;
}


void test_print_iv (void)
{
    for (int i = 0; i < sizeof(blake3_iv)/sizeof(uint32_t); i++) {

        printf("%08x\n", blake3_iv[i]);
    }
    
}