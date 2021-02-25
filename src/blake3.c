
#include "../include/blake/blake3.h"

#include <stdio.h>
#include <string.h>


static const uint32_t blake3_iv[] = 
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint8_t blake3_message_schedule[7][16] =
{
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};


static inline uint32_t get_uint32 (const void *src)
{
    return *((uint32_t *)src);
}

static inline void blake3_init_chunks (struct nc_blake3_state *s)
{
    // TODO
}

static inline void blake3_init_base (
            struct nc_blake3_state *s, const uint32_t key[8], const uint8_t flags)
{
    memset(s, 0, sizeof(struct nc_blake3_state));

    memcpy(s->key, key, NC_BLAKE3_KEY_BYTES);
    blake3_init_chunks(s);
    
    s->cv_stacklen=0;
}

static inline void blake3_compress(
            struct nc_blake3_state *s, const uint8_t block[NC_BLAKE3_BLOCK_BYTES])
{
    uint32_t m[16];
    uint32_t v[16];

    size_t i;

    // TODO
    //for (i = 0; i < 16; ++i)
    //    m[i] = get_uint32( block + i * sizeof(m[i]) );

    //for (i = 0; i < 8; ++i) 
    //    v[i] = s->h[i];
    
}

int nc_blake3_init (struct nc_blake3_state *s, size_t digestlen)
{
    /* bad func args */
    if ( !s || digestlen == 0 || digestlen > NC_BLAKE3_DIGEST_BYTES )
        return -1;

    blake3_init_base(s, blake3_iv, 0);

    // TODO

    return 0; 
}

int nc_blake3_update(struct nc_blake3_state *s, const char *in, const size_t len)
{
    // TODO

    return 0;
}

void test_print_iv (void)
{
    for (int i = 0; i < sizeof(blake3_iv)/sizeof(uint32_t); i++) {

        printf("%08x\n", blake3_iv[i]);
    }
    
}