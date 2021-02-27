
#include "../include/blake/blake3.h"

#include <stdio.h>
#include <string.h>


#define xmemcpy(dest, src, len) memcpy(dest, src, len)
#define xmemset(dest, c, len)   memset(dest, c, len)


static const uint32_t iv[8] = 
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint8_t schedule[7][16] =
{
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    { 2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8},
    { 3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1},
    {10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6},
    {12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4},
    { 9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7},
    {11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13},
};


static inline uint32_t load32 (const void *src)
{
    return *((uint32_t *)src);
}

static inline uint32_t rotr32( const uint32_t w, const unsigned c )
{
    return ( w >> c ) | ( w << ( 32 - c ) );
}

static inline uint32_t counter_low (uint64_t counter)
{
    return ((uint32_t)counter);
}

static inline uint32_t counter_high (uint64_t counter)
{
    return ((uint32_t)(counter >> 32));
}

static inline void compress(
            uint32_t cv[8], const uint8_t *block, const size_t blocklen, 
            const uint64_t block_counter, const uint8_t flags)
{
    uint32_t m[16];
    uint32_t v[16];

    size_t i;

    for (i = 0; i < 16; ++i)
        m[i] = load32( block + i * sizeof(m[i]) );

    for (i = 0; i < 8; ++i) 
        v[i] = cv[i];

    v[ 8] = iv[0];
    v[ 9] = iv[1];
    v[10] = iv[2];
    v[11] = iv[3];

    v[12] = counter_low(block_counter);
    v[13] = counter_high(block_counter);

    v[14] = (uint32_t)blocklen;

    v[15] = flags;
    
#define Gi(r, i, a, b, c, d)                            \
    do {                                                \
        a = a + b + m[schedule[r][2*i+0]];              \
        d = rotr32(d ^ a, 16);                          \
        c = c + d;                                      \
        b = rotr32(b ^ c, 12);                          \
        a = a + b + m[schedule[r][2*i+1]];              \
        d = rotr32(d ^ a, 8);                           \
        c = c + d;                                      \
        b = rotr32(b ^ c, 7);                           \
    } while (0)

#define ROUND(r)                                        \
    do {                                                \
        Gi(r, 0, v[ 0], v[ 4], v[ 8], v[12]);           \
        Gi(r, 1, v[ 1], v[ 5], v[ 9], v[13]);           \
        Gi(r, 2, v[ 2], v[ 6], v[10], v[14]);           \
        Gi(r, 3, v[ 3], v[ 7], v[11], v[15]);           \
        Gi(r, 4, v[ 0], v[ 5], v[10], v[15]);           \
        Gi(r, 5, v[ 1], v[ 6], v[11], v[12]);           \
        Gi(r, 6, v[ 2], v[ 7], v[ 8], v[13]);           \
        Gi(r, 7, v[ 3], v[ 4], v[ 9], v[14]);           \
    } while (0)

    ROUND(0);
    ROUND(1);
    ROUND(2);
    ROUND(3);
    ROUND(4);
    ROUND(5);
    ROUND(6);

#undef ROUND
#undef Gi

    for (i = 0; i < 8; ++i) 
        cv[i] = cv[i] ^ v[i] ^ v[i + 8];
}

static inline void chunk_init (
            struct nc_blake3_chunk_state *cs, const uint32_t key[8], const uint8_t flags)
{
    xmemcpy(cs->cv, key, NC_BLAKE3_KEY_BYTES);
    cs->counter = 0;
    xmemset(cs->buf, 0, NC_BLAKE3_BLOCK_BYTES);
    cs->buflen = 0;
    cs->blocks_compressed = 0;
    cs->flags = flags;
}

static inline void chunk_update (
            struct nc_blake3_chunk_state *cs, const uint8_t *in, const size_t len)
{
    xmemcpy(cs->buf, in, len);
    cs->buflen   = len;
    cs->counter += 1;
}

static inline void chunk_output (struct nc_blake3_chunk_state *cs, uint32_t out[8])
{
    const uint8_t *pbuf = cs->buf;
    size_t i, nblocks = NC_BLAKE3_CHUNK_BYTES / NC_BLAKE3_BLOCK_BYTES; 

    for (i=0; i < nblocks; ++i) {
        compress((uint32_t *)&cs->cv, (pbuf + 0 * NC_BLAKE3_BLOCK_BYTES), 
            cs->buflen, cs->counter, cs->flags);
    }
    
    for (i = 0; i < 8; ++i) 
        out[i] = cs->cv[i];
    
}

static inline void init_state (
            struct nc_blake3_state *s, const uint32_t key[8], const uint8_t flags)
{
    xmemset(s, 0, sizeof(struct nc_blake3_state));

    xmemcpy(s->key, key, NC_BLAKE3_KEY_BYTES);
    chunk_init(&s->chunk, s->key, flags);
    
    s->cv_stacklen=0;
}

NC_BLAKE3_API int nc_blake3_init (struct nc_blake3_state *s, size_t digestlen)
{
    /* bad func args */
    if ( !s || digestlen == 0 || digestlen > NC_BLAKE3_DIGEST_BYTES )
        return -1;

    init_state(s, iv, NC_BLAKE3_CHUNK_START);
    s->digestlen = digestlen;

    return 0; 
}

NC_BLAKE3_API int nc_blake3_update(struct nc_blake3_state *s, const void *in, const size_t len)
{
    /* bad func args */
    if ( !s || !in || len == 0 )
        return -1;

    uint8_t *in_bytes = (uint8_t *) in;
    size_t left = len;

    while (left > NC_BLAKE3_CHUNK_BYTES) {

        // TODO
        chunk_update(&s->chunk, in, NC_BLAKE3_CHUNK_BYTES);

        in_bytes += NC_BLAKE3_CHUNK_BYTES;
        left     -= NC_BLAKE3_CHUNK_BYTES;
    }

    if (left > 0) {
        chunk_update(&s->chunk, in, left);
    }

    return 0;
}

NC_BLAKE3_API int nc_blake3_final(struct nc_blake3_state *s)
{
    if ( !s )
        return -1;

    size_t left = s->chunk.buflen;
    //if ( left > 0 ) {  // TODO commented just for the test
        s->chunk.flags |= NC_BLAKE3_CHUNK_END | NC_BLAKE3_ROOT;
        //xmemset((s->chunk.buf + left), 0, (NC_BLAKE3_CHUNK_BYTES - left));
        chunk_output(&s->chunk, (void *)&s->cv_stack);
    //}

    return 0;
}

void test_print_iv (void)
{
    for (size_t i = 0; i < sizeof(iv)/sizeof(uint32_t); i++) {

        printf("%08x\n", iv[i]);
    }
    
}