
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

static inline void store32 (void *dest, const uint32_t val)
{
    *((uint32_t *)dest) = val;
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

static inline void compress_core (
        uint32_t v[16], uint32_t cv[8], const uint8_t *block, const size_t blocklen,
        const uint64_t block_counter, const uint8_t flags)
{
    uint32_t m[16];

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

}

static inline void compress_in_place (
            uint32_t cv[8], const uint8_t *block, const size_t blocklen,
            const uint64_t block_counter, const uint8_t flags)
{
    uint32_t v[16];
    size_t i;

    compress_core(v, cv, block, blocklen, block_counter, flags);

    for (i = 0; i < 8; ++i)
        cv[i] = v[i] ^ v[i+8];
}

static inline void compress_xof (
            uint32_t cv[8], const uint8_t *block, const size_t blocklen, 
            const uint64_t block_counter, const uint8_t flags, uint8_t out[64])
{
    uint32_t v[16];

    compress_core(v, cv, block, blocklen, block_counter, flags);

    store32(&out[0 * 4], v[0] ^ v[8]);
    store32(&out[1 * 4], v[1] ^ v[9]);
    store32(&out[2 * 4], v[2] ^ v[10]);
    store32(&out[3 * 4], v[3] ^ v[11]);
    store32(&out[4 * 4], v[4] ^ v[12]);
    store32(&out[5 * 4], v[5] ^ v[13]);
    store32(&out[6 * 4], v[6] ^ v[14]);
    store32(&out[7 * 4], v[7] ^ v[15]);
    store32(&out[8 * 4], v[8] ^ cv[0]);
    store32(&out[9 * 4], v[9] ^ cv[1]);
    store32(&out[10 * 4], v[10] ^ cv[2]);
    store32(&out[11 * 4], v[11] ^ cv[3]);
    store32(&out[12 * 4], v[12] ^ cv[4]);
    store32(&out[13 * 4], v[13] ^ cv[5]);
    store32(&out[14 * 4], v[14] ^ cv[6]);
    store32(&out[15 * 4], v[15] ^ cv[7]);
}

static inline uint8_t chunk_need_start_flag (struct nc_blake3_chunk_state *cs)
{
    if (cs->blocks_compressed == 0)
        return NC_BLAKE3_CHUNK_START;
    else
        return 0;
}

static inline uint8_t chunk_need_end_flag (struct nc_blake3_chunk_state *cs) {
    if (cs->blocks_compressed == 15)
        return NC_BLAKE3_CHUNK_END;
    else
        return 0;
}

static inline void chunk_init_key (struct nc_blake3_chunk_state *cs, const uint32_t key[8])
{
    xmemcpy(cs->cv, key, NC_BLAKE3_KEY_BYTES);
}

static inline void chunk_init (
            struct nc_blake3_chunk_state *cs, const uint32_t key[8], const uint8_t flags)
{
    chunk_init_key(cs, key);
    cs->counter = 0;
    xmemset(cs->buf, 0, NC_BLAKE3_BLOCK_BYTES);
    cs->buflen = 0;
    cs->blocks_compressed = 0;
    cs->flags = flags;
}

static inline size_t chunk_update (
            struct nc_blake3_state *s, const uint8_t *in, const size_t len)
{
    size_t bytes_compressed, left;
    bytes_compressed = left = 0;

    // not enough to compress one block, put to buffer and return
    if (s->chunk.buflen + len < NC_BLAKE3_BLOCK_BYTES) {
        xmemcpy((&s->chunk.buf) + s->chunk.buflen, in, len);
        s->chunk.buflen += len;
        return bytes_compressed;
    }

    // calculate bytes to be compressed
    do {
        left += NC_BLAKE3_BLOCK_BYTES;
    } while ( (left < len) && (left < NC_BLAKE3_CHUNK_BYTES) );

    // compress one block with last buffer
    if (s->chunk.buflen > 0) {
        size_t x = NC_BLAKE3_BLOCK_BYTES - s->chunk.buflen;
        xmemcpy(&s->chunk.buf[s->chunk.buflen], in, x);

        uint8_t flags = s->chunk.flags
                        | chunk_need_start_flag(&s->chunk)
                        | chunk_need_end_flag(&s->chunk);

        compress_in_place((uint32_t *)&s->chunk.cv, (const uint8_t *)&s->chunk.buf, NC_BLAKE3_BLOCK_BYTES,
                          s->chunk.counter, flags);
        s->chunk.blocks_compressed += 1;

        in   += x;
        left -= NC_BLAKE3_BLOCK_BYTES;
    }

    // compress blocks
    while (left) {
        xmemcpy(&s->chunk.buf, in, NC_BLAKE3_BLOCK_BYTES);
        uint8_t flags = s->chunk.flags
                        | chunk_need_start_flag(&s->chunk)
                        | chunk_need_end_flag(&s->chunk);

        compress_in_place((uint32_t *)&s->chunk.cv, (const uint8_t *)&s->chunk.buf, NC_BLAKE3_BLOCK_BYTES,
                          s->chunk.counter, flags);
        s->chunk.blocks_compressed += 1;

        in   += NC_BLAKE3_BLOCK_BYTES;
        left -= NC_BLAKE3_BLOCK_BYTES;
    }

    bytes_compressed = s->chunk.blocks_compressed * NC_BLAKE3_BLOCK_BYTES;

    if (s->chunk.blocks_compressed == 16) {
        s->chunk.counter += 1;
        s->chunk.blocks_compressed = 0;
    }

    return bytes_compressed;
}

/**
 * Updates the last chunk which was still in the buffer
 */
static inline size_t chunk_update_last (struct nc_blake3_state *s)
{
    size_t bytes_compressed = s->chunk.buflen;

    if (s->chunk.blocks_compressed == 0) {
        chunk_init_key(&s->chunk, s->key);
    }

    // set trailing buffer zero
    if (s->chunk.buflen < NC_BLAKE3_BLOCK_BYTES) {
        xmemset(&s->chunk.buf[s->chunk.buflen], 0, NC_BLAKE3_BLOCK_BYTES - s->chunk.buflen);
    }

    uint8_t flags = s->chunk.flags
                    | chunk_need_start_flag(&s->chunk)
                    | NC_BLAKE3_CHUNK_END;

    compress_in_place((uint32_t *)&s->chunk.cv, (const uint8_t *)&s->chunk.buf, s->chunk.buflen,
                      s->chunk.counter, flags);
    s->chunk.blocks_compressed += 1;
    s->chunk.buflen = 0;

    return bytes_compressed;
}

static inline void chunk_root_output (struct nc_blake3_state *s, uint32_t out[8])
{
    uint8_t buf64[64];
    struct nc_blake3_chunk_state *cs = &s->chunk;
    size_t nblock = 0, blocks= 0, compress_len = 0;

    // get number of blocks to be compressed
    do {
        compress_len += NC_BLAKE3_BLOCK_BYTES;
        blocks += 1;
    } while (compress_len < cs->buflen);

    // compress blocks time
    while (nblock < blocks) {
        compress_xof(cs->cv, cs->buf, cs->buflen, nblock, cs->flags | NC_BLAKE3_ROOT, buf64);
        nblock += 1;
    }
    
    xmemcpy(out, buf64, s->digestlen);
}

static inline void cv_push (struct nc_blake3_state *s, uint32_t cv[8])
{
    uint8_t *pcv = (uint8_t *) cv;

    memcpy(s->cv_stack + (s->cv_stacklen * 32), pcv, 32);
    s->cv_stacklen += 1;
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

    init_state(s, iv, 0);
    s->digestlen = digestlen;

    return 0; 
}

NC_BLAKE3_API int nc_blake3_update(struct nc_blake3_state *s, const void *in, const size_t len)
{
    /* bad func args */
    if ( !s || !in || len == 0 )
        return -1;

    uint8_t *in_bytes = (uint8_t *) in;
    size_t took, left = len;

    // TODO assuming only one chunk, change it to accept multiple chunks
    took = chunk_update(s, in_bytes, left);
    left -= took;

    cv_push(s, s->chunk.cv);

    if (left > 0) {
        in_bytes += took;
        xmemcpy(&s->chunk.buf, in_bytes, left);
        s->chunk.buflen = left;
    }

    return 0;
}

NC_BLAKE3_API int nc_blake3_final(struct nc_blake3_state *s)
{
    if ( !s )
        return -1;

    if (s->chunk.buflen > 0) {
        chunk_update_last(s);
        cv_push(s, s->chunk.cv);
    }

    chunk_root_output(s, (void *)&s->cv_stack);

    return 0;
}
