
#include <stdint.h>
#include <stdlib.h>


enum nc_blake3_constant
{
    NC_BLAKE3_BLOCK_BYTES    = 64,
    NC_BLAKE3_DIGEST_BYTES   = 32, 
    NC_BLAKE3_KEY_BYTES      = 32, 
    NC_BLAKE3_SALT_BYTES     = 8, 
    NC_BLAKE3_PERSONAL_BYTES = 8
};


enum nc_blake3_domain_flag
{
    NC_BLAKE3_CHUNK_START           = (1 << 0), 
    NC_BLAKE3_CHUNK_END             = (1 << 1), 
    NC_BLAKE3_PARENT                = (1 << 2), 
    NC_BLAKE3_ROOT                  = (1 << 3), 
    NC_BLAKE3_KEYED_HASH            = (1 << 4), 
    NC_BLAKE3_DERIVE_KEY_CONTEXT    = (1 << 5), 
    NC_BLAKE3_DERIVE_KEY_MATERIAL   = (1 << 6)
};

typedef struct nc_blake3_state
{
    uint8_t  h[8];
    uint32_t t[2];
    uint32_t b;
    uint32_t d;
}
nc_blake3_state_t;

typedef struct nc_blake3_param
{
    uint8_t  digest_length;
    uint8_t  key_length;
    uint8_t  fanout;
    uint8_t  depth;
    uint32_t leaf_length;
    uint8_t  node_offset[6];
    uint8_t  node_depth;
    uint8_t  inner_length;
    uint8_t  salt[8];
    uint8_t  personal[8]; 
}
nc_blake3_param_t;



/* phase API */
int nc_blake3_init (nc_blake3_state_t *s, size_t digestlen);
int nc_blake3_init_param (nc_blake3_state_t *s, nc_blake3_param_t *p);
int nc_blake3_update();
int nc_blake3_final();

/* simple API */
int nc_blake3();


/* test functions */
void test_print_iv (void);