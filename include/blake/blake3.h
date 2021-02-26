
#include <stdint.h>
#include <stdlib.h>

/* visibility */
#ifdef BUILD_BLAKE3
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__)
        #ifdef BUILD_BLAKE3_DLL
            #define NC_BLAKE3_API __declspec(dllexport)
        #else
            #define NC_BLAKE3_API
        #endif
    #elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define NC_BLAKE3_API __attribute__ ((visibility("default")))
    #else
        #define NC_BLAKE3_API
    #endif
#else /* not BUILD_BLAKE3 */
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__)
        #ifdef BUILD_BLAKE3_DLL
            #define NC_BLAKE3_API __declspec(dllimport)
        #else
            #define NC_BLAKE3_API
        #endif
    #else
        #define NC_BLAKE3_API
    #endif
#endif /* end BUILD_BLAKE3 */


enum nc_blake3_constant
{
    NC_BLAKE3_BLOCK_BYTES    = 64,
    NC_BLAKE3_CHUNK_BYTES    = 1024,
    NC_BLAKE3_DIGEST_BYTES   = 32, 
    NC_BLAKE3_KEY_BYTES      = 32, 
    NC_BLAKE3_SALT_BYTES     = 8, 
    NC_BLAKE3_PERSONAL_BYTES = 8,
    NC_BLAKE3_MAX_DEPTH      = 54
};


#define BIT(x) (1 << (x))
enum nc_blake3_domain_flag
{
    NC_BLAKE3_CHUNK_START           = BIT(0), 
    NC_BLAKE3_CHUNK_END             = BIT(1), 
    NC_BLAKE3_PARENT                = BIT(2), 
    NC_BLAKE3_ROOT                  = BIT(3), 
    NC_BLAKE3_KEYED_HASH            = BIT(4), 
    NC_BLAKE3_DERIVE_KEY_CONTEXT    = BIT(5), 
    NC_BLAKE3_DERIVE_KEY_MATERIAL   = BIT(6)
};
#undef BIT

struct nc_blake3_chunk 
{
    uint32_t h[8];
    uint32_t chunk_counter;
    uint8_t  buf[NC_BLAKE3_BLOCK_BYTES];
    uint32_t buflen;
    uint8_t  blocks_compressed;
    uint8_t  flags;
};

struct nc_blake3_state
{
    uint32_t key[8];
    struct nc_blake3_chunk chunk;
    uint8_t  cv_stacklen;
    uint8_t  cv_stack[NC_BLAKE3_MAX_DEPTH * NC_BLAKE3_DIGEST_BYTES];
};


/* phase API */
NC_BLAKE3_API int nc_blake3_init (struct nc_blake3_state *s, size_t digestlen);
NC_BLAKE3_API int nc_blake3_update(struct nc_blake3_state *s, const void *in, const size_t len);
NC_BLAKE3_API int nc_blake3_final();

/* simple API */
NC_BLAKE3_API int nc_blake3();


/* test functions */
void test_print_iv (void);