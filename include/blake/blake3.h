
#include <stdint.h>


typedef struct struct_nc_blake3_state
{
    uint8_t  h[8];
    uint32_t t[2];
    uint32_t b;
    uint32_t d;
}
nc_blake3_state;


/* phase API */
int nc_blake3_init();
int nc_blake3_update();
int nc_blake3_final();

/* simple API */
int nc_blake3();


/* test functions */
void test_print_iv (void);