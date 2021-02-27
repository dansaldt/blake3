
#include "include/blake/blake3.h"

int main (int argc, char **argv) 
{
    struct nc_blake3_state s;
    int res = 0;

    const char *msg = "";

    res = nc_blake3_init(&s, NC_BLAKE3_DIGEST_BYTES);
    res = nc_blake3_update(&s, msg, 0);
    res = nc_blake3_final(&s);

    return res;
}