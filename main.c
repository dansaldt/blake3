#include <stdio.h>
#include <string.h>
#include "include/blake/blake3.h"

int main (int argc, char **argv) 
{
    struct nc_blake3_state s;
    int res = 0;

//    const char *msg = "abc";
//    const size_t len = 3;

    char buf[65536];
    memset(buf, 0, sizeof(buf));
    size_t len;

    res = nc_blake3_init(&s, NC_BLAKE3_DIGEST_BYTES);

    FILE *fp = fopen("LoremIpsum", "r");
    if (fp) {
        size_t sz = sizeof(buf[0]);
        size_t count = (sizeof(buf) / sz) - 1;
        while ( fread(buf, sz, count, fp) != 0 ) {
            len = strlen(buf);
            res = nc_blake3_update(&s, buf, len);
        }
        res = nc_blake3_final(&s);
    }
    fclose(fp);

    return res;
}