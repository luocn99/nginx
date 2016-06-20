#include <stdio.h>
#include "common.h"

void print_hex(const unsigned char *src, int len)
{
    int i = 0;
    while (i < len) {
        printf("%02x", src[i]);
        i++;
    }

    printf("\n");
}
