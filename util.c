#include <stdio.h>
#include <stdint.h>

void parse_hex_str(const char *hex, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2*i, "%2hhx", &out[i]);
    }
}