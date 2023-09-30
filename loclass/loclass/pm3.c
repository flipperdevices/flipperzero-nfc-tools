

#include "pm3.h"
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <time.h> // Mingw



void hex_to_buffer(const uint8_t *buf, const uint8_t *hex_data, const size_t hex_len, const size_t hex_max_len,
                   const size_t min_str_len, const size_t spaces_between, bool uppercase) {

    if (buf == NULL) return;

    char *tmp = (char *)buf;
    size_t i;
    memset(tmp, 0x00, hex_max_len);

    size_t max_len = (hex_len > hex_max_len) ? hex_max_len : hex_len;

    for (i = 0; i < max_len; ++i, tmp += 2 + spaces_between) {
        sprintf(tmp, (uppercase) ? "%02X" : "%02x", (unsigned int) hex_data[i]);

        for (size_t j = 0; j < spaces_between; j++)
            sprintf(tmp + 2 + j, " ");
    }

    i *= (2 + spaces_between);

    size_t mlen = min_str_len > i ? min_str_len : 0;
    if (mlen > hex_max_len)
        mlen = hex_max_len;

    for (; i < mlen; i++, tmp += 1)
        sprintf(tmp, " ");

    // remove last space
    *tmp = '\0';
    return;
}

char *sprint_hex(const uint8_t *data, const size_t len) {
    static char buf[UTIL_BUFFER_SIZE_SPRINT - 3] = {0};
    hex_to_buffer((uint8_t *)buf, data, len, sizeof(buf) - 1, 0, 1, true);
    return buf;
}


