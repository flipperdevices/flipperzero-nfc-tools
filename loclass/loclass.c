// Implementation from https://github.com/RfidResearchGroup/proxmark3.git

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "loclass/elite_crack.h"
#include "loclass/optimized_cipher.h"
#include "loclass/optimized_cipherutils.h"
#include "loclass/optimized_elite.h"
#include "loclass/optimized_ikeys.h"
#include "loclass/pm3.h"
#include "iclass_dump.h"

int main(int argc, char *argv[]) {
    uint16_t keytable[128] = {0};
    uint8_t first16bytes[16] = {0};
    uint8_t retval[8] = {0};

    uint8_t* buffer = iclass_dump_bin;
    uint32_t size = iclass_dump_bin_len;

    if(size == 0 || size % 24 != 0) {
      printf("Size must be a multiple of 24\n");
      return 1;
    }

    int res = bruteforceDump(buffer, size, keytable);
    if (res != PM3_SUCCESS) {
      printf("Failed to bruteforce\n");
      return 1;
    }

    for (size_t i = 0 ; i < 16 ; i++) {
      first16bytes[i] = keytable[i] & 0xFF;
    }

    calculateMasterKey(first16bytes, retval);

    printf("Expected: 5B7C62C491C11B39\n");

    printf("Key = ");
    for (size_t i = 0; i < sizeof(retval); i++) {
      printf("%02X", retval[i]);
    }
    printf("\n");

    return 0;
}
