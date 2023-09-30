//-----------------------------------------------------------------------------
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
// Definitions for all the types of commands that may be sent over USB; our
// own protocol.
//-----------------------------------------------------------------------------

#ifndef __PM3_H
#define __PM3_H

#include <stddef.h>
#include <inttypes.h>

#define INFO stdout
#define WARNING stdout
#define SUCCESS stdout
#define ERR stdout
#define NORMAL stdout
#define INPLACE stdout
#define FAILED stdout

#ifdef DEBUG
#define PrintAndLogEx fprintf
#else
#define PrintAndLogEx while(0)
#endif

#define UTIL_BUFFER_SIZE_SPRINT 8193

char *sprint_hex(const uint8_t *data, const size_t len);

// Error codes                          Usages:

// Success, regular quit
#define PM3_SQUIT               2
// Success, transfer nonces            pm3:        Sending nonces back to client
#define PM3_SNONCES             1
// Success (no error)
#define PM3_SUCCESS             0

// Undefined error
#define PM3_EUNDEF             -1
// Invalid argument(s)                  client:     user input parsing
#define PM3_EINVARG            -2
// Operation not supported by device    client/pm3: probably only on pm3 once client becomes universal
#define PM3_EDEVNOTSUPP        -3
// Operation timed out                  client:     no response in time from pm3
#define PM3_ETIMEOUT           -4
// Operation aborted (by user)          client/pm3: kbd/button pressed
#define PM3_EOPABORTED         -5
// Not (yet) implemented                client/pm3: TBD place holder
#define PM3_ENOTIMPL           -6
// Error while RF transmission          client/pm3: fail between pm3 & card
#define PM3_ERFTRANS           -7
// Input / output error                 pm3:        error in client frame reception
#define PM3_EIO                -8
// Buffer overflow                      client/pm3: specified buffer too large for the operation
#define PM3_EOVFLOW            -9
// Software error                       client/pm3: e.g. error in parsing some data
#define PM3_ESOFT             -10
// Flash error                          client/pm3: error in RDV4 Flash operation
#define PM3_EFLASH            -11
// Memory allocation error              client:     error in memory allocation (maybe also for pm3 BigBuff?)
#define PM3_EMALLOC           -12
// File error                           client:     error related to file access on host
#define PM3_EFILE             -13
// Generic TTY error
#define PM3_ENOTTY            -14
// Initialization error                 pm3:        error related to trying to initialize the pm3 / fpga for different operations
#define PM3_EINIT             -15
// Expected a different answer error    client/pm3: error when expecting one answer and got another one
#define PM3_EWRONGANSWER      -16
// Memory out-of-bounds error           client/pm3: error when a read/write is outside the expected array
#define PM3_EOUTOFBOUND       -17
// exchange with card error             client/pm3: error when cant get answer from card or got an incorrect answer
#define PM3_ECARDEXCHANGE     -18

// Failed to create APDU,
#define PM3_EAPDU_ENCODEFAIL  -19
// APDU responded with a failure code
#define PM3_EAPDU_FAIL        -20

// execute pm3 cmd failed               client/pm3: when one of our pm3 cmd tries and fails. opposite from PM3_SUCCESS
#define PM3_EFAILED           -21
// partial success                      client/pm3: when trying to dump a tag and fails on some blocks.  Partial dump.
#define PM3_EPARTIAL          -22
// tearoff occurred                      client/pm3: when a tearoff hook was called and a tearoff actually happened
#define PM3_ETEAROFF          -23

// Got bad CRC                          client/pm3: error in transfer of data,  crc mismatch.
#define PM3_ECRC              -24

// No data                              pm3:        no data available, no host frame available (not really an error)
#define PM3_ENODATA           -98
// Quit program                         client:     reserved, order to quit the program
#define PM3_EFATAL            -99

#endif
