/*
	Copyright (c) 2026, VeriSign, Inc.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted (subject to the limitations in the disclaimer
	below) provided that the following conditions are met:

		* Redistributions of source code must retain the above copyright notice,
		this list of conditions and the following disclaimer.

		* Redistributions in binary form must reproduce the above copyright
		notice, this list of conditions and the following disclaimer in the
		documentation and/or other materials provided with the distribution.

		* Neither the name of the copyright holder nor the names of its
		contributors may be used to endorse or promote products derived from this
		software without specific prior written permission.

	NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
	THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
	CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
	PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
	CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
	EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
	PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
	BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
	IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef __VAL_PQC_ALGO__
#define __VAL_PQC_ALGO__

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "namedb.h"

typedef enum DNSSEC_ALGO_TYPE
{
    ALGO_NONE,
    ALGO_OPENSSL,
    ALGO_LIBOQS,
    ALGO_MTLLIB,
    ALGO_OTHER,
} DNSSEC_ALGO_TYPE;

typedef enum DNSSEC_ALGO_STATE
{
    DISABLED = 0,
    ENABLED = 1,
} DNSSEC_ALGO_STATE;

typedef struct PQC_DNSSEC_ALGOS
{
    char *name;
    uint8_t number;
    DNSSEC_ALGO_TYPE library;
    DNSSEC_ALGO_STATE enabled;
    size_t raw_key_size;
    uint16_t sec_param;
} PQC_DNSSEC_ALGOS;

#define MTL_INDEX_LEN 8

#define MTL_OK 0
#define MTL_NULL_PARAMETERS 1
#define MTL_INVALID_RECORD 2
#define MTL_BUFFER_ERROR 3


/**
 * Get the PQC Algorithm properties by name
 * @param keystr Key string
 * @return PQC_DNSSEC_ALGOS Algorithm properties struct
 *                             (or NULL if not present)
 */
PQC_DNSSEC_ALGOS *val_algo_props(char *keystr);

/**
 * Get the PQC Algorithm properties by ID
 * @param algo Algorithm ID
 * @return PQC_DNSSEC_ALGOS Algorithm properties struct
 *                             (or NULL if not present)
 */
PQC_DNSSEC_ALGOS *val_algo_id_props(uint8_t algo);

/**
 * Get the PQC Algorithm properties by ID
 * @param algo Algorithm ID
 * @return 1 if is MTL algorithm or 0 if not
 */
int val_algo_is_mtl(uint8_t algo);

/**
 * Get the PQC Algorithm hash length value
 * @param algo Algorithm ID
 * @return size of hash in bytes
 */
size_t val_algo_get_hash_size(uint8_t algo);

/**
 * Get the PQC Algorithm condensed signature header offset
 * @param algo Algorithm ID
 * @return size of the header offset minus the sibiling hash size
 */
size_t val_algo_get_condensed_sig_header_size(uint8_t algo);

/**
 * Get the PQC Algorithm condensed signature size
 * @param rr rr_type resource record
 * @param sig_length pointer to size_t that is the length of the condensed signature
 * @return 0 on success, value for error
 */
uint8_t val_algo_get_condensed_size(rr_type* rr, size_t* sig_length);

#endif // __VAL_PQC_ALGO__