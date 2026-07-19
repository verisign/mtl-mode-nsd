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
#include "val_pqc_algo.h"
#include "namedb.h"
#include <string.h>

PQC_DNSSEC_ALGOS sig_algos[] = {
    {"PQC_ALGO_FL_DSA_MTL_SHAKE",  128, ALGO_MTLLIB, ENABLED, 897, 16},
    {"PQC_ALGO_ML_DSA_MTL_SHAKE",  129, ALGO_MTLLIB, ENABLED, 1312, 16},
    {"PQC_ALGO_SLH_DSA_MTL_SHA2",  130, ALGO_MTLLIB, ENABLED, 128, 16},
    {"PQC_ALGO_SLH_DSA_MTL_SHAKE", 131, ALGO_MTLLIB, ENABLED, 128, 16},
    {"PQC_ALGO_MAYO1_MTL_SHAKE",   132, ALGO_MTLLIB, ENABLED, 1168, 16},
    {"PQC_ALGO_MAYO2_MTL_SHAKE",   133, ALGO_MTLLIB, ENABLED, 4912, 16},
    {"PQC_ALGO_SNOVA_MTL_SHAKE",   134, ALGO_MTLLIB, ENABLED, 1016, 16},
    {"PQC_ALGO_MAYO_1",            230, ALGO_LIBOQS, ENABLED, 1168, 0},
    {"PQC_ALGO_MAYO_2",            231, ALGO_LIBOQS, ENABLED, 4912, 0},
    {"PQC_ALGO_SNOVA",             232, ALGO_LIBOQS, ENABLED, 1016, 0},
    {"PQC_ALGO_HAWK",              234, ALGO_OTHER,  DISABLED, 0, 0}, 
    {"PQC_ALGO_SQISIGN",           233, ALGO_OTHER,  DISABLED, 0, 0},
    {"PQC_ALGO_FL_DSA",            244, ALGO_LIBOQS, ENABLED, 897, 0},
    {"PQC_ALGO_ML_DSA",            245, ALGO_LIBOQS, ENABLED, 1312, 0},
    {"PQC_ALGO_SLH_DSA_SHA2",      246, ALGO_LIBOQS, ENABLED, 128, 0},
    {"PQC_ALGO_SLH_DSA_SHAKE",     247, ALGO_LIBOQS, ENABLED, 128, 0},
    {NULL, 0, ALGO_NONE, DISABLED}};

/**
 * Get the PQC Algorithm properties by name
 * @param keystr Key string
 * @return PQC_DNSSEC_ALGOS Algorithm properties struct
 *                             (or NULL if not present)
 */
PQC_DNSSEC_ALGOS *val_algo_props(char *keystr)
{
    size_t algo_idx = 0;

    if(keystr == NULL) {
        return NULL;
    }

    // Find the appropriate algorithm
    while (sig_algos[algo_idx].name != NULL)
    {
        if ((strcmp(sig_algos[algo_idx].name, (char *)keystr) == 0) && 
            (sig_algos[algo_idx].enabled == ENABLED))
        {
            return &sig_algos[algo_idx];
        }
        algo_idx++;
    }
    return NULL;
}

/**
 * Get the PQC Algorithm properties by ID
 * @param algo Algorithm ID
 * @return PQC_DNSSEC_ALGOS Algorithm properties struct
 *                             (or NULL if not present)
 */
PQC_DNSSEC_ALGOS *val_algo_id_props(uint8_t algo)
{
    size_t algo_idx = 0;

    // Find the appropriate algorithm
    while (sig_algos[algo_idx].name != NULL)
    {
        if ((sig_algos[algo_idx].number == algo) && 
            (sig_algos[algo_idx].enabled == ENABLED))
        {
            return &sig_algos[algo_idx];
        }
        algo_idx++;
    }
    return NULL;
}

/**
 * Get the PQC Algorithm properties by ID
 * @param algo Algorithm ID
 * @return 1 if is MTL algorithm or 0 if not
 */
int val_algo_is_mtl(uint8_t algo)
{
    size_t algo_idx = 0;

    // Find the appropriate algorithm
    while (sig_algos[algo_idx].name != NULL)
    {
        if ((sig_algos[algo_idx].number == algo) && 
            (sig_algos[algo_idx].enabled == ENABLED) &&
            (sig_algos[algo_idx].library == ALGO_MTLLIB))
        {
            return 1;
        }
        algo_idx++;
    }
    return 0;
}

/**
 * Get the PQC Algorithm hash length value
 * @param algo Algorithm ID
 * @return size of hash in bytes
 */
size_t val_algo_get_hash_size(uint8_t algo) 
{
    PQC_DNSSEC_ALGOS* properties = val_algo_id_props(algo);

    if(properties) 
    {
        return properties->sec_param;
    }
    return 0;
}

/**
 * Get the PQC Algorithm condensed signature header offset
 * @param algo Algorithm ID
 * @return size of the header offset minus the sibiling hash size
 */
size_t val_algo_get_condensed_sig_header_size(uint8_t algo)
{
    size_t   condensed_len = 0;
    uint16_t hash_size = val_algo_get_hash_size(algo);

    if (hash_size > 0) 
    {   
        condensed_len = 2 * hash_size;  // SID (2x hash size)
        condensed_len += 2;             // Flags (2 bytes)
        condensed_len += hash_size;     // Randomizer (hash size) 
        condensed_len += MTL_INDEX_LEN; // Leaf Index (8 bytes)
        condensed_len += MTL_INDEX_LEN; // Target Left Index (8 bytes)
        condensed_len += MTL_INDEX_LEN; // Target Right Index (8 bytes)

        return condensed_len;
    }
    return 0;
}

/**
 * Get the PQC Algorithm condensed signature size
 * @param rr rr_type resource record
 * @param sig_length pointer to size_t that is the length of the condensed signature
 * @return 0 on success, value for error
 */
uint8_t val_algo_get_condensed_size(rr_type* rr, size_t* sig_length)
{
    // Verify the parameters are not NULL
    if((rr == NULL)||(sig_length == NULL)) {
        return MTL_NULL_PARAMETERS;
    }
    // Default the signature length to 0
    *sig_length = 0;

    #ifdef MTL_MODE_FULL_CODE
        uint16_t hash_size = 0;
        size_t   header_len = 0;
        size_t   buffer_size = 0;
        uint16_t sibling_count = 0;
        size_t   condensed_sig_size = 0;


        // Validate that the rr is the right type and has the right data fields
        if((rr->type != TYPE_RRSIG) ||
        (rr->rdata_count < 8) ||
        (!rr_rrsig_algorithm_mtl(rr))) {
            return MTL_INVALID_RECORD;
        }

        // Get the header_len plus 1 for the DNSSEC type.
        // The offset doesn't include sibiling count or hash data
        header_len = val_algo_get_condensed_sig_header_size(rr_rrsig_algorithm(rr)) + 1;
        hash_size = val_algo_get_hash_size(rr_rrsig_algorithm(rr));
        buffer_size = rdata_atom_size(rr->rdatas[8]);

        // The sibiling count is the next 2 bytes (if present)
        if(buffer_size < header_len + 2) {
            return MTL_BUFFER_ERROR;
        }

        sibling_count = ntohs(*(uint16_t*)(rdata_atom_data(rr->rdatas[8]) + header_len));

        /* Each sibling is hash_size bytes, skipping them 
        * skips the complete Authentication Path
        * and takes us to the remainder that needs
        * to be appended to the RRSIG signature data.
        */
        condensed_sig_size = header_len + 2 + (hash_size * sibling_count);

        if(buffer_size < condensed_sig_size) {
            return MTL_BUFFER_ERROR;
        }

        *sig_length = condensed_sig_size;
    #endif

    return MTL_OK;
}