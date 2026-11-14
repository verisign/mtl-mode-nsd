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
#include <string.h>

PQC_DNSSEC_ALGOS sig_algos[] = {
    {"ML-DSA-44",                         18, ALGO_LIBOQS, ENABLED, 1312, 16},
    {"ML-DSA-65",                        100, ALGO_LIBOQS, ENABLED, 1952, 24},
    {"ML-DSA-87",                        101, ALGO_LIBOQS, ENABLED, 2592, 32},
    {"SLH_DSA_PURE_SHA2_128S",           102, ALGO_LIBOQS, ENABLED,  128, 16},
    {"SLH_DSA_PURE_SHAKE_128S",          103, ALGO_LIBOQS, ENABLED,  128, 16},
    {"ML-DSA-44-MTL-SHAKE-128",          118, ALGO_MTLLIB, ENABLED, 1312, 16},
    {"ML-DSA-65-MTL-SHAKE-192",          110, ALGO_MTLLIB, ENABLED, 1952, 24},
    {"ML-DSA-87-MTL-SHAKE-256",          111, ALGO_MTLLIB, ENABLED, 2592, 32},
    {"SLH-DSA-SHA2-128s-MTL-SHA2-128",   112, ALGO_MTLLIB, ENABLED,  128, 16},
    {"SLH-DSA-SHAKE-128s-MTL-SHAKE-128", 113, ALGO_MTLLIB, ENABLED,  128, 16},
    {NULL, 0, ALGO_NONE, DISABLED, 0, 0}};

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

        sibling_count = ntohs(*(uint16_t *)(rdata_atom_data(rr->rdatas[8]) + header_len));

        /* Each sibling is 16 bytes, skipping them
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

/**
 * Check if a Sigtag handle matches the full signature
 * @param signed_ladder the signed ladder potion of the rrsig record
 * @param signed_ladder_len the length of the signed ladder potion of the rrsig record
 * @param edns the edns option record that contains the sigtags
 * @param leaf_index the leaf index of the condensed signature
 * @return 1 if handle matches the ladder, 0 otherwise
 */
uint8_t val_algo_sigtag_match(uint8_t* signed_ladder, size_t signed_ladder_len, edns_record_type* edns, uint64_t leaf_index) {
    uint8_t match_found = 0;

    if((signed_ladder == NULL) || (edns == NULL) || (signed_ladder_len == 0)) {
        // Inavlid configuration so no match
        return 0;
    }

    #ifdef MTL_MODE_FULL_CODE
    // Find the SID and max rung value for this ladder
    if(signed_ladder_len > 36) {
        buffer_type full_sig;
        buffer_create_from(&full_sig, signed_ladder, signed_ladder_len);
        
        // Process the signed ladder header
        buffer_skip(&full_sig, 2);
        uint8_t* sid = buffer_current(&full_sig);
        buffer_skip(&full_sig, 32);						
        uint16_t rung_count = buffer_read_u16(&full_sig);

        // Seek the largest rung right value
        uint64_t max_right = 0;
        for(int i=0; i<rung_count; i++) {
            buffer_skip(&full_sig, 8);
            uint64_t rung_val = buffer_read_u64(&full_sig);
            buffer_skip(&full_sig, 16);
            if(rung_val > max_right)
                max_right = rung_val;
        }

        // Check if this SID and rung are within the range
        for(int i=0; i<MAX_SIG_TAGS*2; i++) {
            if((edns->sigtags_list[i].sid_length != 0) && 
                (memcmp(sid, edns->sigtags_list[i].sid, 32) == 0) &&
                (edns->sigtags_list[i].max_ladder_index <= max_right) && 
                (edns->sigtags_list[i].max_ladder_index >= leaf_index)) {
                    // When is the handle ok and the client doesn't need a new signature?
                    //   1. When the SID matches and the max index matches
                    //     or
                    //   2. When the SID matches and
                    //      the max index of the handle is less than the current ladder and 
                    //      the leaf index is less than or equal to the max index of the handle
                    //      (e.g. this condensed signature falls within the cached ladder even though it reaches beyond it to a new ladder)				
                    match_found = 1;
            }
        }

        // If there was no match need to not return 1, but if edns sigtag is enabled 
        // save this ladder in the edns list so that future requests are condensed (deuplicated)
        if ((match_found != 1) && 
            (edns->sigtag_enabled)) {
            for (int i=0; i<MAX_SIG_TAGS*2; i++) {
                if (edns->sigtags_list[i].sid_length == 0) {
                    edns->sigtags_list[i].max_ladder_index = max_right;
                    memcpy(edns->sigtags_list[i].sid, sid, 32);
                    edns->sigtags_list[i].sid_length = 32;
                    break;
                }
            }          
        }

    }
    #endif
    return match_found;
}

/**
 * Get the Leaf index from a condensed signature
 * @param rr rr_type resource record
 * @param leaf_index leaf index identified in the record
 * @return 0 on success, value for error
 */
uint8_t val_algo_get_leaf_index_from_condensed(rr_type* rr, uint64_t* leaf_index)
{
    #ifdef MTL_MODE_FULL_CODE
    size_t sig_len = 0;
    buffer_type signature;
    #endif

    // Verify the parameters are not NULL
    if((rr == NULL)||(leaf_index == NULL)) {
        return MTL_NULL_PARAMETERS;
    }

    // Default the index to 0
    *leaf_index = 0;

    #ifdef MTL_MODE_FULL_CODE
        if(val_algo_get_condensed_size(rr, &sig_len) != 0) {
            return MTL_BUFFER_ERROR;
        }

        if(sig_len >= 58) {
            buffer_create_from(&signature, rdata_atom_data(rr->rdatas[8]), sig_len);
            uint8_t* ptr =  rdata_atom_data(rr->rdatas[8]);
            buffer_skip(&signature, 51); // 1 byte for DNS flag and 50 bytes for sig-header
            *leaf_index = buffer_read_u64(&signature);   
        }
    #endif

    return MTL_OK;
}
