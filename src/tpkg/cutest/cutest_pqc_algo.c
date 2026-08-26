/*
	test bitset.h
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "val_pqc_algo.h"
#include "tpkg/cutest/cutest.h"

static uint16_t* create_atom_type(uint16_t length, uint8_t* data) {
    uint8_t *buffer = calloc(1, length+2);

    memcpy(buffer, &length, sizeof(uint16_t));
    memcpy(buffer + 2, data, length);

    return (uint16_t*)buffer;
} 

static void get_condensed_size_valid_size(CuTest *tc) {
	rdata_atom_type temp_rdata[MAXRDATALEN];
    size_t cond_len = 75 + 2 + (6*16);
    size_t sig_len = 0;
    rr_type rr;
    rr.owner = NULL;    
    rr.ttl = 86400;
    rr.type = TYPE_RRSIG;
    rr.klass = CLASS_IN;
    rr.rdata_count = 8;
    rr.rdatas = &temp_rdata[0];

    uint8_t type_covered[] = {46, 00};
    uint8_t algorithm[] = {130};
    uint8_t labels[] = {2};
    uint8_t ttl[] = {0x00, 0x01, 0x51, 0x80};
    uint8_t blank[] = {0x00, 0x00, 0x00, 0x00};
    uint8_t key_tag[] = {0xaa, 0xaa};
    uint8_t signature[1024];
    memset(&signature[0], 0xff, 1024); 
    // Set the sibling count to 6
    signature[75] = 0x00;
    signature[76] = 0x06;

    // Type Covered (16-bit integer)
    temp_rdata[0].data = create_atom_type(2, &type_covered[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[0]) == 2);

    // Algorithm (8-bit integer)
    temp_rdata[1].data = create_atom_type(1, &algorithm[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[1]) == 1);

    // Labels (8-bit integer)
    temp_rdata[2].data = create_atom_type(1, &labels[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[2]) == 1);

    // Original TTL (32-bit integer)
    temp_rdata[3].data = create_atom_type(4, &ttl[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[3]) == 4);        

    //  Signature Expiration (32-bit integer)
    temp_rdata[4].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[4]) == 4);   

    // Signature Inception (32-bit integer)
    temp_rdata[5].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[5]) == 4); 

    // Key Tag (16-bit integer)
    temp_rdata[6].data = create_atom_type(2, &key_tag[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[6]) == 2);

    // Signers Name        - Domain Name
    temp_rdata[7].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[7]) == 4);  

    // Signature            - Binary Data
    temp_rdata[8].data = create_atom_type(cond_len, &signature[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[8]) == cond_len);  
    
    CuAssert(tc, "", val_algo_get_condensed_size(&rr, &sig_len) == 0);
    CuAssert(tc, "", sig_len == cond_len);  
    
    for(int i=0; i<9; i++) {
        free(temp_rdata[i].data);
    }
}


static void get_condensed_size_invalid_size(CuTest *tc) {
	rdata_atom_type temp_rdata[MAXRDATALEN];
    size_t cond_len = 75 + 2 + (6*16);
    size_t sig_len = 0;
    rr_type rr;
    rr.owner = NULL;    
    rr.ttl = 86400;
    rr.type = TYPE_RRSIG;
    rr.klass = CLASS_IN;
    rr.rdata_count = 8;
    rr.rdatas = &temp_rdata[0];

    uint8_t type_covered[] = {46, 00};
    uint8_t algorithm[] = {130};
    uint8_t labels[] = {2};
    uint8_t ttl[] = {0x00, 0x01, 0x51, 0x80};
    uint8_t blank[] = {0x00, 0x00, 0x00, 0x00};
    uint8_t key_tag[] = {0xaa, 0xaa};
    uint8_t signature[1024];
    memset(&signature[0], 0xff, 1024); 
    // Set the sibling count to 7 (one more than is in signature)
    signature[75] = 0x00;
    signature[76] = 0x07;

    // Type Covered (16-bit integer)
    temp_rdata[0].data = create_atom_type(2, &type_covered[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[0]) == 2);

    // Algorithm (8-bit integer)
    temp_rdata[1].data = create_atom_type(1, &algorithm[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[1]) == 1);

    // Labels (8-bit integer)
    temp_rdata[2].data = create_atom_type(1, &labels[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[2]) == 1);

    // Original TTL (32-bit integer)
    temp_rdata[3].data = create_atom_type(4, &ttl[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[3]) == 4);        

    //  Signature Expiration (32-bit integer)
    temp_rdata[4].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[4]) == 4);   

    // Signature Inception (32-bit integer)
    temp_rdata[5].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[5]) == 4); 

    // Key Tag (16-bit integer)
    temp_rdata[6].data = create_atom_type(2, &key_tag[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[6]) == 2);

    // Signers Name        - Domain Name
    temp_rdata[7].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[7]) == 4);  

    // Signature            - Binary Data
    temp_rdata[8].data = create_atom_type(cond_len, &signature[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[8]) == cond_len);  
    
    CuAssert(tc, "", val_algo_get_condensed_size(&rr, &sig_len) == 3);
    CuAssert(tc, "", sig_len == 0);  
    
    for(int i=0; i<9; i++) {
        free(temp_rdata[i].data);
    }    
}

static void get_condensed_size_invalid_header(CuTest *tc) {
	rdata_atom_type temp_rdata[MAXRDATALEN];
    size_t cond_len = 75 + 2 + (6*16);
    size_t sig_len = 0;
    rr_type rr;
    rr.owner = NULL;    
    rr.ttl = 86400;
    rr.type = TYPE_RRSIG;
    rr.klass = CLASS_IN;
    rr.rdata_count = 8;
    rr.rdatas = &temp_rdata[0];

    uint8_t type_covered[] = {46, 00};
    uint8_t algorithm[] = {130};
    uint8_t labels[] = {2};
    uint8_t ttl[] = {0x00, 0x01, 0x51, 0x80};
    uint8_t blank[] = {0x00, 0x00, 0x00, 0x00};
    uint8_t key_tag[] = {0xaa, 0xaa};
    uint8_t signature[1024];
    memset(&signature[0], 0xff, 1024); 
    // Set the sibling count to 7 (one more than is in signature)
    signature[75] = 0x00;
    signature[76] = 0x07;

    // Type Covered (16-bit integer)
    temp_rdata[0].data = create_atom_type(2, &type_covered[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[0]) == 2);

    // Algorithm (8-bit integer)
    temp_rdata[1].data = create_atom_type(1, &algorithm[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[1]) == 1);

    // Labels (8-bit integer)
    temp_rdata[2].data = create_atom_type(1, &labels[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[2]) == 1);

    // Original TTL (32-bit integer)
    temp_rdata[3].data = create_atom_type(4, &ttl[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[3]) == 4);        

    //  Signature Expiration (32-bit integer)
    temp_rdata[4].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[4]) == 4);   

    // Signature Inception (32-bit integer)
    temp_rdata[5].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[5]) == 4); 

    // Key Tag (16-bit integer)
    temp_rdata[6].data = create_atom_type(2, &key_tag[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[6]) == 2);

    // Signers Name        - Domain Name
    temp_rdata[7].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[7]) == 4);  

    // Signature            - Binary Data
    temp_rdata[8].data = create_atom_type(4, &signature[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[8]) == 4);  
    
    CuAssert(tc, "", val_algo_get_condensed_size(&rr, &sig_len) == 3);
    CuAssert(tc, "", sig_len == 0);  
    
    for(int i=0; i<9; i++) {
        free(temp_rdata[i].data);
    }    
}

static void get_other_record_type(CuTest *tc, uint16_t rrtype, uint16_t rr_count, uint8_t algo) {
	rdata_atom_type temp_rdata[MAXRDATALEN];
    size_t cond_len = 75 + 2 + (6*16);
    size_t sig_len = 0;
    rr_type rr;
    rr.owner = NULL;    
    rr.ttl = 86400;
    rr.type = rrtype;
    rr.klass = CLASS_IN;
    rr.rdata_count = rr_count;
    rr.rdatas = &temp_rdata[0];

    uint8_t type_covered[] = {46, 00};
    uint8_t algorithm[] = {algo};
    uint8_t labels[] = {2};
    uint8_t ttl[] = {0x00, 0x01, 0x51, 0x80};
    uint8_t blank[] = {0x00, 0x00, 0x00, 0x00};
    uint8_t key_tag[] = {0xaa, 0xaa};
    uint8_t signature[1024];
    memset(&signature[0], 0xff, 1024); 
    // Set the sibling count to 6
    signature[75] = 0x00;
    signature[76] = 0x06;

    // Type Covered (16-bit integer)
    temp_rdata[0].data = create_atom_type(2, &type_covered[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[0]) == 2);

    // Algorithm (8-bit integer)
    temp_rdata[1].data = create_atom_type(1, &algorithm[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[1]) == 1);

    // Labels (8-bit integer)
    temp_rdata[2].data = create_atom_type(1, &labels[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[2]) == 1);

    // Original TTL (32-bit integer)
    temp_rdata[3].data = create_atom_type(4, &ttl[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[3]) == 4);        

    //  Signature Expiration (32-bit integer)
    temp_rdata[4].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[4]) == 4);   

    // Signature Inception (32-bit integer)
    temp_rdata[5].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[5]) == 4); 

    // Key Tag (16-bit integer)
    temp_rdata[6].data = create_atom_type(2, &key_tag[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[6]) == 2);

    // Signers Name        - Domain Name
    temp_rdata[7].data = create_atom_type(4, &blank[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[7]) == 4);  

    // Signature            - Binary Data
    temp_rdata[8].data = create_atom_type(cond_len, &signature[0]);
    CuAssert(tc, "", rdata_atom_size(temp_rdata[8]) == cond_len);  
    
    CuAssert(tc, "", val_algo_get_condensed_size(&rr, &sig_len) == 2);
    CuAssert(tc, "", sig_len == 0);  
    
    for(int i=0; i<9; i++) {
        free(temp_rdata[i].data);
    }
}

static void call_null_params(CuTest *tc) {
    rr_type rr;
    size_t sig_len = 0;

    CuAssert(tc, "", val_algo_get_condensed_size(NULL, &sig_len) == 1);
    CuAssert(tc, "", val_algo_get_condensed_size(&rr, NULL) == 1);
}


static void get_condensed_size(CuTest *tc)
{
    // Test valid size
    get_condensed_size_valid_size(tc);

    // Test invalid buffer length
    get_condensed_size_invalid_size(tc);
    get_condensed_size_invalid_header(tc);    

    // Test invalid record type (Not RRSIG)
    get_other_record_type(tc, TYPE_DNSKEY, 8, 130);

    // Test invalid data field length
    get_other_record_type(tc, TYPE_RRSIG, 2, 130);

    // Test not MTL mode vs MTL mode
    get_other_record_type(tc, TYPE_RRSIG, 8, 13); 
    
    // Test with null parameters
    call_null_params(tc);
}

CuSuite* reg_cutest_pqc_algo(void)
{
	CuSuite* suite = CuSuiteNew();

    // PQC_DNSSEC_ALGOS *val_algo_props(char *keystr);
    // PQC_DNSSEC_ALGOS *val_algo_id_props(uint8_t algo);
    // int val_algo_is_mtl(uint8_t algo);
    // size_t val_algo_get_hash_size(uint8_t algo);
    // size_t val_algo_get_condensed_sig_header_size(uint8_t algo);
	SUITE_ADD_TEST(suite, get_condensed_size);

	return suite;
}