/*
	test dns.c
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "tpkg/cutest/cutest.h"
#include "edns.h"
#include "query.h"
#include "packet.h"

/**
 * Mock to test deduplication
 */
typedef struct {
    uint8_t ladder_list[4 * 32];
    size_t  ladder_count;
} mock_query_type;


static void edns_opt_sigtag_signal(CuTest *tc);
static void edns_opt_sigtag_signal_extra_data(CuTest *tc);
static void edns_opt_sigtag_one_record(CuTest *tc);
static void edns_opt_sigtag_one_record_extra_data(CuTest *tc);
static void edns_opt_sigtag_multiple_record(CuTest *tc);
static void edns_opt_sigtag_multiple_record_extra_data(CuTest *tc);
static void edns_opt_sigtag_multiple_record_mutiple_option(CuTest *tc);
static void edns_opt_sigtag_multiple_record_mutiple_option_extra_data(CuTest *tc);
static void check_addladder(CuTest* tc);
static void check_existladder(CuTest* tc);
static void check_overflow(CuTest* tc);
static void check_invalidparams(CuTest *tc);



CuSuite* reg_cutest_edns_opt(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, edns_opt_sigtag_signal);
	SUITE_ADD_TEST(suite, edns_opt_sigtag_signal_extra_data);
	SUITE_ADD_TEST(suite, edns_opt_sigtag_one_record);
	SUITE_ADD_TEST(suite, edns_opt_sigtag_one_record_extra_data);
	SUITE_ADD_TEST(suite, edns_opt_sigtag_multiple_record);		
	SUITE_ADD_TEST(suite, edns_opt_sigtag_multiple_record_extra_data);
	SUITE_ADD_TEST(suite, edns_opt_sigtag_multiple_record_mutiple_option);	
	SUITE_ADD_TEST(suite, edns_opt_sigtag_multiple_record_mutiple_option_extra_data);	
	SUITE_ADD_TEST(suite, check_addladder);
    SUITE_ADD_TEST(suite, check_existladder);
    SUITE_ADD_TEST(suite, check_overflow);
	SUITE_ADD_TEST(suite, check_invalidparams);
			
	return suite;
}

static void edns_opt_sigtag_signal(CuTest *tc)
{
	#ifdef MTL_MODE_FULL_CODE
		edns_record_type edns;
		buffer_type packet;
		query_type query;
		// Line one is the EDNS(0) Option header, Line 2 is the length and the payload bytes
		uint8_t signal_data[] = {0x00, // Name
			                     0x00, 0x29, // Type
								 0x04, 0xD0, // Class 
								 0x00, 0x00, 0x00, 0x00, // TTL
			                 	 0x00, 0x04, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for STAG
								 0x00, 0x00}; // Length
		size_t signal_data_len = 15;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &signal_data[0], signal_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS STAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 1);
		CuAssert(tc, "EDNS STAG Test - EDNS field status", edns.status == EDNS_OK);
		CuAssert(tc, "EDNS STAG Test - EDNS field maxlen", edns.maxlen == 1232);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie sttus", edns.cookie_len == 0);		
		CuAssert(tc, "EDNS STAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS STAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_name", edns.sigtag_enabled == 1);
		for(int i=0; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[i].ladder_hash_len == 0);		
		}

	#else
		fprintf(stderr, "  WARNING - MTL Mode Full Code DISABLED. Skipping Test\n");
		fflush(stderr);
	#endif
}

static void edns_opt_sigtag_signal_extra_data(CuTest *tc)
{
	#ifdef MTL_MODE_FULL_CODE
		edns_record_type edns;
		buffer_type packet;
		query_type query;
		// Line one is the EDNS(0) Option header, Line 2 is the length and the payload bytes
		uint8_t signal_data[] = {0x00, // Name
			                     0x00, 0x29, // Type
								 0x04, 0xD0, // Class 
								 0x00, 0x00, 0x00, 0x00, // TTL
			                 	 0x00, 0x0C, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for STAG
								 0x00, 0x08, // Length
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08 };// Extra Data
		size_t signal_data_len = 23;
		edns_init_record(&edns);
		buffer_create_from(&packet, &signal_data[0], signal_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS STAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field maxlen", edns.maxlen == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie sttus", edns.cookie_len == 0);		
		CuAssert(tc, "EDNS STAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS STAG Test - Query field reply full", query.reply_full == 0xaa);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_name", edns.sigtag_enabled == 0);
		for(int i=0; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[i].ladder_hash_len == 0);		
		}	

	#else
		fprintf(stderr, "  WARNING - MTL Mode Full Code DISABLED. Skipping Test\n");
		fflush(stderr);
	#endif
}

static void edns_opt_sigtag_one_record(CuTest *tc)
{
	#ifdef MTL_MODE_FULL_CODE
		edns_record_type edns;
		buffer_type packet;
		query_type query;
		// Line one is the EDNS(0) Option header, Line 2 is the length and the payload bytes
		uint8_t option_data[] = {0x00, // Name
			                     0x00, 0x29, // Type
								 0x04, 0xD0, // Class 
								 0x00, 0x00, 0x00, 0x00, // TTL
			                 	 0x00, 0x24, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for STAG
								 0x00, 0x20, // Length
								 0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
								 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
								 0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
								 0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8 };// Ladder Hash
		size_t option_data_len = 47;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS STAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 1);
		CuAssert(tc, "EDNS STAG Test - EDNS field status", edns.status == EDNS_OK);
		CuAssert(tc, "EDNS STAG Test - EDNS field maxlen", edns.maxlen == 1232);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie sttus", edns.cookie_len == 0);		
		CuAssert(tc, "EDNS STAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS STAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag", edns.sigtag_enabled == 1);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[0].ladder_hash_len == 32);		
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", memcmp(edns.sigtag_list[0].ladder_hash, &option_data[15], 32) == 0);			
		for(int i=1; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[i].ladder_hash_len == 0);		
		}	

	#else
		fprintf(stderr, "  WARNING - MTL Mode Full Code DISABLED. Skipping Test\n");
		fflush(stderr);
	#endif
}

static void edns_opt_sigtag_one_record_extra_data(CuTest *tc)
{
	#ifdef MTL_MODE_FULL_CODE
		edns_record_type edns;
		buffer_type packet;
		query_type query;
		// Line one is the EDNS(0) Option header, Line 2 is the length and the payload bytes
		uint8_t option_data[] = {0x00, // Name
			                     0x00, 0x29, // Type
								 0x04, 0xD0, // Class 
								 0x00, 0x00, 0x00, 0x00, // TTL
			                 	 0x00, 0x25, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for STAG
								 0x00, 0x21, // Length
								 0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
								 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
								 0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
								 0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8, // Ladder Hash
								 0x00 }; // Extra Data
		size_t option_data_len = 48;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS STAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field maxlen", edns.maxlen == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie sttus", edns.cookie_len == 0);		
		CuAssert(tc, "EDNS STAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS STAG Test - Query field reply full", query.reply_full == 0xaa);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag", edns.sigtag_enabled == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[0].ladder_hash_len == 0);			
		for(int i=1; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[i].ladder_hash_len == 0);		
		}	

	#else
		fprintf(stderr, "  WARNING - MTL Mode Full Code DISABLED. Skipping Test\n");
		fflush(stderr);
	#endif
}

static void edns_opt_sigtag_multiple_record(CuTest *tc)
{
	#ifdef MTL_MODE_FULL_CODE
		edns_record_type edns;
		buffer_type packet;
		query_type query;
		// Line one is the EDNS(0) Option header, Line 2 is the length and the payload bytes
		uint8_t option_data[] = {0x00, // Name
			                     0x00, 0x29, // Type
								 0x04, 0xD0, // Class 
								 0x00, 0x00, 0x00, 0x00, // TTL
			                 	 0x00, 0x44, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for STAG
								 0x00, 0x40, // Length
								 0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
								 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
								 0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
								 0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8, // Ladder Hash 1
								 0xb6, 0x61, 0x48, 0xc2, 0x24, 0xa8, 0xe7, 0x51, 
								 0x56, 0xc3, 0x52, 0xe6, 0xe4, 0xf4, 0xe7, 0x93, 
								 0x3a, 0xd1, 0xee, 0xa1, 0x57, 0xce, 0xf9, 0xb0, 
								 0xe7, 0xe6, 0xaa, 0xf9, 0x12, 0x21, 0x78, 0xf4 }; // Ladder Hash 2
		size_t option_data_len = 79;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS STAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 1);
		CuAssert(tc, "EDNS STAG Test - EDNS field status", edns.status == EDNS_OK);
		CuAssert(tc, "EDNS STAG Test - EDNS field maxlen", edns.maxlen == 1232);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie sttus", edns.cookie_len == 0);		
		CuAssert(tc, "EDNS STAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS STAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_name", edns.sigtag_enabled == 1);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[0].ladder_hash_len == 32);		
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", memcmp(edns.sigtag_list[0].ladder_hash, &option_data[15], 32) == 0);				
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[1].ladder_hash_len == 32);		
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", memcmp(edns.sigtag_list[1].ladder_hash, &option_data[47], 32) == 0);			
		for(int i=2; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[i].ladder_hash_len == 0);		
		}	
	#else
		fprintf(stderr, "  WARNING - MTL Mode Full Code DISABLED. Skipping Test\n");
		fflush(stderr);
	#endif
}

static void edns_opt_sigtag_multiple_record_extra_data(CuTest *tc)
{
	#ifdef MTL_MODE_FULL_CODE
		edns_record_type edns;
		buffer_type packet;
		query_type query;
		// Line one is the EDNS(0) Option header, Line 2 is the length and the payload bytes
		uint8_t option_data[] = {0x00, // Name
			                     0x00, 0x29, // Type
								 0x04, 0xD0, // Class 
								 0x00, 0x00, 0x00, 0x00, // TTL
			                 	 0x00, 0x4C, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for STAG
								 0x00, 0x48, // Length
								 0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
								 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
								 0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
								 0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8, // Ladder Hash 1
								 0xb6, 0x61, 0x48, 0xc2, 0x24, 0xa8, 0xe7, 0x51, 
								 0x56, 0xc3, 0x52, 0xe6, 0xe4, 0xf4, 0xe7, 0x93, 
								 0x3a, 0xd1, 0xee, 0xa1, 0x57, 0xce, 0xf9, 0xb0, 
								 0xe7, 0xe6, 0xaa, 0xf9, 0x12, 0x21, 0x78, 0xf4, // Ladder Hash 2
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 }; // Extra data
		size_t option_data_len = 87;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS STAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field maxlen", edns.maxlen == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie sttus", edns.cookie_len == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS STAG Test - Query field reply full", query.reply_full == 0xaa);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_name", edns.sigtag_enabled == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[0].ladder_hash_len == 0);			
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[1].ladder_hash_len == 0);				
		for(int i=2; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[i].ladder_hash_len == 0);		
		}	
	#else
		fprintf(stderr, "  WARNING - MTL Mode Full Code DISABLED. Skipping Test\n");
		fflush(stderr);
	#endif
}


static void edns_opt_sigtag_multiple_record_mutiple_option(CuTest *tc)
{
	#ifdef MTL_MODE_FULL_CODE
		edns_record_type edns;
		buffer_type packet;
		query_type query;
		nsd_type nsd;
		// Line one is the EDNS(0) Option header, Line 2 is the length and the payload bytes
		uint8_t option_data[] = {0x00, // Name
			                     0x00, 0x29, // Type
								 0x04, 0xD0, // Class 
								 0x00, 0x00, 0x00, 0x00, // TTL
			                 	 0x00, 0x50, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for STAG
								 0x00, 0x40, // Length
								 0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
								 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
								 0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
								 0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8, // Ladder Hash 1
								 0xb6, 0x61, 0x48, 0xc2, 0x24, 0xa8, 0xe7, 0x51, 
								 0x56, 0xc3, 0x52, 0xe6, 0xe4, 0xf4, 0xe7, 0x93, 
								 0x3a, 0xd1, 0xee, 0xa1, 0x57, 0xce, 0xf9, 0xb0, 
								 0xe7, 0xe6, 0xaa, 0xf9, 0x12, 0x21, 0x78, 0xf4, // Ladder Hash 2
								 0x00, 0x0a, // Optcode 10 for DNS COOKIE
								 0x00, 0x08, // DNS Cookie Length
								 0x34, 0xd1, 0x20, 0x0a, 0xab, 0xb5, 0x06, 0xb1}; // Cookie Data
		size_t option_data_len = 91;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;
		nsd.do_answer_cookie = 1;

		CuAssert(tc, "EDNS STAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, &nsd) == 1);
		CuAssert(tc, "EDNS STAG Test - EDNS field maxlen", edns.maxlen == 1232);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_INVALID);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie sttus", edns.cookie_len == 8);		
		CuAssert(tc, "EDNS STAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS STAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_name", edns.sigtag_enabled == 1);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[0].ladder_hash_len == 32);		
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", memcmp(edns.sigtag_list[0].ladder_hash, &option_data[15], 32) == 0);			
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[1].ladder_hash_len == 32);		
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", memcmp(edns.sigtag_list[1].ladder_hash, &option_data[47], 32) == 0);			
		for(int i=2; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[i].ladder_hash_len == 0);		
		}	
	#else
		fprintf(stderr, "  WARNING - MTL Mode Full Code DISABLED. Skipping Test\n");
		fflush(stderr);
	#endif
}


static void edns_opt_sigtag_multiple_record_mutiple_option_extra_data(CuTest *tc)
{
	#ifdef MTL_MODE_FULL_CODE
		edns_record_type edns;
		buffer_type packet;
		query_type query;
		nsd_type nsd;
		// Line one is the EDNS(0) Option header, Line 2 is the length and the payload bytes
		uint8_t option_data[] = {0x00, // Name
			                     0x00, 0x29, // Type
								 0x04, 0xD0, // Class 
								 0x00, 0x00, 0x00, 0x00, // TTL
			                 	 0x00, 0x58, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for STAG
								 0x00, 0x48, // Length
								 0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
								 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
								 0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
								 0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8, // Ladder Hash 1
								 0xb6, 0x61, 0x48, 0xc2, 0x24, 0xa8, 0xe7, 0x51, 
								 0x56, 0xc3, 0x52, 0xe6, 0xe4, 0xf4, 0xe7, 0x93, 
								 0x3a, 0xd1, 0xee, 0xa1, 0x57, 0xce, 0xf9, 0xb0, 
								 0xe7, 0xe6, 0xaa, 0xf9, 0x12, 0x21, 0x78, 0xf4, // Ladder Hash 2
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
								 0x00, 0x0a, // Optcode 10 for DNS COOKIE
								 0x00, 0x08, // DNS Cookie Length
								 0x34, 0xd1, 0x20, 0x0a, 0xab, 0xb5, 0x06, 0xb1}; // Cookie Data
		size_t option_data_len = 99;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;
		nsd.do_answer_cookie = 1;

		CuAssert(tc, "EDNS STAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, &nsd) == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field maxlen", edns.maxlen == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS STAG Test - EDNS field cookie sttus", edns.cookie_len == 0);		
		CuAssert(tc, "EDNS STAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS STAG Test - Query field reply full", query.reply_full == 0xaa);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_name", edns.sigtag_enabled == 0);
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[0].ladder_hash_len == 0);		
		CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[1].ladder_hash_len == 0); 	
		for(int i=2; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS STAG Test - EDNS field sig_tag_list", edns.sigtag_list[i].ladder_hash_len == 0);		
		}	
	#else
		fprintf(stderr, "  WARNING - MTL Mode Full Code DISABLED. Skipping Test\n");
		fflush(stderr);
	#endif
}



/** 
 * Verify adding a new hash returns 1 on success. 
 */
static void check_addladder(CuTest* tc) 
{
    mock_query_type q;
    q.ladder_count = 0;
    memset(q.ladder_list, 0, sizeof(q.ladder_list));

    uint8_t  new_hash[32] = {
        0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8
    };

	CuAssert(tc, "Check Add Ladder - Update ladder_list", check_and_add_ladder_hash(q.ladder_list, &q.ladder_count, 4, new_hash) == 1); 
	CuAssert(tc, "Check Add Ladder - Update ladder_count",  q.ladder_count == 1); // Count should increment to 1
    
    // Check if copied to the first slot
    CuAssert(tc, "Check Add Ladder - Hash Copied to ladder_list", memcmp(new_hash, &q.ladder_list[0], 32) == 0);
}


/**
 * Verify adding an identical hash returns 0: deduplication.
 */
static void check_existladder(CuTest* tc)
{
    mock_query_type q;
    q.ladder_count = 0;
    memset(q.ladder_list, 0, sizeof(q.ladder_list));

    uint8_t new_hash[32] = {
        0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8
    };

    // First insertion
    check_and_add_ladder_hash(q.ladder_list, &q.ladder_count, 4, new_hash);
    
    // Second insertion: deduplicate
	CuAssert(tc, "Check Ladder Already Added - Update ladder_list", check_and_add_ladder_hash(q.ladder_list, &q.ladder_count, 4, new_hash) == 0); 
	CuAssert(tc, "Check Ladder Already Added - Update ladder_count",  q.ladder_count == 1); // Count should stay 1
}


/** 
 * Verify array capacity exhaustion returns 2.
 */ 
static void check_overflow(CuTest* tc)
{
    mock_query_type q;
    q.ladder_count = 0;
    memset(q.ladder_list, 0, sizeof(q.ladder_list));

    uint8_t hashes[5][32] = {
        {
        0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8
        }, {
        0x57, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc7
        }, {
        0x56, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc6
        }, {
        0x55, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc5
        }, {
        0x54, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7, 
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc4
        }
    };

    // Fill up to max capacity
    for (int i = 0; i < 4; i++) {
        check_and_add_ladder_hash(q.ladder_list, &q.ladder_count, 4, hashes[i]);
    }

    // Attempting an insertion should trigger out of space
	CuAssert(tc, "Check List Overflow - Update ladder_list", check_and_add_ladder_hash(q.ladder_list, &q.ladder_count, 4, hashes[4]) == 2); 
	CuAssert(tc, "Check List Overflow - Update ladder_count",  q.ladder_count == 4); // Count should cap at max capacity
}



/**
 * Verify invalid input parameters.
 */
static void check_invalidparams(CuTest *tc) {
    uint8_t list[LADDER_HASH_OUTPUT_SIZE * 5] = {0};
    uint8_t new_hash[LADDER_HASH_OUTPUT_SIZE] = {1};
    size_t count = 0;
    size_t max_capacity = 5;
    int result;

	// Test NULL count
	CuAssert(tc, "Check Deduplication Invalid Params - NULL count", check_and_add_ladder_hash(list, NULL, max_capacity, new_hash) == -1); 

    // Test NULL list
    count = 0;
	CuAssert(tc, "Check Deduplication Invalid Params - NULL list", check_and_add_ladder_hash(NULL, &count, max_capacity, new_hash) == -1); 
	CuAssert(tc, "Check Deduplication Invalid Params - NULL list", count == 0); 

    // Test NULL new_hash
    count = 0;
	CuAssert(tc, "Check Deduplication Invalid Params - NULL new_hash", check_and_add_ladder_hash(list, &count, max_capacity, NULL) == -1); 
	CuAssert(tc, "Check Deduplication Invalid Params - NULL new_hash", count == 0); 

    // Test 0 max_capacity
    count = 0;
	CuAssert(tc, "Check Deduplication Invalid Params - 0 max_capacity", check_and_add_ladder_hash(list, &count, 0, new_hash) == 2); 
	CuAssert(tc, "Check Deduplication Invalid Params - 0 max_capacity", count == 0); 
}