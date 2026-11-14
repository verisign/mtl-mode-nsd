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

static void edns_opt_sigtag_signal(CuTest *tc);
static void edns_opt_sigtag_signal_extra_data(CuTest *tc);
static void edns_opt_sigtag_one_record(CuTest *tc);
static void edns_opt_sigtag_one_record_extra_data(CuTest *tc);
static void edns_opt_sigtag_multiple_record(CuTest *tc);
static void edns_opt_sigtag_multiple_record_extra_data(CuTest *tc);
static void edns_opt_sigtag_multiple_record_mutiple_option(CuTest *tc);

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
								 0xFE, 0x1A, // Optcode 65050 for SIGTAG
								 0x00, 0x00}; // Length
		size_t signal_data_len = 15;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &signal_data[0], signal_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS SIGTAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 1);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field status", edns.status == EDNS_OK);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field maxlen", edns.maxlen == 1232);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field cookie sttus", edns.cookie_len == 0);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS SIGTAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name", edns.sigtag_enabled == 1);
		for(int i=0; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[i].sid_length == 0);		
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
								 0xFE, 0x1A, // Optcode 65050 for SIGTAG
								 0x00, 0x08, // Length
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08 };// Extra Data
		size_t signal_data_len = 23;
		edns_init_record(&edns);
		buffer_create_from(&packet, &signal_data[0], signal_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS SIGTAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field status", edns.status == EDNS_ERROR);
		CuAssert(tc, "EDNS SIGTAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name", edns.sigtag_enabled == 0);
		for(int i=0; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[i].sid_length == 0);		
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
			                 	 0x00, 0x2C, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for SIGTAG
								 0x00, 0x28, // Length
								 0x85, 0x22, 0x39, 0x42, 0x70, 0x55, 0x3b, 0x98, // SID
								 0xde, 0x7a, 0xc1, 0x96, 0xbe, 0xe5, 0xe7, 0x45,
								 0xb5, 0xd5, 0x21, 0x2d, 0x15, 0xb3, 0xa3, 0xd5,
								 0xb5, 0xaf, 0x07, 0xc3, 0xa2, 0xe4, 0x7b, 0x91,
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08 };// Leaf Index
		size_t option_data_len = 55;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS SIGTAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 1);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field status", edns.status == EDNS_OK);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field maxlen", edns.maxlen == 1232);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field cookie sttus", edns.cookie_len == 0);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS SIGTAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name", edns.sigtag_enabled == 1);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[0].sid_length == 32);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", memcmp(edns.sigtags_list[0].sid, &option_data[15], 32) == 0);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[0].max_ladder_index == 8);		
		for(int i=1; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[i].sid_length == 0);		
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
			                 	 0x00, 0x2D, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for SIGTAG
								 0x00, 0x29, // Length
								 0x85, 0x22, 0x39, 0x42, 0x70, 0x55, 0x3b, 0x98, // SID
								 0xde, 0x7a, 0xc1, 0x96, 0xbe, 0xe5, 0xe7, 0x45,
								 0xb5, 0xd5, 0x21, 0x2d, 0x15, 0xb3, 0xa3, 0xd5,
								 0xb5, 0xaf, 0x07, 0xc3, 0xa2, 0xe4, 0x7b, 0x91,
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // Leaf Index
								 0x00 }; // Extra Data
		size_t option_data_len = 56;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS SIGTAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field status", edns.status == EDNS_ERROR);
		CuAssert(tc, "EDNS SIGTAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name", edns.sigtag_enabled == 0);
		for(int i=0; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[i].sid_length == 0);		
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
			                 	 0x00, 0x54, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for SIGTAG
								 0x00, 0x50, // Length
								 0x85, 0x22, 0x39, 0x42, 0x70, 0x55, 0x3b, 0x98, // SID #1
								 0xde, 0x7a, 0xc1, 0x96, 0xbe, 0xe5, 0xe7, 0x45,
								 0xb5, 0xd5, 0x21, 0x2d, 0x15, 0xb3, 0xa3, 0xd5,
								 0xb5, 0xaf, 0x07, 0xc3, 0xa2, 0xe4, 0x7b, 0x91,
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // Leaf Index #1
								 0x00, 0xac, 0x1d, 0xf7, 0x18, 0xba, 0xd3, 0x07, // SID #2
								 0xb7, 0xff, 0xb0, 0xa9, 0x0e, 0x1d, 0x86, 0x72,
								 0x74, 0x8d, 0x78, 0xb7, 0x52, 0xb6, 0x5a, 0x21,
								 0x20, 0xb1, 0x0a, 0x34, 0xd1, 0xab, 0xb5, 0x06,
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}; // Leaf Index #2
		size_t option_data_len = 95;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS SIGTAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 1);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field status", edns.status == EDNS_OK);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field maxlen", edns.maxlen == 1232);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_NOT_PRESENT);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field cookie sttus", edns.cookie_len == 0);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS SIGTAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name", edns.sigtag_enabled == 1);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[0].sid_length == 32);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", memcmp(edns.sigtags_list[0].sid, &option_data[15], 32) == 0);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[0].max_ladder_index == 8);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[1].sid_length == 32);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", memcmp(edns.sigtags_list[1].sid, &option_data[55], 32) == 0);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[1].max_ladder_index == 256);		
		for(int i=2; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[i].sid_length == 0);		
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
			                 	 0x00, 0x5C, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for SIGTAG
								 0x00, 0x58, // Length
								 0x85, 0x22, 0x39, 0x42, 0x70, 0x55, 0x3b, 0x98, // SID #1
								 0xde, 0x7a, 0xc1, 0x96, 0xbe, 0xe5, 0xe7, 0x45,
								 0xb5, 0xd5, 0x21, 0x2d, 0x15, 0xb3, 0xa3, 0xd5,
								 0xb5, 0xaf, 0x07, 0xc3, 0xa2, 0xe4, 0x7b, 0x91,
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // Leaf Index #1
								 0x00, 0xac, 0x1d, 0xf7, 0x18, 0xba, 0xd3, 0x07, // SID #2
								 0xb7, 0xff, 0xb0, 0xa9, 0x0e, 0x1d, 0x86, 0x72,
								 0x74, 0x8d, 0x78, 0xb7, 0x52, 0xb6, 0x5a, 0x21,
								 0x20, 0xb1, 0x0a, 0x34, 0xd1, 0xab, 0xb5, 0x06,
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // Leaf Index #2
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}; // Extra data
		size_t option_data_len = 103;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;

		CuAssert(tc, "EDNS SIGTAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, NULL) == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field status", edns.status == EDNS_ERROR);
		CuAssert(tc, "EDNS SIGTAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name", edns.sigtag_enabled == 0);
		for(int i=0; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[i].sid_length == 0);		
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
			                 	 0x00, 0x60, // RD Len
								 0xFE, 0x1A, // Optcode 65050 for SIGTAG
								 0x00, 0x50, // Length
								 0x85, 0x22, 0x39, 0x42, 0x70, 0x55, 0x3b, 0x98, // SID #1
								 0xde, 0x7a, 0xc1, 0x96, 0xbe, 0xe5, 0xe7, 0x45,
								 0xb5, 0xd5, 0x21, 0x2d, 0x15, 0xb3, 0xa3, 0xd5,
								 0xb5, 0xaf, 0x07, 0xc3, 0xa2, 0xe4, 0x7b, 0x91,
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // Leaf Index #1
								 0x00, 0xac, 0x1d, 0xf7, 0x18, 0xba, 0xd3, 0x07, // SID #2
								 0xb7, 0xff, 0xb0, 0xa9, 0x0e, 0x1d, 0x86, 0x72,
								 0x74, 0x8d, 0x78, 0xb7, 0x52, 0xb6, 0x5a, 0x21,
								 0x20, 0xb1, 0x0a, 0x34, 0xd1, 0xab, 0xb5, 0x06,
								 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // Leaf Index #2
								 0x00, 0x0a, // Optcode 10 for DNS COOKIE
								 0x00, 0x08, // DNS Cookie Length
								 0x34, 0xd1, 0x20, 0x0a, 0xab, 0xb5, 0x06, 0xb1}; // Cookie Data
		size_t option_data_len = 107;
		
		edns_init_record(&edns);
		buffer_create_from(&packet, &option_data[0], option_data_len);
		query.reply_full = 0xaa;
		nsd.do_answer_cookie = 1;

		CuAssert(tc, "EDNS SIGTAG Test - Parse signal record", edns_parse_record(&edns, &packet, &query, &nsd) == 1);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field maxlen", edns.maxlen == 1232);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field cookie len", edns.cookie_status == COOKIE_INVALID);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field cookie sttus", edns.cookie_len == 8);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field dnssec ok", edns.dnssec_ok == 0x00);
		CuAssert(tc, "EDNS SIGTAG Test - Query field reply full", query.reply_full == 0);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name", edns.sigtag_enabled == 1);
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[0].sid_length == 32);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", memcmp(edns.sigtags_list[0].sid, &option_data[15], 32) == 0);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[0].max_ladder_index == 8);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[1].sid_length == 32);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", memcmp(edns.sigtags_list[1].sid, &option_data[55], 32) == 0);		
		CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[1].max_ladder_index == 256);		
		for(int i=2; i<MAX_SIG_TAGS; i++) {
			CuAssert(tc, "EDNS SIGTAG Test - EDNS field sig_name_list", edns.sigtags_list[i].sid_length == 0);		
		}	

	#else
		fprintf(stderr, "  WARNING - MTL Mode Full Code DISABLED. Skipping Test\n");
		fflush(stderr);
	#endif
}