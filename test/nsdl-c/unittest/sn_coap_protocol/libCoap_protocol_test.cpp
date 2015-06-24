/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include "CppUTest/TestHarness.h"
#include <string.h>

#include "sn_nsdl.h"
#include "sn_coap_protocol.h"
#include "sn_nsdl_lib.h"
#include "sn_coap_header_internal.h"


TEST_GROUP(libCoap_protocol)
{
    void setup()
    {

    }

    void teardown()
    {

    }
};

void *null_allocator(uint16_t size)
{
	return NULL;
}

void *test_allocator(uint16_t size)
{
	return malloc(size);
}

void null_free(void *addr)
{
	;
}

uint8_t null_tx_cb(uint8_t *a, uint16_t b, sn_nsdl_addr_s *c, void *d)
{
	return 0;
}

TEST(libCoap_protocol, sn_coap_protocol_init_null_func_ptrs)
{
	POINTERS_EQUAL(NULL, sn_coap_protocol_init(NULL, NULL, NULL, NULL));
}

TEST(libCoap_protocol, sn_coap_protocol_init_null_malloc)
{
	POINTERS_EQUAL(NULL, sn_coap_protocol_init( null_allocator, null_free, null_tx_cb, NULL));
}

TEST(libCoap_protocol, sn_coap_protocol_init_happy)
{
	coap_s *hnd;
	hnd = sn_coap_protocol_init( test_allocator, null_free, null_tx_cb, NULL);
	CHECK(hnd != NULL);

}

TEST(libCoap_protocol, sn_coap_protocol_build_null_ptrs)
{
	POINTERS_EQUAL(NULL, sn_coap_protocol_build(NULL, NULL, NULL, NULL, NULL));
}
