/*
 * Copyright (c) 2015 ARM. All rights reserved.
 */
#include "gtest/gtest.h"
#include "test_sn_coap_parser.h"


class sn_coap_parser : public testing::Test {
    void SetUp(void) {

    }

    void TearDown(void) {

    }
};


TEST_F(sn_coap_parser, test_sn_coap_parser)
{
    ASSERT_TRUE(test_sn_coap_parser());
}

TEST_F(sn_coap_parser, test_sn_coap_parser_options_parsing)
{
    ASSERT_TRUE(test_sn_coap_parser_options_parsing());
}

TEST_F(sn_coap_parser, test_sn_coap_parser_options_parsing_switches)
{
    ASSERT_TRUE(test_sn_coap_parser_options_parsing_switches());
}

TEST_F(sn_coap_parser, test_sn_coap_parser_options_count_needed_memory_multiple_option)
{
    ASSERT_TRUE(test_sn_coap_parser_options_count_needed_memory_multiple_option());
}

TEST_F(sn_coap_parser, test_sn_coap_parser_options_parse_multiple_options)
{
    ASSERT_TRUE(test_sn_coap_parser_options_parse_multiple_options());
}

TEST_F(sn_coap_parser, test_sn_coap_parser_parsing)
{
    ASSERT_TRUE(test_sn_coap_parser_parsing());
}

TEST_F(sn_coap_parser, test_sn_coap_parser_release_allocated_coap_msg_mem)
{
    ASSERT_TRUE(test_sn_coap_parser_release_allocated_coap_msg_mem());
}
