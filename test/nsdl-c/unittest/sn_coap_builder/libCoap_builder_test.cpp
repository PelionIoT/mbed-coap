/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "CppUTest/TestHarness.h"
#include <string.h>

#include "sn_nsdl.h"
#include "sn_coap_header.h"
#include "stubs.h"

sn_coap_hdr_s coap_header;
sn_coap_options_list_s option_list;
uint8_t buffer[64];
uint8_t temp[10];

struct coap_s {
    void *(*sn_coap_protocol_malloc)(uint16_t);
    void (*sn_coap_protocol_free)(void *);

    uint8_t (*sn_coap_tx_callback)(uint8_t *, uint16_t, sn_nsdl_addr_s *, void *);
    int8_t (*sn_coap_rx_callback)(sn_coap_hdr_s *, sn_nsdl_addr_s *, void *);
};

static void *own_alloc(uint16_t size)
{
    return malloc(size);
}

static void own_free(void *ptr)
{
    free(ptr);
}

TEST_GROUP(libCoap_builder)
{
    void setup() {
        memset(&coap_header, 0, sizeof(sn_coap_hdr_s));
        memset(&option_list, 0, sizeof(sn_coap_options_list_s));

        coap_header.options_list_ptr = &option_list;
        coap_header.msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
        coap_header.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
        coap_header.msg_id = 12;
    }

    void teardown() {

    }
};

TEST(libCoap_builder, build_confirmable_response)
{
    struct coap_s handle;
    sn_coap_hdr_s *response = NULL;

    handle.sn_coap_protocol_malloc = &own_alloc;
    handle.sn_coap_protocol_free = &own_free;

    coap_header.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    coap_header.msg_code = COAP_MSG_CODE_REQUEST_GET;
    coap_header.msg_id = 12;

    //NULL pointer
    CHECK(sn_coap_build_response(NULL, NULL, 0) == NULL);
    CHECK(sn_coap_build_response(&handle, NULL, 0) == NULL);
    CHECK(sn_coap_build_response(NULL, &coap_header, 0) == NULL);
    response = sn_coap_build_response(&handle, &coap_header, COAP_MSG_CODE_RESPONSE_CONTENT);

    CHECK(response != NULL);
    CHECK(response->msg_type == COAP_MSG_TYPE_ACKNOWLEDGEMENT);
    CHECK(response->msg_id == 12);
    CHECK(response->msg_code == COAP_MSG_CODE_RESPONSE_CONTENT);

    own_free(response);
}

TEST(libCoap_builder, build_non_confirmable_response)
{
    struct coap_s handle;
    sn_coap_hdr_s *response = NULL;
    uint8_t token_val = 0x99;

    handle.sn_coap_protocol_malloc = &own_alloc;
    handle.sn_coap_protocol_free = &own_free;

    coap_header.msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
    coap_header.msg_code = COAP_MSG_CODE_REQUEST_GET;
    coap_header.msg_id = 12;
    coap_header.token_len = 1;
    coap_header.token_ptr = &token_val;

    response = sn_coap_build_response(&handle, &coap_header, COAP_MSG_CODE_RESPONSE_CONTENT);

    CHECK(response != NULL);
    CHECK(response->msg_type == COAP_MSG_TYPE_NON_CONFIRMABLE);
    CHECK(response->msg_code == COAP_MSG_CODE_RESPONSE_CONTENT);
    CHECK(response->token_ptr != NULL);
    CHECK(memcmp(response->token_ptr, coap_header.token_ptr, coap_header.token_len) == 0);
    CHECK(response->token_len == coap_header.token_len);

    own_free(response->token_ptr);
    own_free(response);
}


TEST(libCoap_builder, build_message_negative_cases)
{
    // Null pointers as a parameter
    CHECK(sn_coap_builder(NULL, NULL) == -2);
    CHECK(sn_coap_builder(NULL, &coap_header) == -2);
    CHECK(sn_coap_builder(buffer, NULL) == -2);

    // Invalid option length
    coap_header.token_ptr = temp;
    CHECK(sn_coap_builder(buffer, &coap_header) == -1);
}

TEST(libCoap_builder, build_message_ok_cases)
{
    CHECK(sn_coap_builder(buffer, &coap_header) == 4);
}

TEST(libCoap_builder, build_message_options_token)
{
    coap_header.token_ptr = temp;
    coap_header.token_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 6);
}

TEST(libCoap_builder, build_message_options_uri_path)
{
    coap_header.uri_path_ptr = temp;
    coap_header.uri_path_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 7);
}

TEST(libCoap_builder, build_message_options_content_type)
{
    coap_header.content_type_ptr = temp;
    coap_header.content_type_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 7);
}

TEST(libCoap_builder, build_message_options_max_age)
{
    coap_header.options_list_ptr->max_age_ptr = temp;
    coap_header.options_list_ptr->max_age_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 8);
}

TEST(libCoap_builder, build_message_options_proxy_uri)
{
    coap_header.options_list_ptr->proxy_uri_ptr = temp;
    coap_header.options_list_ptr->proxy_uri_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 8);
}

TEST(libCoap_builder, build_message_options_etag)
{
    coap_header.options_list_ptr->etag_ptr = temp;
    coap_header.options_list_ptr->etag_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 7);
}

TEST(libCoap_builder, build_message_options_uri_host)
{
    coap_header.options_list_ptr->uri_host_ptr = temp;
    coap_header.options_list_ptr->uri_host_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 7);
}

TEST(libCoap_builder, build_message_options_location_path)
{
    coap_header.options_list_ptr->location_path_ptr = temp;
    coap_header.options_list_ptr->location_path_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 7);
}

TEST(libCoap_builder, build_message_options_uri_port)
{
    coap_header.options_list_ptr->uri_port_ptr = temp;
    coap_header.options_list_ptr->uri_port_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 7);
}

TEST(libCoap_builder, build_message_options_location_query)
{
    coap_header.options_list_ptr->location_query_ptr = temp;
    coap_header.options_list_ptr->location_query_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 8);
}

TEST(libCoap_builder, build_message_options_observe)
{
    coap_header.options_list_ptr->observe_ptr = temp;
    coap_header.options_list_ptr->observe_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 7);
}


TEST(libCoap_builder, build_message_options_accept)
{
    coap_header.options_list_ptr->accept_ptr = temp;
    coap_header.options_list_ptr->accept_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 8);
}


TEST(libCoap_builder, build_message_options_uri_query)
{
    coap_header.options_list_ptr->uri_query_ptr = temp;
    coap_header.options_list_ptr->uri_query_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 8);
}


TEST(libCoap_builder, build_message_options_block1)
{
    coap_header.options_list_ptr->block1_ptr = temp;
    coap_header.options_list_ptr->block1_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 8);
}

TEST(libCoap_builder, build_message_options_block2)
{
    coap_header.options_list_ptr->block2_ptr = temp;
    coap_header.options_list_ptr->block2_len = 2;
    CHECK(sn_coap_builder(buffer, &coap_header) == 8);
}