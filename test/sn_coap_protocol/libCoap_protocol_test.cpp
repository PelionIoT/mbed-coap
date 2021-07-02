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
#include "gtest/gtest.h"
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "sn_coap_protocol.h"
#include "sn_coap_header_internal.h"
#include "sn_coap_protocol_internal.h"

#include "sn_coap_builder_stub.h"
#include "sn_coap_parser_stub.h"
#include "sn_coap_header_check_stub.h"


int retCounter = 0;
static coap_s *coap_handle = NULL;
void myFree(void *addr);
void *myMalloc(uint16_t size);
uint8_t null_tx_cb(uint8_t *a, uint16_t b, sn_nsdl_addr_s *c, void *d);
void test_block1_receive(struct coap_s *handle, sn_nsdl_addr_s *src_addr_ptr, uint16_t packet_data_len, uint8_t *packet_data_ptr);
void test_block1_send(struct coap_s *handle, sn_nsdl_addr_s *src_addr_ptr, uint16_t packet_data_len, uint8_t *packet_data_ptr);
void test_block2_receive(struct coap_s *handle, sn_nsdl_addr_s *addr, uint16_t packet_data_len, uint8_t *packet_data_ptr);
void test_block2_send(struct coap_s *handle, sn_nsdl_addr_s *addr, uint16_t packet_data_len, uint8_t *packet_data_ptr);

class libCoap_protocol : public testing::Test {
    void SetUp(void) {
        retCounter = 1;
        coap_handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);
    }

    void TearDown(void) {
        retCounter = 0;
        sn_coap_protocol_destroy(coap_handle);
    }
};

void *myMalloc(uint16_t size)
{
    if (retCounter > 0) {
        retCounter--;
        return malloc(size);
    } else {
        return NULL;
    }
}

void myFree(void *addr)
{
    if (addr) {
        free(addr);
    }
}

uint8_t null_tx_cb(uint8_t *a, uint16_t b, sn_nsdl_addr_s *c, void *d)
{
    return 0;
}

int8_t null_rx_cb(sn_coap_hdr_s *a, sn_nsdl_addr_s *b, void *c)
{
    return 0;
}

TEST_F(libCoap_protocol, sn_coap_protocol_destroy)
{
    ASSERT_TRUE(-1 == sn_coap_protocol_destroy(NULL));
    struct coap_s *handle = (struct coap_s *)malloc(sizeof(struct coap_s));
    handle->sn_coap_protocol_free = &myFree;
    handle->sn_coap_protocol_malloc = &myMalloc;
    ns_list_init(&handle->linked_list_resent_msgs);
    coap_send_msg_s *msg_ptr = (coap_send_msg_s *)malloc(sizeof(coap_send_msg_s));
    memset(msg_ptr, 0, sizeof(coap_send_msg_s));

    ns_list_add_to_end(&handle->linked_list_resent_msgs, msg_ptr);
#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT
    ns_list_init(&handle->linked_list_duplication_msgs);
#endif
#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
    ns_list_init(&handle->linked_list_blockwise_sent_msgs);
    ns_list_init(&handle->linked_list_blockwise_received_payloads);
#endif
    ASSERT_TRUE(0 == sn_coap_protocol_destroy(handle));
}

TEST_F(libCoap_protocol, sn_coap_protocol_init_null_func_ptrs)
{
    ASSERT_TRUE(NULL == sn_coap_protocol_init(NULL, NULL, NULL, NULL));
}

TEST_F(libCoap_protocol, sn_coap_protocol_init_null_malloc)
{
    ASSERT_TRUE(NULL == sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL));

    retCounter = 1;
    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);
    ASSERT_TRUE(NULL != handle);

    sn_coap_protocol_destroy(handle);
}

TEST_F(libCoap_protocol, sn_coap_protocol_set_block_size)
{
#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
    ASSERT_TRUE(0 == sn_coap_protocol_set_block_size(coap_handle, 16));
    ASSERT_TRUE(-1 == sn_coap_protocol_set_block_size(NULL, 1));
#endif
    ASSERT_TRUE(-1 == sn_coap_protocol_set_block_size(coap_handle, 1));
}

TEST_F(libCoap_protocol, sn_coap_protocol_clear_sent_blockwise_messages)
{
#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
    sn_coap_protocol_clear_sent_blockwise_messages(NULL);

    coap_blockwise_msg_s *message = (coap_blockwise_msg_s *)malloc(sizeof(coap_blockwise_msg_s));
    memset(message, 0, sizeof(coap_blockwise_msg_s));
    message->coap_msg_ptr = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(message->coap_msg_ptr, 0, sizeof(sn_coap_hdr_s));
    message->coap_msg_ptr->payload_ptr = (uint8_t *)malloc(5);
    message->coap_msg_ptr->payload_len = 5;
    ns_list_add_to_end(&coap_handle->linked_list_blockwise_sent_msgs, message);
    sn_coap_protocol_clear_sent_blockwise_messages(coap_handle);
    ASSERT_TRUE(0 == ns_list_count(&coap_handle->linked_list_blockwise_sent_msgs));
#endif
}

TEST_F(libCoap_protocol, sn_coap_protocol_set_duplicate_buffer_size)
{
#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT
    ASSERT_TRUE(0 == sn_coap_protocol_set_duplicate_buffer_size(coap_handle, 3));
    ASSERT_TRUE(-1 == sn_coap_protocol_set_duplicate_buffer_size(NULL, 3));
#endif
    ASSERT_TRUE(-1 == sn_coap_protocol_set_duplicate_buffer_size(coap_handle, 231));
}

TEST_F(libCoap_protocol, sn_coap_protocol_set_retransmission_parameters)
{
#if ENABLE_RESENDINGS
    ASSERT_TRUE(0 == sn_coap_protocol_set_retransmission_parameters(coap_handle, 3, 0));
    ASSERT_TRUE(0 == sn_coap_protocol_set_retransmission_parameters(coap_handle, 3, 10));
    ASSERT_TRUE(-1 == sn_coap_protocol_set_retransmission_parameters(NULL, 3, 0));
#endif
    ASSERT_TRUE(-1 == sn_coap_protocol_set_retransmission_parameters(coap_handle, 231, 0));
}

TEST_F(libCoap_protocol, sn_coap_protocol_set_retransmission_buffer)
{
#if ENABLE_RESENDINGS
    ASSERT_TRUE(0 == sn_coap_protocol_set_retransmission_buffer(coap_handle, 3, 3));
    ASSERT_TRUE(-1 == sn_coap_protocol_set_retransmission_buffer(NULL, 3, 3));
#endif
    ASSERT_TRUE(-1 == sn_coap_protocol_set_retransmission_buffer(coap_handle, 3, 999));
}

//TEST_F(libCoap_protocol, sn_coap_protocol_clear_retransmission_buffer)
//{
//    sn_coap_protocol_clear_retransmission_buffer();
//}
#include <stdio.h>

TEST_F(libCoap_protocol, sn_coap_protocol_delete_retransmission)
{
#if ENABLE_RESENDINGS
    retCounter = 6;
    sn_nsdl_addr_s dst_addr_ptr;
    sn_coap_hdr_s src_coap_msg_ptr;
    uint8_t temp_addr[4] = {0};
    uint8_t dst_packet_data_ptr[4] = {0x40, 0x00, 0x00, 0x63};

    memset(&dst_addr_ptr, 0, sizeof(sn_nsdl_addr_s));
    memset(&src_coap_msg_ptr, 0, sizeof(sn_coap_hdr_s));

    dst_addr_ptr.addr_ptr = temp_addr;
    dst_addr_ptr.addr_len = 4;
    dst_addr_ptr.type = SN_NSDL_ADDRESS_TYPE_IPV4;

    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);

    ASSERT_TRUE(-1 == sn_coap_protocol_delete_retransmission(NULL, 0));

    ASSERT_TRUE(-2 == sn_coap_protocol_delete_retransmission(handle, 0));

    sn_coap_builder_stub.expectedInt16 = 4;

    ASSERT_TRUE(0 < sn_coap_protocol_build(handle, &dst_addr_ptr, dst_packet_data_ptr, &src_coap_msg_ptr, NULL));

    ASSERT_TRUE(0 == sn_coap_protocol_delete_retransmission(handle, 99));

    sn_coap_protocol_destroy(handle);
#endif
}

TEST_F(libCoap_protocol, sn_coap_protocol_delete_retransmission_by_token)
{
#if ENABLE_RESENDINGS
    retCounter = 6;
    sn_nsdl_addr_s dst_addr_ptr;
    sn_coap_hdr_s src_coap_msg_ptr;
    uint8_t temp_addr[4] = {0};
    uint8_t dst_packet_data_ptr[9] = {0x04, 0x00, 0x00, 0x63, 0x10, 0x10, 0x10, 0x10};

    memset(&dst_addr_ptr, 0, sizeof(sn_nsdl_addr_s));
    memset(&src_coap_msg_ptr, 0, sizeof(sn_coap_hdr_s));

    dst_addr_ptr.addr_ptr = temp_addr;
    dst_addr_ptr.addr_len = 4;
    dst_addr_ptr.type = SN_NSDL_ADDRESS_TYPE_IPV4;
    src_coap_msg_ptr.token_ptr = (uint8_t *)malloc(4);
    memset(src_coap_msg_ptr.token_ptr, 0x10, 4);
    src_coap_msg_ptr.token_len = 4;

    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);

    ASSERT_TRUE(-1 == sn_coap_protocol_delete_retransmission_by_token(NULL, NULL, 0));

    ASSERT_TRUE(-2 == sn_coap_protocol_delete_retransmission_by_token(handle,
                                                                src_coap_msg_ptr.token_ptr,
                                                                src_coap_msg_ptr.token_len));

    sn_coap_builder_stub.expectedInt16 = 9;

    ASSERT_TRUE(0 < sn_coap_protocol_build(handle, &dst_addr_ptr, dst_packet_data_ptr, &src_coap_msg_ptr, NULL));

    ASSERT_TRUE(0 == sn_coap_protocol_delete_retransmission_by_token(handle, src_coap_msg_ptr.token_ptr, src_coap_msg_ptr.token_len));

    free(src_coap_msg_ptr.token_ptr);
    sn_coap_protocol_destroy(handle);
#endif
}


TEST_F(libCoap_protocol, sn_coap_protocol_build)
{
    retCounter = 1;
    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);

    sn_coap_protocol_set_retransmission_buffer(handle, 6, 0);
    sn_nsdl_addr_s addr;
    memset(&addr, 0, sizeof(sn_nsdl_addr_s));
    sn_coap_hdr_s hdr;
    memset(&hdr, 0, sizeof(sn_coap_hdr_s));

    uint8_t *dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    ASSERT_TRUE(-2 == sn_coap_protocol_build(NULL, NULL, NULL, NULL, NULL));

    ASSERT_TRUE(-2 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    hdr.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    hdr.msg_id = 0;

    addr.addr_ptr = (uint8_t *)malloc(5);
    memset(addr.addr_ptr, '1', 5);

    sn_coap_builder_stub.expectedInt16 = 0;
    retCounter = 6;

    ASSERT_TRUE(0 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    // Test duplicate response sending
    addr.port = 1000;
    hdr.msg_id = 100;
    hdr.msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_builder_stub.expectedInt16 = 0;
    retCounter = 3;

    coap_duplication_info_s *duplicate = (coap_duplication_info_s *)malloc(sizeof(coap_duplication_info_s));
    memset(duplicate, 0, sizeof(coap_duplication_info_s));
    duplicate->address = (sn_nsdl_addr_s *)malloc(sizeof(sn_nsdl_addr_s));
    duplicate->address->addr_ptr = (uint8_t *)malloc(5);
    duplicate->address->addr_len = 5;
    memset(duplicate->address->addr_ptr, '1', 5);
    duplicate->address->port = 1000;
    duplicate->msg_id = 100;
    ns_list_add_to_end(&handle->linked_list_duplication_msgs, duplicate);

    ASSERT_TRUE(0 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    ns_list_remove(&handle->linked_list_duplication_msgs, duplicate);
    free(duplicate->address->addr_ptr);
    free(duplicate->address);
    free(duplicate->packet_ptr);
    free(duplicate);

    hdr.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    hdr.payload_ptr = (uint8_t *)malloc(SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20);
    memset(hdr.payload_ptr, '1', SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20);
    hdr.payload_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;

    sn_coap_builder_stub.expectedInt16 = -3;
//    ASSERT_TRUE( -2 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    retCounter = 0;
    hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    hdr.options_list_ptr->block1 = 67777;

    ASSERT_TRUE(-3 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));
    free(hdr.options_list_ptr);
    hdr.options_list_ptr = NULL;

    retCounter = 2;
    ASSERT_TRUE(-3 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    free(hdr.options_list_ptr);
    hdr.options_list_ptr = NULL;

    hdr.payload_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    hdr.msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
    hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    hdr.options_list_ptr->block2 = 1;
    retCounter = 0;

    ASSERT_TRUE(-3 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));
    free(hdr.options_list_ptr);
    hdr.options_list_ptr = NULL;

    free(hdr.payload_ptr);
    hdr.payload_ptr = NULL;
    hdr.payload_len = 0;

    //Test variations of sn_coap_convert_block_size here -->
    for (int i = 0; i < 8; i++) {
        uint16_t multiplier = 16 * pow(2, i);
        sn_coap_protocol_set_block_size(handle, multiplier);
        hdr.payload_ptr = (uint8_t *)malloc(multiplier + 20);
        memset(hdr.payload_ptr, '1', multiplier + 20);
        hdr.payload_len = multiplier + 20;
        retCounter = 2;
        hdr.msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        ASSERT_TRUE(-3 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));
        hdr.msg_code = COAP_MSG_CODE_EMPTY;

        free(hdr.options_list_ptr);
        hdr.options_list_ptr = NULL;

        free(hdr.payload_ptr);
        hdr.payload_ptr = NULL;
        hdr.payload_len = 0;
    }
    sn_coap_protocol_set_block_size(handle, SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE);

    // <-- Test variations of sn_coap_convert_block_size here

    retCounter = 1;
    sn_coap_builder_stub.expectedInt16 = -1;
    ASSERT_TRUE(-1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    retCounter = 6;
    sn_coap_builder_stub.expectedInt16 = 1;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    hdr.msg_code = COAP_MSG_CODE_EMPTY;

    retCounter = 7;
    sn_coap_builder_stub.expectedInt16 = 1;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    retCounter = 8;
    sn_coap_builder_stub.expectedInt16 = 1;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    retCounter = 9;
    sn_coap_builder_stub.expectedInt16 = 1;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    retCounter = 10;
    sn_coap_builder_stub.expectedInt16 = 1;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    // Test second SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE -->
    hdr.payload_ptr = (uint8_t *)malloc(SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20);
    memset(hdr.payload_ptr, '1', SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20);
    hdr.payload_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;

    sn_coap_protocol_clear_retransmission_buffer(handle);
    retCounter = 7;
    sn_coap_builder_stub.expectedInt16 = 1;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));
    free(hdr.payload_ptr);

    hdr.payload_ptr = (uint8_t *)malloc(SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20);
    memset(hdr.payload_ptr, '1', SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20);
    hdr.payload_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;

    retCounter = 8;
    sn_coap_builder_stub.expectedInt16 = 1;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    free(hdr.payload_ptr);
    hdr.payload_ptr = (uint8_t *)malloc(UINT16_MAX);
    memset(hdr.payload_ptr, '1', UINT16_MAX);
    hdr.payload_len = UINT16_MAX;

    retCounter = 9;
    sn_coap_builder_stub.expectedInt16 = 1;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    free(hdr.payload_ptr);
    hdr.payload_ptr = (uint8_t *)malloc(UINT16_MAX - 1);
    memset(hdr.payload_ptr, '1', UINT16_MAX - 1);
    hdr.payload_len = UINT16_MAX - 1;

    retCounter = 10;
    sn_coap_builder_stub.expectedInt16 = 1;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    sn_coap_protocol_destroy(handle);
    handle = NULL;
    retCounter = 1;
    handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);
    free(hdr.options_list_ptr);
    hdr.options_list_ptr = NULL;

    //Test sn_coap_protocol_copy_header here -->
    retCounter = 4;
    sn_coap_builder_stub.expectedInt16 = 1;
    hdr.payload_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    ASSERT_TRUE(-2 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    free(hdr.options_list_ptr);
    hdr.options_list_ptr = NULL;

    sn_coap_hdr_s *hdr2 = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(hdr2, 0, sizeof(sn_coap_hdr_s));
    hdr2->msg_type = COAP_MSG_TYPE_NON_CONFIRMABLE;
    hdr2->uri_path_ptr = (uint8_t *)malloc(3);
    hdr2->uri_path_len = 3;
    hdr2->token_ptr = (uint8_t *)malloc(3);
    hdr2->token_len = 3;
    hdr2->content_format = COAP_CT_TEXT_PLAIN;

    hdr2->options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(hdr2->options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    hdr2->options_list_ptr->accept = COAP_CT_TEXT_PLAIN;
    hdr2->options_list_ptr->block1 = 67777;
    hdr2->options_list_ptr->block2 = 67777;
    hdr2->options_list_ptr->etag_ptr = (uint8_t *)malloc(3);
    hdr2->options_list_ptr->etag_len = 3;
    hdr2->options_list_ptr->location_path_ptr = (uint8_t *)malloc(3);
    hdr2->options_list_ptr->location_path_len = 3;
    hdr2->options_list_ptr->location_query_ptr = (uint8_t *)malloc(3);
    hdr2->options_list_ptr->location_query_len = 3;
    hdr2->options_list_ptr->max_age = 3;
    hdr2->options_list_ptr->observe = 0;
    hdr2->options_list_ptr->proxy_uri_ptr = (uint8_t *)malloc(3);
    hdr2->options_list_ptr->proxy_uri_len = 3;
    hdr2->options_list_ptr->uri_host_ptr = (uint8_t *)malloc(3);
    hdr2->options_list_ptr->uri_host_len = 3;
    hdr2->options_list_ptr->uri_port = 3;
    hdr2->options_list_ptr->uri_query_ptr = (uint8_t *)malloc(3);
    hdr2->options_list_ptr->uri_query_len = 3;
    hdr2->options_list_ptr->use_size1 = true;
    hdr2->options_list_ptr->size1 = 0xFFFF01;

    int buff_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    hdr2->payload_ptr = (uint8_t *)malloc(buff_len);

    for (int i = 1; i <= 11; i++) {
        retCounter = i;
        sn_coap_builder_stub.expectedInt16 = 1;
        hdr2->payload_len = buff_len;
        int8_t rett = sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, hdr2, NULL);
        ASSERT_TRUE(-2 == rett);
    }

    retCounter = 12;
    sn_coap_builder_stub.expectedInt16 = 1;
    hdr2->payload_len = buff_len;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, hdr2, NULL));

    retCounter = 12;
    sn_coap_builder_stub.expectedInt16 = 1;
    hdr2->payload_len = buff_len;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, hdr2, NULL));

    free(hdr2->payload_ptr);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, hdr2);
    hdr2 = NULL;

    //<-- Test sn_coap_protocol_copy_header here

    hdr.msg_code = COAP_MSG_CODE_REQUEST_GET;
    retCounter = 7;
    sn_coap_builder_stub.expectedInt16 = 1;
    hdr.payload_len = 0;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    sn_coap_protocol_destroy(handle);
    handle = NULL;
    retCounter = 1;
    handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);

    retCounter = 4;
    sn_coap_builder_stub.expectedInt16 = 1;
    hdr.payload_len = 0;
    ASSERT_TRUE(-2 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    retCounter = 8;
    sn_coap_builder_stub.expectedInt16 = 1;
    hdr.payload_len = 0;
    ASSERT_TRUE(1 == sn_coap_protocol_build(handle, &addr, dst_packet_data_ptr, &hdr, NULL));

    free(hdr.payload_ptr);
    hdr.payload_ptr = NULL;
    hdr.payload_len = 0;

    hdr.msg_code = COAP_MSG_CODE_EMPTY;

    // <-- Test second SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE

    free(addr.addr_ptr);
    free(dst_packet_data_ptr);
    sn_coap_protocol_destroy(handle);
}

TEST_F(libCoap_protocol, sn_coap_protocol_parse)
{
    ASSERT_TRUE(NULL == sn_coap_protocol_parse(NULL, NULL, 0, NULL, NULL));
    retCounter = 1;
    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, null_rx_cb);

    sn_nsdl_addr_s *addr = (sn_nsdl_addr_s *)malloc(sizeof(sn_nsdl_addr_s));
    memset(addr, 0, sizeof(sn_nsdl_addr_s));

    addr->addr_ptr = (uint8_t *)malloc(5);

    uint8_t *packet_data_ptr = (uint8_t *)malloc(5);
    uint16_t packet_data_len = 5;

    sn_coap_parser_stub.expectedHeader = NULL;
    ASSERT_TRUE(NULL == sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL));

    // Failed to parse CoAP header
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_header_check_stub.expectedInt8 = 1;
    sn_coap_parser_stub.expectedHeader->coap_status = COAP_STATUS_PARSER_ERROR_IN_HEADER;
    ASSERT_TRUE(NULL == sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL));

    // sn_coap_protocol_parse - message code not valid!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_header_check_stub.expectedInt8 = 1;
    sn_coap_parser_stub.expectedHeader->msg_code = sn_coap_msg_code_e(COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED + 60);
    ASSERT_TRUE(NULL == sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL));

    // Send reset message
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_header_check_stub.expectedInt8 = 0;

    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_EMPTY;

    ASSERT_TRUE(NULL == sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL));

    test_block1_receive(handle, addr, packet_data_len, packet_data_ptr);

    test_block1_send(handle, addr, packet_data_len, packet_data_ptr);

    test_block2_receive(handle, addr, packet_data_len, packet_data_ptr);

    test_block2_send(handle, addr, packet_data_len, packet_data_ptr);

    free(packet_data_ptr);
    free(addr->addr_ptr);
    free(addr);

    sn_coap_protocol_destroy(handle);
}


TEST_F(libCoap_protocol, sn_coap_protocol_exec)
{
    ASSERT_TRUE(-1 == sn_coap_protocol_exec(NULL, 0));

    retCounter = 1;
    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);

    sn_nsdl_addr_s tmp_addr;
    memset(&tmp_addr, 0, sizeof(sn_nsdl_addr_s));
    sn_coap_hdr_s tmp_hdr;
    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));

    uint8_t *dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    tmp_addr.addr_ptr = (uint8_t *)malloc(5);
    memset(tmp_addr.addr_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 5;
    int buff_size = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_size);
    tmp_hdr.msg_id = 18;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = buff_size;
    sn_coap_protocol_build(handle, &tmp_addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(tmp_addr.addr_ptr);
    free(dst_packet_data_ptr);

    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 7;

    sn_coap_options_list_s *list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;
    uint8_t *payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;

    uint8_t *packet_data_ptr = (uint8_t *)malloc(5);
    uint16_t packet_data_len = 5;

    sn_nsdl_addr_s *addr = (sn_nsdl_addr_s *)malloc(sizeof(sn_nsdl_addr_s));
    memset(addr, 0, sizeof(sn_nsdl_addr_s));

    addr->addr_ptr = (uint8_t *)malloc(5);

    retCounter = 5;
    sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    free(payload);
    free(packet_data_ptr);
    free(addr->addr_ptr);
    free(addr);

    ASSERT_TRUE(0 == sn_coap_protocol_exec(handle, 600));

    sn_coap_builder_stub.expectedInt16 = 0;
    retCounter = 0;
    sn_coap_protocol_destroy(handle);
}

TEST_F(libCoap_protocol, sn_coap_protocol_exec2)
{
    retCounter = 1;
    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, null_rx_cb);

    sn_nsdl_addr_s tmp_addr;
    memset(&tmp_addr, 0, sizeof(sn_nsdl_addr_s));
    sn_coap_hdr_s tmp_hdr;
    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));

    uint8_t *dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    tmp_addr.addr_ptr = (uint8_t *)malloc(5);
    memset(tmp_addr.addr_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 5;
    int buf_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buf_len);
    tmp_hdr.msg_id = 18;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = buf_len;
    sn_coap_protocol_build(handle, &tmp_addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(tmp_addr.addr_ptr);
    free(dst_packet_data_ptr);

    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 7;

    sn_coap_options_list_s *list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;
    uint8_t *payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;

    uint8_t *packet_data_ptr = (uint8_t *)malloc(5);
    uint16_t packet_data_len = 5;

    sn_nsdl_addr_s *addr = (sn_nsdl_addr_s *)malloc(sizeof(sn_nsdl_addr_s));
    memset(addr, 0, sizeof(sn_nsdl_addr_s));

    addr->addr_ptr = (uint8_t *)malloc(5);

    retCounter = 5;
    sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    free(payload);
    free(packet_data_ptr);
    free(addr->addr_ptr);
    free(addr);

    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));

    sn_coap_protocol_set_retransmission_parameters(handle, 0, 5);
    ASSERT_TRUE(0 == sn_coap_protocol_exec(handle, 600));

    sn_coap_builder_stub.expectedInt16 = 0;
    retCounter = 0;
    sn_coap_protocol_destroy(handle);
}

TEST_F(libCoap_protocol, sn_coap_protocol_block_remove)
{
    sn_coap_protocol_block_remove(0, 0, 0, 0);
    retCounter = 9;
    sn_nsdl_addr_s *addr = (sn_nsdl_addr_s *)malloc(sizeof(sn_nsdl_addr_s));
    memset(addr, 0, sizeof(sn_nsdl_addr_s));
    addr->addr_ptr = (uint8_t *)malloc(5);
    memset(addr->addr_ptr, 'a', 5);
    addr->addr_len = 5;
    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);
    uint8_t *packet_data_ptr = (uint8_t *)malloc(5);
    memset(packet_data_ptr, 'x', 5);
    uint16_t packet_data_len = 5;
    sn_coap_parser_stub.expectedHeader = NULL;
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 13;

    sn_coap_options_list_s *list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_PUT;
    uint8_t *payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = packet_data_ptr;
    sn_coap_parser_stub.expectedHeader->payload_len = packet_data_len;
    sn_coap_builder_stub.expectedUint16 = 1;

    // Success
    retCounter = 19;
    sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 1);
    sn_coap_protocol_block_remove(handle, addr, packet_data_len, packet_data_ptr);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);

    // Ports does not match
    retCounter = 19;
    sn_coap_parser_stub.expectedHeader->msg_id = 14;
    addr->port = 5600;
    sn_coap_protocol_set_block_size(handle, 32);
    sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 1);
    addr->port = 5601;
    sn_coap_protocol_block_remove(handle, addr, packet_data_len, packet_data_ptr);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 1);

    // Addresses does not match
    retCounter = 19;
    sn_coap_parser_stub.expectedHeader->msg_id = 15;
    sn_coap_protocol_set_block_size(handle, 64);
    sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 2);
    addr->addr_ptr[0] = 'x';
    sn_coap_protocol_block_remove(handle, addr, packet_data_len, packet_data_ptr);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 2);

    // Payload length does not match
    addr->addr_ptr[0] = 'a';
    sn_coap_protocol_block_remove(handle, addr, packet_data_len + 1, packet_data_ptr);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 2);

    free(sn_coap_parser_stub.expectedHeader->options_list_ptr);
    free(sn_coap_parser_stub.expectedHeader);
    free(addr->addr_ptr);
    free(addr);
    free(payload);
    free(packet_data_ptr);
    sn_coap_protocol_destroy(handle);
}

TEST_F(libCoap_protocol, sn_coap_protocol_remove_sent_blockwise_message)
{
    sn_coap_protocol_remove_sent_blockwise_message(0, 0);
    retCounter = 9;
    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);
    coap_blockwise_msg_s *message = (coap_blockwise_msg_s *)malloc(sizeof(coap_blockwise_msg_s));
    memset(message, 0, sizeof(coap_blockwise_msg_s));
    message->coap_msg_ptr = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(message->coap_msg_ptr, 0, sizeof(sn_coap_hdr_s));
    message->coap_msg_ptr->msg_id = 100;
    ns_list_add_to_end(&handle->linked_list_blockwise_sent_msgs, message);
    sn_coap_protocol_remove_sent_blockwise_message(handle, 1);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_sent_msgs) == 1);

    sn_coap_protocol_remove_sent_blockwise_message(handle, 100);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_sent_msgs) == 0);
    sn_coap_protocol_destroy(handle);
}

TEST_F(libCoap_protocol, sn_coap_protocol_handle_block2_response_internally)
{
    sn_coap_protocol_handle_block2_response_internally(0, 0);
    retCounter = 9;
    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);
    sn_coap_protocol_handle_block2_response_internally(handle, true);
    ASSERT_TRUE(handle->sn_coap_internal_block2_resp_handling == true);
    sn_coap_protocol_handle_block2_response_internally(handle, false);
    ASSERT_TRUE(handle->sn_coap_internal_block2_resp_handling == false);
    sn_coap_protocol_destroy(handle);
}

TEST_F(libCoap_protocol, sn_coap_protocol_get_configured_blockwise_size)
{
    retCounter = 9;
    struct coap_s *handle = sn_coap_protocol_init(myMalloc, myFree, null_tx_cb, NULL);
    ASSERT_TRUE(sn_coap_protocol_get_configured_blockwise_size(handle) == SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE);
    sn_coap_protocol_destroy(handle);
}

void test_block1_receive(struct coap_s *handle, sn_nsdl_addr_s *addr, uint16_t packet_data_len, uint8_t *packet_data_ptr)
{
    // sn_coap_protocol_linked_list_blockwise_payload_store - failed addr_ptr null
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));

    sn_coap_options_list_s *list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->msg_id = 4;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    sn_coap_hdr_s *ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);

    // sn_coap_protocol_linked_list_blockwise_payload_store - failed to allocate blockwise!
    uint8_t *payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->msg_id = 4;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);
    free(payload);

    // sn_coap_protocol_linked_list_blockwise_payload_store - failed to allocate payload!
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->msg_id = 4;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 4;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);
    free(payload);

    // sn_coap_protocol_linked_list_blockwise_payload_store - failed to allocate address pointer!
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->msg_id = 5;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 5;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);
    free(payload);

    // sn_coap_protocol_linked_list_blockwise_payload_store - failed to allocate token pointer!
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    uint32_t token = 1000;
    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->msg_id = 6;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 6;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);
    free(payload);

    // sn_coap_protocol_linked_list_blockwise_payload_store - success
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->msg_id = 7;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 8;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 1);
    free(payload);
#if !SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT
    free(sn_coap_parser_stub.expectedHeader->payload_ptr);
#endif
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);


    // sn_coap_protocol_linked_list_blockwise_payload_store - success, reallocate
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x10;
    sn_coap_parser_stub.expectedHeader->msg_id = 8;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 7;
    // Update existing block data payload
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 1);
    ASSERT_TRUE(ret->payload_len == 10);
#if !SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT
    free(sn_coap_parser_stub.expectedHeader->payload_ptr);
#endif
    free(payload);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);

    // sn_coap_protocol_linked_list_blockwise_payload_store - failed to allocate temp buffer!
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x20;
    sn_coap_parser_stub.expectedHeader->msg_id = 9;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 3;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    free(payload);

    // sn_coap_protocol_linked_list_blockwise_payload_store - success
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->msg_id = 700;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 8;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 1);
    free(payload);
#if !SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT
    free(sn_coap_parser_stub.expectedHeader->payload_ptr);
#endif
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);

    // sn_coap_protocol_linked_list_blockwise_payload_store - failed to reallocate payload!
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x20;
    sn_coap_parser_stub.expectedHeader->msg_id = 701;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 4;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    free(payload);


    // sn_coap_protocol_linked_list_blockwise_payload_store - success, size1 present
    payload = (uint8_t *)malloc(16);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 16;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->size1 = 20;
    sn_coap_parser_stub.expectedHeader->msg_id = 10;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 8;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 1);
    free(payload);

#if !SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT
    free(sn_coap_parser_stub.expectedHeader->payload_ptr);
#endif

    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);


    // sn_coap_protocol_linked_list_blockwise_payload_store - success, size1, update block payload
    payload = (uint8_t *)malloc(4);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 4;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x10;
    sn_coap_parser_stub.expectedHeader->msg_id = 11;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 7;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 1);
    ASSERT_TRUE(ret->payload_len == 20);

#if !SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT
    free(sn_coap_parser_stub.expectedHeader->payload_ptr);
#endif

    free(payload);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    sn_coap_protocol_clear_received_blockwise_messages(handle);
    // end of sn_coap_protocol_linked_list_blockwise_payload_store() testing

    // continue block1 testing -->

    // sn_coap_handle_blockwise_message - (recv block1) failed to allocate ack message!
    payload = (uint8_t *)malloc(16);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 16;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x08;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->size1 = 16;
    sn_coap_parser_stub.expectedHeader->msg_id = 12;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 3;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);
    free(payload);


    // sn_coap_handle_blockwise_message - (recv block1) COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE!
    payload = (uint8_t *)malloc(16);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 16;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x08;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->size1 = SN_COAP_MAX_INCOMING_BLOCK_MESSAGE_SIZE + 1;
    sn_coap_parser_stub.expectedHeader->msg_id = 13;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 8;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    free(payload);

    // sn_coap_handle_blockwise_message - (recv block1) block size1 bigger than configured block size
    payload = (uint8_t *)malloc(16);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 16;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    // Block1 size 128 bytes
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x1b;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->size1 = 16;
    sn_coap_parser_stub.expectedHeader->msg_id = 14;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_GET;

    retCounter = 8;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    sn_coap_protocol_clear_received_blockwise_messages(handle);
    free(payload);

    // sn_coap_protocol_update_duplication_package_data - failed to allocate duplication info!
    payload = (uint8_t *)malloc(16);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 16;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x08;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->size1 = 16;
    sn_coap_parser_stub.expectedHeader->msg_id = 15;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_POST;

    retCounter = 7;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);
    free(payload);

    // sn_coap_handle_blockwise_message - (recv block1) message allocation failed!
    payload = (uint8_t *)malloc(16);
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 16;

    sn_coap_parser_stub.expectedHeader->token_len = sizeof(uint32_t);
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(sizeof(uint32_t));
    memcpy(sn_coap_parser_stub.expectedHeader->token_ptr, &token, sizeof(uint32_t));

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x08;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->size1 = 16;
    sn_coap_parser_stub.expectedHeader->msg_id = 16;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_DELETE;

    retCounter = 5;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_received_payloads) == 0);
    free(payload);
}

void test_block1_send(struct coap_s *handle, sn_nsdl_addr_s *addr, uint16_t packet_data_len, uint8_t *packet_data_ptr)
{
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 15;

    sn_coap_options_list_s *list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x00;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    uint8_t *payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;

    retCounter = 2;
    sn_coap_hdr_s *ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL != ret);

#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT && SN_COAP_DUPLICATION_MAX_MSGS_COUNT > 1
    ASSERT_TRUE(COAP_STATUS_PARSER_DUPLICATED_MSG == ret->coap_status);
#else
    ASSERT_TRUE(COAP_STATUS_OK == ret->coap_status);
#endif
    free(payload);
    free(list);
    free(sn_coap_parser_stub.expectedHeader);

    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 15;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;

    retCounter = 2;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL != ret);
#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT && SN_COAP_DUPLICATION_MAX_MSGS_COUNT > 1
    ASSERT_TRUE(COAP_STATUS_PARSER_DUPLICATED_MSG == ret->coap_status);
#else
    ASSERT_TRUE(COAP_STATUS_PARSER_BLOCKWISE_ACK == ret->coap_status);
#endif
    free(payload);
    free(list);
    free(sn_coap_parser_stub.expectedHeader);

    // sn_coap_handle_blockwise_message - (send block1) - success
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 16;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CONTINUE;
    payload = (uint8_t *)malloc(16);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 16;

    sn_coap_hdr_s tmp_hdr;
    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));

    uint8_t *dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    int buff_size = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 17;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_size);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.options_list_ptr->block1 = 0x08;
    tmp_hdr.msg_id = 16;
    tmp_hdr.payload_len = buff_size;

    // Create block message to sent blockwise list
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(dst_packet_data_ptr);

    retCounter = 7;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL != ret);
#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT && SN_COAP_DUPLICATION_MAX_MSGS_COUNT > 1
    ASSERT_TRUE(COAP_STATUS_PARSER_DUPLICATED_MSG == ret->coap_status);
#else
    ASSERT_TRUE(COAP_STATUS_PARSER_BLOCKWISE_ACK == ret->coap_status);
#endif
    free(payload);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (send block1) - success - last block
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 17;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x18;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(16);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 16;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    buff_size = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 17;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_size);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.options_list_ptr->block1 = 0x18;
    tmp_hdr.msg_id = 17;
    tmp_hdr.payload_len = buff_size;

    // Create block message to sent blockwise list
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(dst_packet_data_ptr);

    retCounter = 7;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL != ret);
    ASSERT_TRUE(ret->coap_status == COAP_STATUS_PARSER_BLOCKWISE_ACK);
    // Last block sent, list should be empty now
    ASSERT_TRUE(ns_list_count(&handle->linked_list_blockwise_sent_msgs) == 0);
    free(payload);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (send block1) failed to allocate ack message!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 18;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x18;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(16);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 16;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    buff_size = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 17;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_size);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.options_list_ptr->block1 = 0x18;
    tmp_hdr.msg_id = 18;
    tmp_hdr.payload_len = buff_size;

    // Create block message to sent blockwise list
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(dst_packet_data_ptr);

    retCounter = 3;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);

    // sn_coap_handle_blockwise_message - (send block1) failed to allocate ack message!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 19;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0xe808;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);
    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(UINT16_MAX);
    tmp_hdr.msg_id = 19;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = UINT16_MAX;
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);
    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    tmp_hdr.payload_ptr = NULL;
    free(dst_packet_data_ptr);
    free(payload);

    retCounter = 2;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);

    // block1 response not in order, request stays in resend queue
    sn_coap_protocol_clear_retransmission_buffer(handle);

    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_id = 20;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x18;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CONTINUE;
    payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;

    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    sn_coap_builder_stub.expectedInt16 = 1;
    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));

    retCounter = 7;
    sn_coap_builder_stub.expectedInt16 = 1;
    buff_size = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 17;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_size);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.options_list_ptr->block1 = 0x28;
    tmp_hdr.msg_id = 20;
    tmp_hdr.payload_len = buff_size;
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_resent_msgs) == 1);
    ASSERT_TRUE(NULL != ret);
    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    tmp_hdr.payload_ptr = NULL;
    free(dst_packet_data_ptr);
    free(payload);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);

    // block1 final response comes too early, request stays in resend queue
    sn_coap_protocol_clear_retransmission_buffer(handle);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);

    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_id = 21;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = 0x07;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CONTINUE;
    payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;

    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    sn_coap_builder_stub.expectedInt16 = 1;
    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));

    retCounter = 7;
    sn_coap_builder_stub.expectedInt16 = 1;
    buff_size = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 17;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_size);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.options_list_ptr->block1 = 0x08;
    tmp_hdr.msg_id = 21;
    tmp_hdr.payload_len = buff_size;
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ns_list_count(&handle->linked_list_resent_msgs) == 1);
    ASSERT_TRUE(NULL != ret);
    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    tmp_hdr.payload_ptr = NULL;
    free(dst_packet_data_ptr);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);

    free(payload);
    sn_coap_protocol_clear_retransmission_buffer(handle);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
}

void test_block2_receive(struct coap_s *handle, sn_nsdl_addr_s *addr, uint16_t packet_data_len, uint8_t *packet_data_ptr)
{
    // sn_coap_handle_blockwise_message - (recv block2) success - set more - bit
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 20;

    sn_coap_options_list_s *list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_DELETE;
    uint8_t *payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;
    sn_coap_parser_stub.expectedHeader->token_len = 4;
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(4);
    memset(sn_coap_parser_stub.expectedHeader->token_ptr, '1', 4);

    sn_coap_hdr_s tmp_hdr;
    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));

    uint8_t *dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    int buff_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);

    tmp_hdr.msg_id = 20;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = buff_len;
    tmp_hdr.token_len = 4;
    tmp_hdr.token_ptr = (uint8_t *)malloc(4);
    memset(tmp_hdr.token_ptr, '1', 4);
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    tmp_hdr.payload_ptr = NULL;
    free(tmp_hdr.token_ptr);
    tmp_hdr.token_ptr = NULL;
    free(dst_packet_data_ptr);

    retCounter = 7;
    sn_coap_hdr_s *ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL != ret);
    ASSERT_TRUE(COAP_STATUS_PARSER_BLOCKWISE_ACK == ret->coap_status);
    free(payload);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (recv block2) success - last block
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 21;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x1b;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_DELETE;
    payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;
    sn_coap_parser_stub.expectedHeader->token_len = 4;
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(4);
    memset(sn_coap_parser_stub.expectedHeader->token_ptr, '1', 4);

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    buff_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);

    tmp_hdr.msg_id = 21;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = buff_len;
    tmp_hdr.token_len = 4;
    tmp_hdr.token_ptr = (uint8_t *)malloc(4);
    memset(tmp_hdr.token_ptr, '1', 4);
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    tmp_hdr.payload_ptr = NULL;
    free(tmp_hdr.token_ptr);
    tmp_hdr.token_ptr = NULL;
    free(dst_packet_data_ptr);

    retCounter = 7;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL != ret);
    ASSERT_TRUE(COAP_STATUS_PARSER_BLOCKWISE_ACK == ret->coap_status);
    free(payload);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (recv block2) failed to allocate packet!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 22;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_DELETE;
    payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;
    sn_coap_parser_stub.expectedHeader->token_len = 4;
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(4);
    memset(sn_coap_parser_stub.expectedHeader->token_ptr, '1', 4);

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);

    tmp_hdr.msg_id = 22;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = buff_len;
    tmp_hdr.token_len = 4;
    tmp_hdr.token_ptr = (uint8_t *)malloc(4);
    memset(tmp_hdr.token_ptr, '1', 4);
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    tmp_hdr.payload_ptr = NULL;
    free(tmp_hdr.token_ptr);
    tmp_hdr.token_ptr = NULL;
    free(dst_packet_data_ptr);

    retCounter = 5;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (recv block2) failed to allocate options!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 23;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_REQUEST_DELETE;
    payload = (uint8_t *)malloc(17);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 17;
    sn_coap_parser_stub.expectedHeader->token_len = 4;
    sn_coap_parser_stub.expectedHeader->token_ptr = (uint8_t *)malloc(4);
    memset(sn_coap_parser_stub.expectedHeader->token_ptr, '1', 4);

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);

    tmp_hdr.msg_id = 23;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = buff_len;
    tmp_hdr.token_len = 4;
    tmp_hdr.token_ptr = (uint8_t *)malloc(4);
    memset(tmp_hdr.token_ptr, '1', 4);
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    tmp_hdr.payload_ptr = NULL;
    free(tmp_hdr.token_ptr);
    tmp_hdr.token_ptr = NULL;
    free(dst_packet_data_ptr);

    retCounter = 3;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    free(payload);
    sn_coap_protocol_clear_retransmission_buffer(handle);
}

void test_block2_send(struct coap_s *handle, sn_nsdl_addr_s *addr, uint16_t packet_data_len, uint8_t *packet_data_ptr)
{
    // sn_coap_handle_blockwise_message - (send block2) previous message null!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    sn_coap_options_list_s *list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 30;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    uint8_t *payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    sn_coap_hdr_s *ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    free(payload);

    // sn_coap_handle_blockwise_message - (send block2) failed to allocate message!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 31;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    sn_coap_hdr_s tmp_hdr;
    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));

    uint8_t *dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    int buff_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.msg_id = 31;
    tmp_hdr.payload_len = buff_len;
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(dst_packet_data_ptr);

    retCounter = 0;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL == ret);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);

    // sn_coap_handle_blockwise_message - (send block2) success!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 32;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.msg_id = 32;
    tmp_hdr.payload_len = buff_len;
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(dst_packet_data_ptr);

    retCounter = 10;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - COAP_STATUS_PARSER_DUPLICATED_MSG
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 32;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.msg_id = 32;
    tmp_hdr.payload_len = buff_len;
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(dst_packet_data_ptr);

    retCounter = 10;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret->coap_status == COAP_STATUS_PARSER_DUPLICATED_MSG);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (send block2) success - token + uri!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 33;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.msg_id = 33;
    tmp_hdr.payload_len = buff_len;

    tmp_hdr.uri_path_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.uri_path_len = buff_len;
    tmp_hdr.token_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.token_len = buff_len;

    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(tmp_hdr.uri_path_ptr);
    free(tmp_hdr.token_ptr);
    free(dst_packet_data_ptr);

    retCounter = 10;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - failed to allocate for uri path ptr!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 34;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.msg_id = 34;
    tmp_hdr.payload_len = buff_len;

    tmp_hdr.uri_path_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.uri_path_len = buff_len;
    tmp_hdr.token_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.token_len = buff_len;

    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(tmp_hdr.uri_path_ptr);
    free(tmp_hdr.token_ptr);
    free(dst_packet_data_ptr);

    retCounter = 5;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - failed to allocate for token ptr!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 35;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.msg_id = 35;
    tmp_hdr.payload_len = buff_len;

    tmp_hdr.uri_path_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.uri_path_len = buff_len;
    tmp_hdr.token_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.token_len = buff_len;

    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(tmp_hdr.uri_path_ptr);
    free(tmp_hdr.token_ptr);
    free(dst_packet_data_ptr);

    retCounter = 6;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (send block2) failed to allocate packet!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 36;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.msg_id = 36;
    tmp_hdr.payload_len = buff_len;

    tmp_hdr.uri_path_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.uri_path_len = buff_len;
    tmp_hdr.token_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.token_len = buff_len;

    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(tmp_hdr.uri_path_ptr);
    free(tmp_hdr.token_ptr);
    free(dst_packet_data_ptr);

    retCounter = 7;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (send block2) failed to allocate blockwise message!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 37;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 1;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.msg_id = 37;
    tmp_hdr.payload_len = buff_len;

    tmp_hdr.uri_path_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.uri_path_len = buff_len;
    tmp_hdr.token_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.token_len = buff_len;

    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(tmp_hdr.uri_path_ptr);
    free(tmp_hdr.token_ptr);
    free(dst_packet_data_ptr);

    retCounter = 8;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (send block2) builder failed!
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 0x08;
    sn_coap_parser_stub.expectedHeader->msg_id = 38;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);

    retCounter = 20;

    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->block2 = 1;
    tmp_hdr.msg_id = 38;
    tmp_hdr.payload_len = buff_len;

    tmp_hdr.uri_path_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.uri_path_len = buff_len;
    tmp_hdr.token_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.token_len = buff_len;

    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(tmp_hdr.uri_path_ptr);
    free(tmp_hdr.token_ptr);
    free(dst_packet_data_ptr);

    retCounter = 10;
    sn_coap_builder_stub.expectedInt16 = -1;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret == NULL);
    free(payload);
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);

    // sn_coap_handle_blockwise_message - (send block2) last block
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;

    list = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(list, 0, sizeof(sn_coap_options_list_s));
    sn_coap_parser_stub.expectedHeader->options_list_ptr = list;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block1 = -1;
    sn_coap_parser_stub.expectedHeader->options_list_ptr->block2 = 1;
    sn_coap_parser_stub.expectedHeader->msg_id = 41;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    payload = (uint8_t *)malloc(5);
    sn_coap_parser_stub.expectedHeader->payload_ptr = payload;
    sn_coap_parser_stub.expectedHeader->payload_len = 5;

    retCounter = 10;
    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(NULL != ret);
    ASSERT_TRUE(ret->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED);
    free(payload);
#if !SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT
    free(sn_coap_parser_stub.expectedHeader->payload_ptr);
#endif
    sn_coap_protocol_clear_sent_blockwise_messages(handle);
    sn_coap_protocol_clear_retransmission_buffer(handle);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, sn_coap_parser_stub.expectedHeader);

    // Do not clean stored blockwise message when empty ack is received
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 100;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));
    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);
    dst_packet_data_ptr[2] = 0;
    dst_packet_data_ptr[3] = 18;

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 5;
    buff_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.msg_id = 100;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = buff_len;
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(dst_packet_data_ptr);

    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret != NULL);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, ret);

    // Do not clean stored blockwise message when empty ack is received - remove from the list
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 101;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));

    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);
    dst_packet_data_ptr[2] = 0;
    dst_packet_data_ptr[3] = 185;

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 5;
    buff_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.msg_id = 101;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = buff_len;
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->observe = 1;
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(dst_packet_data_ptr);

    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret != NULL);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, ret);

    // Do not clean stored blockwise message when empty ack is received - remove from the list
    sn_coap_parser_stub.expectedHeader = (sn_coap_hdr_s *)malloc(sizeof(sn_coap_hdr_s));
    memset(sn_coap_parser_stub.expectedHeader, 0, sizeof(sn_coap_hdr_s));
    sn_coap_parser_stub.expectedHeader->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    sn_coap_parser_stub.expectedHeader->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    sn_coap_parser_stub.expectedHeader->msg_id = 101;

    memset(&tmp_hdr, 0, sizeof(sn_coap_hdr_s));

    dst_packet_data_ptr = (uint8_t *)malloc(5);
    memset(dst_packet_data_ptr, '1', 5);
    dst_packet_data_ptr[2] = 0;
    dst_packet_data_ptr[3] = 185;

    retCounter = 20;
    sn_coap_builder_stub.expectedInt16 = 5;
    buff_len = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE + 20;
    tmp_hdr.payload_ptr = (uint8_t *)malloc(buff_len);
    tmp_hdr.msg_id = 101;
    tmp_hdr.msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
    tmp_hdr.payload_len = buff_len;
    tmp_hdr.options_list_ptr = (sn_coap_options_list_s *)malloc(sizeof(sn_coap_options_list_s));
    memset(tmp_hdr.options_list_ptr, 0, sizeof(sn_coap_options_list_s));
    tmp_hdr.options_list_ptr->observe = 1;
    sn_coap_protocol_build(handle, addr, dst_packet_data_ptr, &tmp_hdr, NULL);

    free(tmp_hdr.options_list_ptr);
    free(tmp_hdr.payload_ptr);
    free(dst_packet_data_ptr);

    ret = sn_coap_protocol_parse(handle, addr, packet_data_len, packet_data_ptr, NULL);
    ASSERT_TRUE(ret != NULL);
    sn_coap_parser_release_allocated_coap_msg_mem(handle, ret);
}
