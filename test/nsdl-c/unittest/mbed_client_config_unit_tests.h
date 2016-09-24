/*
 * Copyright (c) 2016 ARM Limited. All rights reserved.
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

#ifndef MBED_CLIENT_CONFIG_UNIT_TESTS_H
#define MBED_CLIENT_CONFIG_UNIT_TESTS_H

// dummy file to provide the definitions used by unit tests

// XXX: these can not be provided via makefile, as the sn_config.h undefs
// all defines even if the user's config file is not given. Perhaps the
// fix should be done there instead.

#define SN_COAP_DUPLICATION_MAX_MSGS_COUNT  4
#define SN_COAP_MAX_INCOMING_BLOCK_MESSAGE_SIZE 65535


#endif // MBED_CLIENT_CONFIG_UNIT_TESTS_H
