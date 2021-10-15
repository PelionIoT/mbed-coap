/*
 * Copyright (c) 2014-2016, Pelion and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * \file randLIB.h
 * \brief Pseudo Random Library API:
 *
 *
 * \section net-boot Network Bootstrap Control API:
 *  - randLIB_seed_random(), Set seed for pseudo random
 *  - randLIB_get_8bit(), Generate 8-bit random number
 *  - randLIB_get_16bit(),Generate 16-bit random number
 *  - randLIB_get_32bit(),Generate 32-bit random number
 *  - randLIB_get_n_bytes_random(), Generate n-bytes random numbers
 *
 */

#ifndef RANDLIB_H_
#define RANDLIB_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This library is made for getting random numbers for Timing needs in protocols.
 *
 * **not safe to use for security or cryptographic operations.**
 *
 */
extern void randLIB_seed_random(void);
extern uint16_t randLIB_get_16bit(void);
extern uint32_t randLIB_get_32bit(void);
extern uint64_t randLIB_get_64bit(void);
extern void *randLIB_get_n_bytes_random(void *data_ptr, uint8_t count);
extern uint16_t randLIB_get_random_in_range(uint16_t min, uint16_t max);
extern uint32_t randLIB_randomise_base(uint32_t base, uint16_t min_factor, uint16_t max_factor);

#ifdef RANDLIB_PRNG
/* \internal Reset the PRNG state to zero (invalid) */
void randLIB_reset(void);
#endif


#ifdef __cplusplus
}
#endif
#endif /* RANDLIB_H_ */
