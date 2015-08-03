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
#include "ns_list.h"

void ns_list_init_(ns_list_t *list)
{
}

void ns_list_link_init_(ns_list_link_t *link)
{
}

void ns_list_add_to_start_(ns_list_t *list, ns_list_offset_t offset, void *restrict entry)
{
}

void ns_list_add_after_(ns_list_t *list, ns_list_offset_t offset, void *current, void *restrict entry)
{
}

void ns_list_add_before_(ns_list_offset_t offset, void *current, void *restrict entry)
{
}

void ns_list_add_to_end_(ns_list_t *list, ns_list_offset_t offset, void *restrict entry)
{
}

void *ns_list_get_next_(ns_list_offset_t offset, const void *current)
{
}

void *ns_list_get_previous_(const ns_list_t *list, ns_list_offset_t offset, const void *current)
{
}

void *ns_list_get_last_(const ns_list_t *list, ns_list_offset_t offset)
{
}

void ns_list_remove_(ns_list_t *list, ns_list_offset_t offset, void *removed)
{
}

void ns_list_replace_(ns_list_t *list, ns_list_offset_t offset, void *current, void *restrict replacement)
{
}

void ns_list_concatenate_(ns_list_t *dst, ns_list_t *src, ns_list_offset_t offset)
{
}

uint_fast16_t ns_list_count_(const ns_list_t *list, ns_list_offset_t offset)
{
}
