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
