#include <stdio.h>
#include <stddef.h>

#include "pl_types.h"
#include "sn_linked_list.h"

SN_LINKED_LIST_FUNCTION_POINTER_MEMORY_ATTRIBUTE
void *(*sn_linked_list_memory_alloc)(uint16_t);
SN_LINKED_LIST_FUNCTION_POINTER_MEMORY_ATTRIBUTE
void (*sn_linked_list_memory_free)(void*);

SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
void sn_linked_list_init(void *(*linked_list_alloc_function)(uint16_t), void (*linked_list_free_function)(void*))
{

	sn_linked_list_memory_alloc = linked_list_alloc_function;
	sn_linked_list_memory_free = linked_list_free_function;
}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
sn_linked_list_t *sn_linked_list_create(void)
{

	sn_linked_list_t *new_linked_list = sn_linked_list_memory_alloc(sizeof(sn_linked_list_t));

	if(new_linked_list)
	{

		new_linked_list->first_node = NULL;
		new_linked_list->current_node = NULL;
		new_linked_list->node_count = 0;
	}

	return new_linked_list;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
int8_t sn_linked_list_free(sn_linked_list_t *linked_list)
{

	if(!linked_list)
	{
		return SN_LINKED_LIST_ERROR_INVALID_LIST_POINTER;
	}

	if(linked_list->first_node)
	{
		return SN_LINKED_LIST_ERROR_LIST_NOT_EMPTY;
	}

	sn_linked_list_memory_free(linked_list);

	return SN_LINKED_LIST_ERROR_NO_ERROR;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
int8_t sn_linked_list_add_node(sn_linked_list_t *linked_list, void *data)
{

	struct sn_linked_list_node *node_to_add = NULL;

	if(!linked_list)
	{
		return SN_LINKED_LIST_ERROR_INVALID_LIST_POINTER;
	}

	if(!data)
	{
		return SN_LINKED_LIST_ERROR_NO_DATA_TO_ADD;
	}

	node_to_add = sn_linked_list_memory_alloc(sizeof(struct sn_linked_list_node));

	if(!node_to_add)
	{

		return SN_LINKED_LIST_ERROR_DATA_ALLOCATOIN_FAILED;

	}

	node_to_add->data = data;
	node_to_add->next_node = linked_list->first_node;
	node_to_add->previous_node = NULL;

	if(linked_list->first_node)
	{
		linked_list->first_node->previous_node = node_to_add;
	}

	linked_list->first_node = node_to_add;

	linked_list->node_count++;

	return SN_LINKED_LIST_ERROR_NO_ERROR;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
void *sn_linked_list_get_first_node(sn_linked_list_t *linked_list)
{

	if(!linked_list)
	{
		return NULL;
	}

	if(linked_list->first_node)
	{

		linked_list->current_node = linked_list->first_node;
		return linked_list->first_node->data;

	}

	return NULL;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
void *sn_linked_list_get_next_node(sn_linked_list_t *linked_list)
{

	if(!linked_list)
	{
		return NULL;
	}
	if(!linked_list->current_node)
	{
		return NULL;
	}

	linked_list->current_node = linked_list->current_node->next_node;

	if(!linked_list->current_node)
	{
		return NULL;
	}

	return linked_list->current_node->data;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
void *sn_linked_list_get_current_node(sn_linked_list_t *linked_list)
{

	if(!linked_list)
	{
		return NULL;
	}
	if(!linked_list->current_node)
	{
		return NULL;
	}

	return linked_list->current_node->data;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
void *sn_linked_list_get_previous_node(sn_linked_list_t *linked_list)
{

	if(!linked_list)
	{
		return NULL;
	}
	if(!linked_list->current_node)
	{
		return NULL;
	}

	linked_list->current_node = linked_list->current_node->previous_node;

	if(!linked_list->current_node)
	{
		return NULL;
	}

	return linked_list->current_node->data;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
extern void *sn_linked_list_get_last_node(sn_linked_list_t *linked_list)
{

	if(!sn_linked_list_get_first_node(linked_list))
	{

		return NULL;

	}
	while(linked_list->current_node->next_node)
	{

		sn_linked_list_get_next_node(linked_list);

	}

	return linked_list->current_node->data;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
void *sn_linked_list_remove_current_node(sn_linked_list_t *linked_list)
{

	struct sn_linked_list_node *node_to_remove = NULL;
	void *data_from_removed_node = NULL;

	if(!linked_list)
	{
		return NULL;
	}
	if(!linked_list->current_node)
	{
		return NULL;
	}

	node_to_remove = linked_list->current_node;

	if(node_to_remove != linked_list->first_node)
	{

		node_to_remove->previous_node->next_node = node_to_remove->next_node;

		if(node_to_remove->next_node)
		{
			node_to_remove->next_node->previous_node = node_to_remove->previous_node;
		}

	}
	else
	{

		linked_list->first_node = node_to_remove->next_node;

		if(node_to_remove->next_node)
		{
			node_to_remove->next_node->previous_node =  NULL;
		}

	}

	if(!node_to_remove->next_node && node_to_remove->previous_node)
	{

		linked_list->current_node = node_to_remove->previous_node;

	}
	else
	{

		linked_list->current_node = node_to_remove->next_node;

	}

	data_from_removed_node = node_to_remove->data;

	sn_linked_list_memory_free(node_to_remove);

	linked_list->node_count--;

	return data_from_removed_node;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
int8_t sn_linked_list_update_current_node(sn_linked_list_t *linked_list, void *data)
{

	if(!linked_list)
	{
		return SN_LINKED_LIST_ERROR_INVALID_LIST_POINTER;
	}

	if(!data)
	{
		return SN_LINKED_LIST_ERROR_NO_DATA_TO_ADD;
	}
	if(!linked_list->current_node)
	{
		return SN_LINKED_LIST_ERROR_INVALID_LIST_POINTER;
	}

	linked_list->current_node->data = data;

	return SN_LINKED_LIST_ERROR_NO_ERROR;

}
SN_LINKED_LIST_FUNCTION_MEMORY_ATTRIBUTE
uint16_t sn_linked_list_count_nodes(sn_linked_list_t *linked_list)
{

	return linked_list->node_count;

}

/* EOF */
