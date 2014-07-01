/*
 * sn_linked_list.h
 *
 *  Created on: 9.8.2011
 *      Author: user
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SN_LINKED_LIST_H_
#define SN_LINKED_LIST_H_

#define SN_LINKED_LIST_ERROR_NO_ERROR                0
#define SN_LINKED_LIST_ERROR_INVALID_LIST_POINTER    1
#define SN_LINKED_LIST_ERROR_LIST_NOT_EMPTY          2
#define SN_LINKED_LIST_ERROR_NO_DATA_TO_ADD          3
#define SN_LINKED_LIST_ERROR_DATA_ALLOCATOIN_FAILED  4
#define SN_LINKED_LIST_ERROR_NOTHING_TO_REMOVE       5

struct sn_linked_list_node
{
	struct sn_linked_list_node *next_node;
	struct sn_linked_list_node *previous_node;
	void *data;
};

typedef struct sn_linked_list_t_
{
	struct sn_linked_list_node *first_node;
	struct sn_linked_list_node *current_node;
	uint16_t node_count;
}sn_linked_list_t;

/* \brief This function MUST be called once before starting to use other functionalities in this file. */
extern void sn_linked_list_init(void *(*linked_list_alloc_function)(uint16_t), void (*linked_list_free_function)(void*));

/* \brief Creates a new linked list and returns a pointer to it, returns value NULL on allocation error */
extern sn_linked_list_t *sn_linked_list_create(void);

/* \brief Removes empty linked list.
 * Note that the list will NOT be removed unless it is empty */
extern int8_t sn_linked_list_free(sn_linked_list_t *linked_list);

/* \brief Adds node to a linked list */
extern int8_t sn_linked_list_add_node(sn_linked_list_t *linked_list, void *data);

/* \brief Returns a pointer to data on first node and sets it as a current node.
 * Returns NULL pointer if list is empty
 * Note that node first added to list is the last node on list and first node on list is the most recently added. */
extern void *sn_linked_list_get_first_node(sn_linked_list_t *linked_list);

/* \brief Returns a pointer to next node and a NULL pointer if next node does not exist
 * Note that you need to call sn_linked_list_get_first_node or
 * sn_linked_list_get_last_node and sn_linked_list_get_previous_node before using this function */
extern void *sn_linked_list_get_next_node(sn_linked_list_t *linked_list);

/* \brief Returns a pointer to current node and a NULL pointer if current node does not exist */
extern void *sn_linked_list_get_current_node(sn_linked_list_t *linked_list);

/* \brief Returns a pointer to next node and a NULL pointer if next node does not exist
 * * Note that you need to call sn_linked_list_get_last_node or
 * sn_linked_list_get_first_node and sn_linked_list_get_next_node before using this function */
extern void *sn_linked_list_get_previous_node(sn_linked_list_t *linked_list);

/* \brief Returns a pointer to last node on list and a NULL pointer if list is empty or error occurs.
 * Sets last node as current node. */
extern void *sn_linked_list_get_last_node(sn_linked_list_t *linked_list);

/* \brief Removes current node from list. Sets next node as current node or
 * if next node is null sets pointer to previous node.
 * Returns data pointer from removed node or NULL pointer if there is no current node.
 * Note that linked list does NOT free the data in current node. */
extern void *sn_linked_list_remove_current_node(sn_linked_list_t *linked_list);

/* \brief Updates current node to contain data given in the data parameter.
 * Note that this function does NOT free data that current node held before this function call.
 * If error is returned, nothing has been done. */
extern int8_t sn_linked_list_update_current_node(sn_linked_list_t *linked_list, void *data);

/* \brief Returns number of nodes that are currently stored in list.
 * Note: if list contains over 65535 nodes, this function can NOT be used */
extern uint16_t sn_linked_list_count_nodes(sn_linked_list_t *linked_list);

#endif /* SN_LINKED_LIST_H_ */

#ifdef __cplusplus
}
#endif
