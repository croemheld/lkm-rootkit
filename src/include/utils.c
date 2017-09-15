#include "utils.h"
#include "syscalltable.h"

/* get adress of system call table via our sysmap.h file */
void **table_ptr = NULL;

/* check if list is empty */
int is_empty_data_node(struct data_node **head)
{
	return *head == NULL;
}

/* special case of find_data_node_field (with offset = 0) */
struct data_node *find_data_node(struct data_node **head, void *data, 
	int length)
{
	struct data_node *node = *head;

	while(node != NULL) {
		if(!memcmp(data, node->data, length)) {
			debug("DATA_NODE FOUND IN LIST");
			return node;
		}

		node = node->next;
	}

	return NULL;
}

struct data_node *find_data_node_field(struct data_node **head, void *needle, 
	int offset, int length) 
{
	struct data_node *node = *head;

	while(node != NULL) {
		if(!memcmp(node->data + offset, needle, length)) {
			debug("DATA_NODE FOUND IN LIST");
			return node;
		}

		node = node->next;
	}

	return NULL;
}

/* insert node at the beginning of the current list */
struct data_node *insert_data_node(struct data_node **head, void *data)
{
	struct data_node *node = kmalloc(sizeof(struct data_node), GFP_KERNEL);
	node->data = data;

	/* since we are adding at the begining, prev is always NULL */
	node->prev = NULL;
	node->next = (*head);    

	if((*head) != NULL)
		(*head)->prev = node;

	(*head) = node;

	return (*head);
}

/* delete node */
void delete_data_node(struct data_node **head, struct data_node *node)
{
	/* check for NULL */
	if(*head == NULL || node == NULL) {
		debug("DATA_NODE LIST EMPTY");
		return;
	}

	/* node to be deleted is head */
	if(*head == node) {
		debug("DATA_NODE IS HEAD")
		*head = node->next;	
	}

	/* next node */
	if(node->next != NULL)
		node->next->prev = node->prev;	

	/* prev node */
	if(node->prev != NULL)
		node->prev->next = node->next;     	

	kfree(node);
}

/* call a function for each node */
void foreach_data_node_callback(struct data_node **head, 
	void (*callback_function)(struct data_node *)) 
{
	struct data_node *node = *head;

	if(is_empty_data_node(head)) {
		debug("DATA_NODE LIST EMPTY");
		return;
	}

	while(node != NULL) {
		debug("CALLBACK FUNCTION CALLED");
		callback_function(node);
		node = node->next;
	}
}

/* completely free a list */
void free_data_node_list(struct data_node **head)
{
	if(is_empty_data_node(head)) {
		debug("DATA_NODE LIST EMPTY");
		return;
	}

	while(!is_empty_data_node(head)) {
		debug("DELETE DATA_NODE");
		delete_data_node(head, *head);
	}
}

/* completely free a list with callback function */
void free_data_node_list_callback(struct data_node **head, 
	void (*callback_function)(struct data_node *))
{

	if(is_empty_data_node(head)) {
		debug("DATA_NODE LIST EMPTY");
		return;
	}

	while(!is_empty_data_node(head)) {
		debug("CALLBACK FUNCTION CALLED");

		/* callback function with param node */
		callback_function(*head);
		delete_data_node(head, *head);
	}
}

/* critical section functions (mutexes) */

/* increment counter of a critical section */
void inc_critical(struct mutex *lock, int *counter)
{
	/* lock access mutex */
	mutex_lock(lock);
	(*counter)++;

	/* unlock access mutex */
	mutex_unlock(lock);
}

/* decrement counter of a critical section */
void dec_critical(struct mutex *lock, int *counter)
{

	/* lock access mutex */
	mutex_lock(lock);
	(*counter)--;

	/* unlock access mutex */
	mutex_unlock(lock);
}

/* simple util functions */

/* disable page protection */
void disable_page_protection(void)
{
	alert("DISABLE_PAGE_PROTECTION");
	write_cr0(read_cr0() & (~0x10000));
}

/* enable page protection */
void enable_page_protection(void)
{
	alert("ENABLE_PAGE_PROTECTION");
	write_cr0(read_cr0() | 0x10000);
}

/* set pointer to system call table */
int set_syscalltable(void)
{
	table_ptr = (void **)get_syscalltable();

	if(table_ptr == NULL)
		return 1;

	return 0;
}

/* strtoint: convert char *str containing a number into an integer */
int strtoint(char *str)
{
	long res;

	/* using kstrtol with base 10 (decimal) */
	if(kstrtol(str, 10, &res) == 0)
		return (int)res;

	return -1;
}

/* getdigits: get number of digits for a given int */
int getdigits(int num)
{
	if(num < 0)
		return 1 + getdigits(num * (-1));

	if(num < 10)
		return 1;

	return 1 + getdigits(num / 10);
}

MODULE_LICENSE("GPL");