#ifndef PORT_H
#define PORT_H

#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <net/netfilter/ipv6/nf_reject.h>
#include <net/tcp.h>

/* define length */
#define KNOCKING_LENGTH 3

/* struct for saving information about sender and port */
struct sender_node {
	int protocol;
	int knocking_counter;

	/* depending on protocol */
	union {
		u8 ipv4_addr[4];
		u8 ipv6_addr[16];
	} ip_addr;

	#define ipv4 ip_addr.ipv4_addr
	#define ipv6 ip_addr.ipv6_addr
};

void port_hide(int port);
void port_unhide(int port);

int port_knocking_init(void);
void port_knocking_exit(void);

#endif