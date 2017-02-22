#ifndef PRIV_ESCALATION
#define PRIV_ESCALATION

#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/list.h>
#include <linux/rwlock.h>
#include <linux/rcupdate.h>

/* struct for saving old creds */
struct cred_node {
	int pid;
	struct task_struct *task, *parent, *real_parent;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
};

void process_escalate(int pid);
void process_deescalate(int pid);

int priv_escalation_init(void);
void priv_escalation_exit(void);

#endif