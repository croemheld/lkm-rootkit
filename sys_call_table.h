#ifndef SYS_CALL_TABLE
#define SYS_CALL_TABLE

#include <linux/types.h>
#include <asm/msr-index.h>

unsigned long **get_sys_call_table(void);

#endif