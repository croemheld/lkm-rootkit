#include "utils.h"
#include "syscalltable.h"

/*
 * from: http://bw0x00.blogspot.de/2011/03/find-syscalltable-in-linux-26.html
 */
unsigned long **get_syscalltable(void)
{
	int i, lo, hi;
	unsigned char *ptr;
	unsigned long system_call;

	alert("GETTING SYS_CALL_TABLE");

	/* http://wiki.osdev.org/Inline_Assembly/Examples#RDMSR */
	asm volatile("rdmsr" : "=a" (lo), "=d" (hi) : "c" (MSR_LSTAR));
	system_call = (unsigned long)(((long)hi << 32) | lo);

	/* loop until first 3 bytes of instructions are found */
	for (ptr = (unsigned char *)system_call, i = 0; i < 500; i++)  {
		if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5) {
			debug("SYS_CALL_TABLE FOUND");
			/* set address together */
			return (unsigned long **)(0xffffffff00000000 
				| *((unsigned int *)(ptr + 3)));
		}

		ptr++;
	}

	debug("SYS_CALL_TABLE NOT FOUND");

	return NULL;
}

MODULE_LICENSE("GPL");