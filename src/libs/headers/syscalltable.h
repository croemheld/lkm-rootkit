#ifndef SYSCALLTABLE_H
#define SYSCALLTABLE_H

#include <linux/types.h>
#include <asm/msr-index.h>

unsigned long **get_syscalltable(void);

#endif