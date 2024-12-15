#ifndef __UNLOCKED_IOCTL_GUARD__
#define __UNLOCKED_IOCTL_GUARD__

#include <linux/fs.h>
#include "icewall.h"

#define RULES_DEVICE_NAME DEV_NAME
#define ICEWALL_CLASS "icewall"

long create_rules_chrdev(void);
void destroy_rules_chrdev(void);

#endif