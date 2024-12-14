#ifndef __UNLOCKED_IOCTL_GUARD__
#define __UNLOCKED_IOCTL_GUARD__

#include <linux/fs.h>

#define RULES_DEVICE_NAME "icewall-rules"
#define ICEWALL_CLASS "icewall"

long create_rules_chrdev();
long destroy_rules_chrdev();

#endif