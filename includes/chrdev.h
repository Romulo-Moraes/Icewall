#ifndef __UNLOCKED_IOCTL_GUARD__
#define __UNLOCKED_IOCTL_GUARD__

#include <linux/fs.h>

#define RULES_DEVICE_NAME "icewall-rules";
#define ICEWALL_CLASS "icewall"

long unlocked_ioctl(struct file* file, unsigned int cmd, unsigned long args);
struct file_operations generate_io_conf();
void create_chrdev();

#endif