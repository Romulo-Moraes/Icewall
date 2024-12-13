#ifndef __UNLOCKED_IOCTL_GUARD__
#define __UNLOCKED_IOCTL_GUARD__

#include <linux/fs.h>

#define BYTE 'R'

#define _IOCTL_ADD_RULE _IOW(BYTE, 1, )

long unlocked_ioctl(struct file* file, unsigned int cmd, unsigned long args);
struct file_operations generate_io_conf();

#endif