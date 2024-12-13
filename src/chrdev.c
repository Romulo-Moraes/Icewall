#include "../includes/chrdev.h"
#include "../includes/icewall-ctrl.h"

long unlocked_ioctl(struct file* file, unsigned int cmd, unsigned long args) {
    switch (cmd) {
        case _IOCTL_ADD_INC_RULE:
            break;
        case _IOCTL_ADD_OUT_RULE:
            break;
        case _IOCTL_SET_INC_POLICY:
            break;
        case _IOCTL_SET_OUT_POLICY:
            break;
    }
}

struct file_operations generate_io_conf() {
    const struct file_operations ops = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = unlocked_ioctl
    };
    
    return ops;
}