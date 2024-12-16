#ifndef __ICEWALL_CTRL__
#define __ICEWALL_CTRL__

#include "rules-types.h"

#define MAGIC_BYTE 'R'
#define MAX_LIST_RESULT_LEN 64

struct ioctl_list_value {
    r_id id;
    struct rule_description rule;
};

struct ioctl_list_result {
    uint8_t count;
    policy policy;
    struct ioctl_list_value values[MAX_LIST_RESULT_LEN];
};

#define _IOCTL_ADD_INC_RULE _IOC(_IOC_WRITE, MAGIC_BYTE, 1, sizeof(struct rule_description))
#define _IOCTL_ADD_OUT_RULE _IOC(_IOC_WRITE, MAGIC_BYTE, 2, sizeof(struct rule_description))
#define _IOCTL_SET_INC_POLICY _IOC(_IOC_WRITE, MAGIC_BYTE, 3, sizeof(uint8_t))
#define _IOCTL_SET_OUT_POLICY _IOC(_IOC_WRITE, MAGIC_BYTE, 4, sizeof(uint8_t))
#define _IOCTL_LIST_INC _IOC(_IOC_READ, MAGIC_BYTE, 5, sizeof(struct ioctl_list_result))
#define _IOCTL_LIST_OUT _IOC(_IOC_READ, MAGIC_BYTE, 6, sizeof(struct ioctl_list_result))

#endif