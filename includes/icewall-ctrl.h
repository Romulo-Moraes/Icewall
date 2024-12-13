#ifndef __ICEWALL_CTRL__
#define __ICEWALL_CTRL__

#define _IOCTL_ADD_INC_RULE _IOW(MAGIC_BYTE, 1, sizeof(struct rule_description))
#define _IOCTL_ADD_OUT_RULE _IOW(MAGIC_BYTE, 2, sizeof(struct rule_description))
#define _IOCTL_SET_INC_POLICY _IOW(MAGIC_BYTE, 3, sizeof(uint8_t))
#define _IOCTL_SET_OUT_POLICY _IOW(MAGIC_BYTE, 4, sizeof(uint8_t))

#endif