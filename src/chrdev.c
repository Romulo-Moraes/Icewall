#include "../includes/chrdev.h"
#include "../includes/icewall-ctrl.h"
#include "../includes/sec.h"
#include "../includes/sentinel.h"
#include <linux/uaccess.h>

static struct file_operations ops;
static dev_t rules_dev_id;
static struct class *icewall_class;
static struct device *rules_dev;
static int major_number;

static long handle_rule_op(unsigned long args, unsigned int cmd);
static long handle_rule_list_op(unsigned long args, unsigned int cmd);
static long handle_policy_op(unsigned long args, unsigned int cmd);

static long unlocked_ioctl(struct file* file, unsigned int cmd, unsigned long args) {
    if (cmd == _IOCTL_ADD_INC_RULE || cmd == _IOCTL_ADD_OUT_RULE) {
        pr_info("Add firewall rule command received\n");
        return handle_rule_op(args, cmd);
    }

    if(cmd == _IOCTL_SET_INC_POLICY || cmd == _IOCTL_SET_OUT_POLICY) {
        pr_info("Set default policy command received\n");
        return handle_policy_op(args, cmd);
    }

    if (cmd == _IOCTL_LIST_INC || cmd == _IOCTL_LIST_OUT) {
        pr_info("List rules command received");
        return handle_rule_list_op(args, cmd);
    }

    return -ENOTTY;
}

long create_rules_chrdev(void) {

    ops = (struct file_operations) {
        .owner = THIS_MODULE,
        .unlocked_ioctl = unlocked_ioctl
    };
    
    major_number = register_chrdev(0, DEV_NAME, &ops);

    // failure
    if (major_number < 0) {
        return major_number;
    }
    
    rules_dev_id = MKDEV(major_number, 0);

    icewall_class = class_create(ICEWALL_CLASS);

    if (IS_ERR(icewall_class)) {
        return PTR_ERR(icewall_class);
    }

    rules_dev = device_create(icewall_class, NULL, rules_dev_id, NULL, RULES_DEVICE_NAME);

    if (IS_ERR(rules_dev)) {
        return PTR_ERR(rules_dev);
    }

    return 0;
}

void destroy_rules_chrdev(void) {
    device_destroy(icewall_class, rules_dev_id);
    unregister_chrdev(major_number, RULES_DEVICE_NAME);
    class_destroy(icewall_class);
}


static long handle_rule_op(unsigned long args, unsigned int cmd) {
    struct rule_description rule;
    long op_stt;
    
    if (copy_from_user(&rule, (void __user *) args, sizeof(rule)) != 0) {
        return -EFAULT;
    }

    if (check_rule_integrity(rule) == false) {
        return -EINVAL;
    }

    switch (cmd) {
        case _IOCTL_ADD_INC_RULE:
            op_stt = add_firewall_rule(rule, DIRECTION_IN);
            break;
        case _IOCTL_ADD_OUT_RULE:
            op_stt = add_firewall_rule(rule, DIRECTION_OUT);
            break;
    }

    //pr_info("op stt: %d\n", op_stt);

    return op_stt;
}

static long handle_policy_op(unsigned long args, unsigned int cmd) {
    policy pol;
    long op_stt;

    if (!copy_from_user(&pol, (void*) args, sizeof(pol))) {
        return -EFAULT;
    }

    if (!check_policy_integrity(pol)) {
        return -EINVAL;
    }

    switch (cmd) {
        case _IOCTL_SET_INC_POLICY:
            op_stt = set_policy(pol, DIRECTION_IN);
            break;
        case _IOCTL_SET_OUT_POLICY:
            op_stt = set_policy(pol, DIRECTION_OUT);
            break;
    }
    
    return op_stt;
}


static long handle_rule_list_op(unsigned long args, unsigned int cmd) {
    struct rule_list_node *list;
    policy policy;
    struct ioctl_list_result res = {
        .count = 0
    };

    switch (cmd) {
        case _IOCTL_LIST_INC:
            list = get_act_rules(DIRECTION_IN);
            policy = get_policy(DIRECTION_IN);
            break;
        case _IOCTL_LIST_OUT:
            list = get_act_rules(DIRECTION_OUT);
            policy = get_policy(DIRECTION_OUT);
            break;
    }

    res.policy = policy;

    for (; list != NULL && res.count < MAX_LIST_RESULT_LEN; list = list->next) {
        res.values[res.count++] = (struct ioctl_list_value) {
            .id = list->id,
            .rule = list->desc
        };
    }

    if (copy_to_user((void*) args, &res, sizeof(res)) != 0) {
        return -EFAULT;
    }

    return 0;
}