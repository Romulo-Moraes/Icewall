#include "../includes/sentinel.h"

static struct rule_list_head in;
static struct rule_list_head out;
static policy in_policy = POLICY_ACCEPT;
static policy out_policy = POLICY_ACCEPT;

void init_sentinel() {
    init_rule_list(&in, in_policy);
    init_rule_list(&out, out_policy);
}

/**
 * add a new rule to the firewall
 * @param rule the rule that will be added
 * @param dir the rule's direction
 * @returns -EINVAL, -ENOMEM on failure, 0 on success
 */
long add_firewall_rule(struct rule_description rule, direction dir) {
    opstatus stt;

    switch (dir) {
        case DIRECTION_IN:
            stt = add_rule(&in, rule);
            break;
        case DIRECTION_OUT:
            stt = add_rule(&out, rule);
            break;
        default:
            return -EINVAL;
            break;
    }

    if (stt == MEM_FAILURE) {
        return -ENOMEM;
    }

    return 0;
}

/*
 * test a packet against the specified ruleset
 * @param pckt the incoming or outgoing packet
 * @param dir the packet direction (DIRECTION_IN or DIRECTION_OUT)
 * @param act_out the action to be performed based on the given packet and direction
 * @returns -EINVAL if dir is not known, 0 otherwise, that means success
 */
long test_packet(struct packet pckt, direction dir, action *act_out) {
    if (dir == DIRECTION_IN) {
        *act_out = test_against_ruleset(&in, pckt, in_policy);
    } else if (dir == DIRECTION_OUT) {
        *act_out = test_against_ruleset(&out, pckt, out_policy);
    } else {
        return -EINVAL;
    }

    return 0;
}

/*
 * set the policy of incoming and outgoing packets
 * @param policy the new policy to be used
 * @param dir set policy to incoming or outgoing packets
 * @returns -EINVAL if direction is not known, 0 otherwise, that means success
 */
long set_policy(policy policy, direction dir) {
    if (dir == DIRECTION_IN) {
        in_policy = policy;
    } else if (dir == DIRECTION_OUT) {
        out_policy = policy;
    } else {
        return -EINVAL;
    }

    return 0;
}
