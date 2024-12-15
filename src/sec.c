#include "../includes/sec.h"

static void check_addr_rule(struct rule_description *rule, bool *eval) {
    switch (rule->ip_rule) {
        case ADDR_SET_RULE:
            *eval &= (rule->pre_len >= 0 && rule->pre_len <= 32);
            break;
        case SINGLE_ADDR_RULE:
        case NO_ADDR_RULE:
            break;
        default:
            *eval = false;
            break;
    }
}

static void check_p_rule(struct rule_description *rule, bool *eval) {
    switch (rule->p_rule) {
        case P_RANGE_RULE:
            *eval &= (rule->p_begin >= 0 && rule->p_end <= __UINT16_MAX__ && rule->p_begin < rule->p_end);
            break;
        case SINGLE_P_RULE:
            *eval &= (rule->p_begin >= 0 && rule->p_begin <= __UINT16_MAX__);
            break;
        case NO_P_RULE:
            break;
        default:
            *eval = false;
            break;
    }
}

static void check_policy(struct rule_description *rule, bool *eval) {
    *eval &= (rule->act == POLICY_ACCEPT || rule->act == POLICY_DROP);
}

static void check_proto_rule(struct rule_description *rule, bool *eval) {
    if (rule->proto_rule != TCP_PROTO_RULE && rule->proto_rule != UDP_PROTO_RULE && rule->proto_rule != NO_PROTO_RULE) {
        *eval = false;
    }
}

bool check_policy_integrity(policy policy) {
    return (policy == POLICY_ACCEPT || policy == POLICY_DROP);
}

bool check_rule_integrity(struct rule_description rule) {
    bool eval = true;

    check_policy(&rule, &eval);

    if (eval == false) {
        pr_info("err1\n");
    }

    check_addr_rule(&rule, &eval);

    if (eval == false) {
        pr_info("err2\n");
    }
    check_p_rule(&rule, &eval);

    if (eval == false) {
        pr_info("err3\n");
    }
    check_proto_rule(&rule, &eval);

    if (eval == false) {
        pr_info("err4\n");
    }

    return eval;
}