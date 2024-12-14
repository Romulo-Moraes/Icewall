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
            *eval &= (rule->p_begin >= 0 && rule->p_end <= UINT16_MAX && rule->p_begin < rule->p_end);
            break;
        case SINGLE_P_RULE:
            *eval &= (rule->p_begin >= 0 && rule->p_begin <= UINT16_MAX);
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
    check_addr_rule(&rule, &eval);
    check_p_rule(&rule, &eval);
    check_proto_rule(&rule, &eval);

    return eval;
}