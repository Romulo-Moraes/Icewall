#include "./../includes/rules.h"
#include <linux/slab.h>
#include "../includes/sentinel.h"

#define NET_SUBNET 1
#define NET_N_SUBNET 2

typedef unsigned char subnet_stt;

// void zero_id() {
//     id = 0;
// }

static void fill_rule_node(struct rule_list_node *n, struct rule_description desc, r_id id) {
    // accept outgoing 255.255.255.255:65000:tcp
    // accept incoming
    n->desc = desc;
    n->id = id;
    n->next = NULL;
}

/* 
 * add a new rule to the firewall
 * @returns MEM_FAILURE on dynamic memory allocation failure, ADD_NO_ERR otherwise
 */
opstatus add_rule(struct rule_list_head *list_head, struct rule_description desc, r_id id) {
    struct rule_list_node *n = (struct rule_list_node*) kmalloc(sizeof(struct rule_list_node), GFP_KERNEL);

    if (!n) {
        return MEM_FAILURE;
    }

    fill_rule_node(n, desc, id);

    if (list_head->end != NULL) {
        list_head->end->next = n;
        list_head->end = n;
    } else {
        list_head->begin = n;
        list_head->end = n;
    }

    return ADD_NO_ERR;
}

/*
 * remove the rule specified by id from list_head
 * @returns RULE_NEXIST if the rule doesn't exists, DEL_RULE_OK otherwise
 */
opstatus remove_rule(struct rule_list_head *list_head, r_id id) {
    struct rule_list_node *p = NULL;

    for (struct rule_list_node *n = list_head->begin; n != NULL; n = n->next) {

        if (n->id == id) {
            if (p == NULL) {

                if (list_head->begin == list_head->end) {
                    list_head->begin = NULL;
                    list_head->end = NULL;
                } else {
                    list_head->begin = n->next;
                }

                kfree(n);
            } else {
                p->next = n->next;

                if (n == list_head->end) {
                    list_head->end = p;
                }

                kfree(n);
            }

            return DEL_RULE_OK;
        }

        p = n;
    }

    return RULE_NEXIST;
}

/*
 * initializes the list_head structure using policy
 * @returns returns a error message if policy is unknown, INIT_NO_ERR otherwise
 */
errmsg init_rule_list(struct rule_list_head *list_head, unsigned char policy) {
    const errmsg msg = "Unknown policy on init rule list.";

    if (policy != POLICY_ACCEPT && policy != POLICY_DROP) {
        return msg;
    }

    list_head->policy = policy;

    list_head->begin = NULL;
    list_head->end = NULL;

    return INIT_NO_ERR;
}

static subnet_stt apply_netmask(uint32_t pckt_addr, uint32_t rule_addr, uint8_t pre_len) {
    uint32_t mask = (__UINT32_MAX__ << (32 - pre_len));

    pckt_addr = pckt_addr & mask;

    return pckt_addr == rule_addr ? NET_SUBNET : NET_N_SUBNET;
}

static void test_addr_rule(struct ruleset_test_flags *flags, struct rule_list_node *n, struct packet pckt) { 
    subnet_stt stt;

    switch (n->desc.ip_rule) {
        case SINGLE_ADDR_RULE:
            pr_info("%d | %d\n", n->desc.addr, pckt.addr);
            if (n->desc.addr == pckt.addr) {
                flags->addr_check = TEST_MATCH;
            } else {
                flags->addr_check = TEST_MISMATCH;
            }

            break;
        case ADDR_SET_RULE:

            stt = apply_netmask(pckt.addr, n->desc.addr, n->desc.pre_len);

            if (stt == NET_SUBNET) {
                flags->addr_check = TEST_MATCH;
            } else {
                flags->addr_check = TEST_MISMATCH;
            }

            break;
        case NO_ADDR_RULE:
            flags->addr_check = TEST_MATCH;
            break;
    }
}

static void test_port_rule(struct ruleset_test_flags *flags, struct rule_list_node *n, struct packet pckt) {
    switch (n->desc.p_rule) {
        case SINGLE_P_RULE:
            
            if (n->desc.p_begin == pckt.hport) {
                flags->p_check = TEST_MATCH;
            } else {
                flags->p_check = TEST_MISMATCH;
            }

            break;
        case P_RANGE_RULE:
            
            if (pckt.hport >= n->desc.p_begin && pckt.hport <= n->desc.p_end) {
                flags->p_check = TEST_MATCH;
            } else {
                flags->p_check = TEST_MISMATCH;
            }

            break;
        case NO_P_RULE:
            flags->p_check = TEST_MATCH;
            break;
    }
}

static void test_proto_rule(struct ruleset_test_flags *flags, struct rule_list_node *n, struct packet pckt) {
    switch (n->desc.proto_rule) {
        case TCP_PROTO_RULE:

            if (pckt.proto == IPPROTO_TCP) {
                flags->proto_check = TEST_MATCH;
            } else {
                flags->proto_check = TEST_MISMATCH;
            }

            break;
        case UDP_PROTO_RULE:

            if (pckt.proto == IPPROTO_UDP) {
                flags->proto_check = TEST_MATCH;
            } else {
                flags->proto_check = TEST_MISMATCH;
            }

            break;
        case NO_PROTO_RULE:
            flags->proto_check = TEST_MATCH;
            break;
    }
}

action test_against_ruleset(struct rule_list_head *list_head, struct packet pckt, policy policy) {
    struct ruleset_test_flags flags;
    
    for (struct rule_list_node *n = list_head->begin; n != NULL; n = n->next) {
        test_addr_rule(&flags, n, pckt);
        test_port_rule(&flags, n, pckt);
        test_proto_rule(&flags, n, pckt);

        if ((flags.addr_check & flags.p_check & flags.proto_check) == TEST_MATCH) {
            return n->desc.act;
        }
    }

    return policy;
}