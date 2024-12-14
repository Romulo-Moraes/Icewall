#include <stdint.h>
#include <linux/ioctl.h>
#include <linux/inet.h>  

#define SINGLE_P_RULE 1
#define P_RANGE_RULE 2
#define NO_P_RULE 3
#define SINGLE_ADDR_RULE 4
#define ADDR_SET_RULE 5
#define NO_ADDR_RULE 6
#define TCP_PROTO_RULE 7
#define UDP_PROTO_RULE 8
#define NO_PROTO_RULE 9
#define POLICY_ACCEPT 10
#define POLICY_DROP 11
#define INIT_NO_ERR NULL
#define MEM_FAILURE 12
#define ADD_NO_ERR 0
#define RULE_NEXIST 13
#define DEL_RULE_OK 14    
#define TEST_MATCH 1
#define TEST_MISMATCH 0

typedef unsigned char rule_type;
typedef uint16_t port_value;
typedef uint32_t ip_addr; // little-endian order
typedef uint16_t r_id;
typedef char* errmsg;
typedef uint8_t opstatus;
typedef uint16_t pckt_proto;
typedef unsigned char policy;
typedef policy action;

struct ruleset_test_flags {
    unsigned char addr_check : 1;
    unsigned char p_check : 1;
    unsigned char proto_check : 1;
};

struct packet {
    ip_addr addr;
    port_value hport;
    pckt_proto proto;
};

struct rule_description {
    action act;
    rule_type p_rule;
    port_value p_begin;
    port_value p_end;
    rule_type ip_rule;
    ip_addr addr;
    uint8_t pre_len;
    rule_type proto_rule;
};

struct rule_list_node {
    r_id id;
    struct rule_description desc;
    struct rule_list_node *next;
};

struct rule_list_head {
    policy policy;
    struct rule_list_node *begin;
    struct rule_list_node *end;
};

errmsg init_rule_list(struct rule_list_head *list_head, unsigned char policy);
opstatus add_rule(struct rule_list_head *list_head, struct rule_description desc);
opstatus remove_rule(struct rule_list_head *list_head, r_id id);
action test_against_ruleset(struct rule_list_head *list_head, struct packet pckt, policy policy);
void zero_id();