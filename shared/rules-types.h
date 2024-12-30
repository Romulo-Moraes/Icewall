#ifndef __RULES_STRUCTS__
#define __RULES_STRUCTS__

#include "icewall.h"

typedef uint16_t r_id;
typedef char* errmsg;
typedef uint8_t opstatus;
typedef uint16_t pckt_proto;

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

#endif