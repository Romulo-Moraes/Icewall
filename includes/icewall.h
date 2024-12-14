#ifndef __ICEWALL_GUARD__
#define __ICEWALL_GUARD__

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
#endif

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

typedef unsigned char policy;
typedef unsigned char rule_type;
typedef policy action;
typedef uint16_t port_value;
typedef uint8_t prefix;
typedef uint32_t ip_addr; // little-endian order

struct rule_description {
    action act;
    rule_type p_rule;
    port_value p_begin;
    port_value p_end;
    rule_type ip_rule;
    ip_addr addr;
    prefix pre_len;
    rule_type proto_rule;
};

#endif