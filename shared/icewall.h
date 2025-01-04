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
#define SUBNET_RULE 5
#define NO_ADDR_RULE 6
#define TCP_PROTO_RULE 7
#define UDP_PROTO_RULE 8
#define NO_PROTO_RULE 9
#define POLICY_ACCEPT 10
#define POLICY_DROP 11
#define ONLY_CHECK 12
#define ADDR_SET_RULE 13
#define P_SET_RULE 14
#define UNDEFINED_RULE 15
#define DEV_NAME "icewall-rules"
#define LOG_FLAG 1

typedef unsigned char policy;
typedef unsigned char rule_type;
typedef policy action;
typedef uint16_t port_value;
typedef unsigned char flags;
typedef uint8_t prefix;
typedef uint32_t ip_addr; // little-endian order

struct rule_description {
    action act;
    
    rule_type p_rule;
    unsigned char port_count; // useful for P_SET_RULE
    port_value *ports;
    
    rule_type ip_rule;
    unsigned char addr_count; // useful for ADDR_SET_RULE
    ip_addr *addrs;
    prefix pre_len;
    
    rule_type proto_rule;

    flags r_flags;
};

#endif
