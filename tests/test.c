#include <stdio.h>
#include <arpa/inet.h>
#include <assert.h>
#include "./../includes/rules.h"

void test_init_rule_list() {
    struct rule_list_head rules;

    errmsg msg = init_rule_list(&rules, POLICY_ACCEPT);
    assert(msg == NULL);
    assert(rules.begin == NULL);
    assert(rules.end == NULL);
    assert(rules.policy == POLICY_ACCEPT);

    struct rule_list_head rules2;
    errmsg msg2 = init_rule_list(&rules2, POLICY_DROP);
    assert(msg2 == NULL);
    assert(rules2.begin == NULL);
    assert(rules2.end == NULL);
    assert(rules2.policy == POLICY_DROP);

    struct rule_list_head rules3;
    errmsg msg3 = init_rule_list(&rules3, 142);
    assert(msg3 != NULL);
    printf("test init err msg: %s\n", msg);
}

struct rule_list_head test_add_rule() {
    zero_id();
    struct rule_list_head rules;

    init_rule_list(&rules, POLICY_ACCEPT);

    opstatus stt = add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = SINGLE_ADDR_RULE,
        .addr = 0,
        .p_rule = SINGLE_P_RULE,
        .p_begin = 9090,
        .pre_len = 24,
        .proto_rule = NO_PROTO_RULE
    });

    assert(stt == ADD_NO_ERR);
    assert(rules.begin->id == 0);
    assert(rules.begin == rules.end);
    assert(rules.begin->next == NULL);

    opstatus stt2 = add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = SINGLE_ADDR_RULE,
        .addr = 0,
        .p_rule = SINGLE_P_RULE,
        .p_begin = 9090,
        .pre_len = 24,
        .proto_rule = NO_PROTO_RULE
    });

    assert(stt2 == ADD_NO_ERR);
    assert(rules.end->id == 1);
    assert(rules.begin != rules.end);
    assert(rules.end->next == NULL);
    assert(rules.begin->next == rules.end);

    opstatus stt3 = add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = SINGLE_ADDR_RULE,
        .addr = 0,
        .p_rule = SINGLE_P_RULE,
        .p_begin = 9090,
        .pre_len = 24,
        .proto_rule = NO_PROTO_RULE
    });

    assert(stt3 == ADD_NO_ERR);
    assert(rules.end->id == 2);
    assert(rules.begin != rules.end);
    assert(rules.end->next == NULL);
    assert(rules.begin->next != rules.end);

    return rules;
}

void test_remove_rule() {
    puts("calling for shortcut");
    struct rule_list_head rules = test_add_rule();

    opstatus stt = remove_rule(&rules, 1);

    assert(stt == DEL_RULE_OK);
    assert(rules.begin->next == rules.end);
    assert(rules.end->id == 2);
    assert(rules.begin->id == 0);

    opstatus stt2 = remove_rule(&rules, 2);

    assert(stt2 == DEL_RULE_OK);
    assert(rules.begin->next == NULL);
    assert(rules.end->id == 0);
    assert(rules.begin->id == 0);

    opstatus stt3 = remove_rule(&rules, 0);

    assert(stt3 == DEL_RULE_OK);
    assert(rules.begin == NULL);
    assert(rules.end == NULL);

    opstatus stt4 = remove_rule(&rules, 10);
    assert(stt4 == RULE_NEXIST);

    opstatus stt5 = remove_rule(&rules, 0);
    assert(stt5 == RULE_NEXIST);
}

void test_test_against_proto_ruleset() {
    struct rule_list_head rules;
    policy policy = POLICY_ACCEPT;

    zero_id();
    init_rule_list(&rules, policy);

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = NO_ADDR_RULE,
        .proto_rule = TCP_PROTO_RULE,
        .p_rule = NO_P_RULE,
    });

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = NO_ADDR_RULE,
        .proto_rule = UDP_PROTO_RULE,
        .p_rule = NO_P_RULE
    });

    action act = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235821, // 192.168.1.45
        .hport = 8080,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act == POLICY_DROP);

    action act2 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236118, // 192.168.2.86
        .hport = 9090,
        .proto = IPPROTO_UDP
    }, policy);
    assert(act2 == POLICY_DROP);

    remove_rule(&rules, 1);

    action act3 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236297, // 192.168.3.9 
        .hport = 4040,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act3 == POLICY_DROP);

    action act4 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235822, // 192.168.1.46
        .hport = 4043,
        .proto = IPPROTO_UDP
    }, policy);
    assert(act4 == POLICY_ACCEPT);

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_ACCEPT,
        .ip_rule = NO_ADDR_RULE,
        .proto_rule = UDP_PROTO_RULE,
        .p_rule = NO_P_RULE
    });

    action act5 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235822, // 192.168.1.46
        .hport = 4045,
        .proto = IPPROTO_UDP
    }, policy);
    assert(act5 == POLICY_ACCEPT);

    remove_rule(&rules, 0);

    action act6 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236297, // 192.168.3.9 
        .hport = 4040,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act6 == POLICY_ACCEPT);

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_ACCEPT,
        .ip_rule = NO_ADDR_RULE,
        .proto_rule = TCP_PROTO_RULE,
        .p_rule = NO_P_RULE
    });

    action act7 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236297, // 192.168.3.9 
        .hport = 4040,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act7 == POLICY_ACCEPT);
}

void test_test_against_port_ruleset() {
    struct rule_list_head rules;
    policy policy = POLICY_ACCEPT;

    init_rule_list(&rules, policy);

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = NO_ADDR_RULE,
        .proto_rule = NO_PROTO_RULE,
        .p_rule = SINGLE_P_RULE,
        .p_begin = 8080
    });

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = NO_ADDR_RULE,
        .proto_rule = NO_PROTO_RULE,
        .p_rule = P_RANGE_RULE,
        .p_begin = 4040,
        .p_end = 4045
    });

    action act = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235821, // 192.168.1.45
        .hport = 8080,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act == POLICY_DROP);

    action act2 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236118, // 192.168.2.86
        .hport = 9090,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act2 == POLICY_ACCEPT);

    action act3 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236297, // 192.168.3.9 
        .hport = 4040,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act3 == POLICY_DROP);

    action act4 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235822, // 192.168.1.46
        .hport = 4043,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act4 == POLICY_DROP);

    action act5 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235822, // 192.168.1.46
        .hport = 4045,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act4 == POLICY_DROP);

}


void test_test_against_union_ruleset() {
    struct rule_list_head rules;
    policy policy = POLICY_ACCEPT;

    init_rule_list(&rules, policy);

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = SINGLE_ADDR_RULE,
        .addr = 3232235821, // 192.168.1.45
        .proto_rule = NO_PROTO_RULE,
        .p_rule = SINGLE_P_RULE,
        .p_begin = 8080
    });

    action act = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235821, // 192.168.1.45
        .hport = 8080,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act == POLICY_DROP);

    act = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235821, // 192.168.1.45
        .hport = 8081,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act == POLICY_ACCEPT);

    act = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235821, // 192.168.1.45
        .hport = 8080,
        .proto = IPPROTO_UDP
    }, policy);
    assert(act == POLICY_DROP);


    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = SINGLE_ADDR_RULE,
        .addr = 3232235821, // 192.168.1.45
        .proto_rule = TCP_PROTO_RULE,
        .p_rule = NO_P_RULE,
    });

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = NO_ADDR_RULE,
        .proto_rule = NO_PROTO_RULE,
        .p_rule = P_RANGE_RULE,
        .p_begin = 4040,
        .p_end = 4045
    });

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = NO_ADDR_RULE,
        .proto_rule = TCP_PROTO_RULE,
        .p_rule = SINGLE_P_RULE,
        .p_begin = 4545
    });

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = ADDR_SET_RULE,
        .addr = 3232236032, // 192.168.2.0
        .pre_len = 24,
        .proto_rule = TCP_PROTO_RULE,
        .p_rule = P_RANGE_RULE,
        .p_begin = 4545,
        .p_end = 4550
    });

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_DROP,
        .ip_rule = SINGLE_ADDR_RULE,
        .addr = 3232236383, // 192.168.3.90
        .proto_rule = TCP_PROTO_RULE,
        .p_rule = NO_P_RULE
    });

    action act2 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235821, // 192.168.1.45
        .hport = 9090,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act2 == POLICY_DROP);

    act2 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235821, // 192.168.1.45
        .hport = 9090,
        .proto = IPPROTO_UDP
    }, policy);
    assert(act2 == POLICY_ACCEPT);

    action act3 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236297, // 192.168.3.9 
        .hport = 4545,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act3 == POLICY_DROP);

    act3 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236297, // 192.168.3.9 
        .hport = 4545,
        .proto = IPPROTO_UDP
    }, policy);
    assert(act3 == POLICY_ACCEPT);

    action act4 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236050, // 192.168.2.18
        .hport = 4045,
        .proto = IPPROTO_TCP
    }, policy);
    printf("%d\n", act4);
    assert(act4 == POLICY_DROP);

    act4 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236041, // 192.168.2.9
        .hport = 4548,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act4 == POLICY_DROP);

    act4 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236041, // 192.168.2.9
        .hport = 4551,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act4 == POLICY_ACCEPT);

    act4 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236041, // 192.168.2.9
        .hport = 4548,
        .proto = IPPROTO_UDP
    }, policy);
    assert(act4 == POLICY_ACCEPT);

    act4 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236375, // 192.168.3.87
        .hport = 4548,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act4 == POLICY_ACCEPT);

    action act5 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236383, // 192.168.3.90
        .hport = 4045,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act5 == POLICY_DROP);

    act5 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236383, // 192.168.3.90
        .hport = 4090,
        .proto = IPPROTO_UDP
    }, policy);
    assert(act5 == POLICY_ACCEPT);

    act5 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236383, // 192.168.3.90
        .hport = 4090,
        .proto = IPPROTO_UDP
    }, policy);
    assert(act5 == POLICY_ACCEPT);

    act5 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236379, // 192.168.3.91
        .hport = 4020,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act5 == POLICY_ACCEPT);

}

void test_test_against_addr_ruleset() {
    struct rule_list_head rules;
    policy policy = POLICY_DROP;

    init_rule_list(&rules, policy);

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_ACCEPT,
        .ip_rule = SINGLE_ADDR_RULE,
        .addr = 3232235821, // 192.168.1.45
        .proto_rule = NO_PROTO_RULE,
        .p_rule = NO_P_RULE
    });

    add_rule(&rules, (struct rule_description) {
        .act = POLICY_ACCEPT,
        .ip_rule = ADDR_SET_RULE,
        .addr = 3232236032, // 192.168.2.0
        .pre_len = 24,
        .proto_rule = NO_PROTO_RULE,
        .p_rule = NO_P_RULE
    });

    action act = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235821, // 192.168.1.45
        .hport = 9090,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act == POLICY_ACCEPT);

    action act2 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236118, // 192.168.2.86
        .hport = 9090,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act2 == POLICY_ACCEPT);

    action act3 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232236297, // 192.168.3.9 
        .hport = 9090,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act3 == POLICY_DROP);

    action act4 = test_against_ruleset(&rules, (struct packet) {
        .addr = 3232235822, // 192.168.1.46
        .hport = 9090,
        .proto = IPPROTO_TCP
    }, policy);
    assert(act4 == POLICY_DROP);

}

int main(void) {
    test_init_rule_list();
    puts("Init list tests passed");

    test_add_rule();
    puts("add rule tests passed");

    test_remove_rule();
    puts("remove rule tests passed");

    test_test_against_addr_ruleset();
    puts("test against addr ruleset tests passed");

    test_test_against_port_ruleset();
    puts("test against port ruleset tests passed");

    test_test_against_proto_ruleset();
    puts("test against proto ruleset tests passed");

    test_test_against_union_ruleset();
    puts("test against union ruleset tests passed");

/*    //192.168.1.192
    // 192.168.1.0/24 
    struct in_addr addr;

    inet_pton(AF_INET, "192.168.1.129", &addr);
    uint32_t host = ntohl(addr.s_addr);

    inet_pton(AF_INET, "192.168.1.0", &addr);
    uint32_t net = htonl(addr.s_addr);

    int n = apply_netmask(host, net, 25);

    if (n == NET_SUBNET) {
        puts("subnet!");
    } else {
        puts("Not subnet!");
    }

*/
    return 0;
}