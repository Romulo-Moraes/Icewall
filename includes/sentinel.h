#ifndef __SENTINEL_GUARD__
#define __SENTINEL_GUARD__

#define DIRECTION_IN 1
#define DIRECTION_OUT 2

typedef unsigned char direction;

void init_sentinel();
long add_firewall_rule(struct rule_description rule, direction dir);
long test_packet(struct packet pckt, direction dir, action *act_out);
long set_policy(policy policy, direction dir);

#endif