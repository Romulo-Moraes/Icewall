#ifndef __SENTINEL_GUARD__
#define __SENTINEL_GUARD__

#include <icewall-ctrl.h>

#include "rules.h"

void init_sentinel(void);
struct rule_list_node* get_act_rules(direction dir);
policy get_policy(direction dir);
long add_firewall_rule(struct rule_description rule, direction dir);
long rm_firewall_rule(r_id id, direction dir);
long test_packet(struct packet pckt, direction dir, action *act_out);
long set_policy(policy policy, direction dir);

#endif
