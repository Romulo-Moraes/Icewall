#ifndef __RULES_GUARD__
#define __RULES_GUARD__

#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/inet.h>  

#include "icewall.h"
#include "rules-types.h"

#define INIT_NO_ERR NULL
#define MEM_FAILURE 12
#define ADD_NO_ERR 0
#define RULE_NEXIST 13
#define DEL_RULE_OK 14    
#define TEST_MATCH 1
#define TEST_MISMATCH 0

errmsg init_rule_list(struct rule_list_head *list_head, unsigned char policy);
opstatus add_rule(struct rule_list_head *list_head, struct rule_description desc, r_id id);
opstatus remove_rule(struct rule_list_head *list_head, r_id id);
action test_against_ruleset(struct rule_list_head *list_head, struct packet pckt, policy policy);
void zero_id(void);

#endif