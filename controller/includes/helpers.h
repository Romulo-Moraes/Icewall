#ifndef __HELPERS_GUARD__
#define __HELPERS_GUARD__

#include <stdbool.h>
#include "../includes/parser.h"
#include "../../includes/icewall-ctrl.h"

void list_rules(direction dir, struct ioctl_list_result *result, char *chr_dev);
void send_add_rule_cmd(struct drop_accept_cmd *parsed_cmd, char *chr_dev);
void generate_p_rule(struct rule_description desc, bool *first_rule, char *buffer_out);
void generate_proto_rule(rule_type proto_rule, bool *first_rule, char *buffer_out);
void generate_addr_rule(rule_type ip_rule, ip_addr addr, bool *first_rule, prefix pre_len, char *buffer_out);
void generate_rule_cmd(r_id id, struct rule_description desc, char *output, size_t out_len, direction dir);
void print_rules(struct ioctl_list_result *result, direction dir, policy policy);
int rm_rule(r_id id, direction dir, char *chr_dev);

#endif