#ifndef __PARSER_HELPERS__
#define __PARSER_HELPERS__

#include <stdint.h>
#include <icewall.h>
#include <parser.h>

#define SET_SECTION 1
#define MALFORMATTED_SET 2
#define SINGLE_VALUE 3

check_flag_status check_for_flag(char *token, flags *flags, const char **errmsg);
unsigned char check_if_section_is_set(char *section);
uint8_t split_rule_sections(char *rule, char *sections[3]);
parse_command_status concat_rule_tokens(struct command_token *token, char **out, struct command_token **remaining_tokens, const char **errmsg);
parse_command_status check_for_remaining_flags(struct command_token *token, flags *flags, const char **errmsg);
parse_status parse_addr(char *token, ip_addr *addr, rule_type *ip_rule, prefix *pre_len);
parse_status parse_proto(char *token, rule_type *proto_rule);
parse_status parse_port(char *token, rule_type *p_rule, port_value *p_begin, port_value *p_end);


#endif
