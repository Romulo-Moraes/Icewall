#include <icewall-ctrl.h>
#include <rules-types.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>

#include <icewall.h>
#include <parser.h>
#include <daemon-errors.h>
#include <parser-helpers.h>


static parse_command_status parse_rule(struct command_token **token, struct rule_description *rule, const char **errmsg);
static parse_command_status parse_command_direction(struct command_token **token, direction *dir, const char **errmsg, flags *flags);
static parse_command_status parse_default_policy_constant(struct command_token **token, const char **errmsg);
static parse_command_status parse_default_policy(struct command_token **token, policy *policy, const char **errmsg);
static parse_command_status parse_rm_rule_id(struct command_token **token, r_id *rule_id, const char **errmsg);
static parsed_token parse_token(char *token, ip_addr *addr, rule_type *rule, prefix *pre_len, port_value *p_begin, port_value *p_end);
static parse_command_status parse_single_token(char *rule_section, struct rule_description *rule, rule_type *type_out, const char **errmsg);


parse_status parse_command(struct command_token *cmd, const char **msg, struct rule_cmd *rule_out, struct default_cmd *default_pol_out, struct rm_cmd *rm_out, struct dump_cmd *dump_out) {
    struct rule_cmd rule;
    struct default_cmd default_pol;
    struct rm_cmd rm;
    struct dump_cmd dump;
    char *command = cmd->token;
    cmd = cmd->next;

    rule.rule = (struct rule_description) {
        .p_rule = NO_P_RULE,
        .ip_rule = NO_ADDR_RULE,
        .proto_rule = NO_PROTO_RULE
    };
  

    if(strcmp(command, "drop") == 0) {
        rule.rule.act = POLICY_DROP;

        if (parse_command_direction(&cmd, &rule.dir, msg, &rule.rule.r_flags) == PARSE_ERROR) {
            return PARSE_ERROR;
        }
        
        if (parse_rule(&cmd, &rule.rule, msg) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (check_for_remaining_flags(cmd, &rule.rule.r_flags, msg) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (rule_out != NULL) {
            *rule_out = rule;
        }
        
        return RULE_COMMAND;

    } else if(strcmp(command, "accept") == 0) {

        rule.rule.act = POLICY_ACCEPT;

        if (parse_command_direction(&cmd, &rule.dir, msg, &rule.rule.r_flags) == PARSE_ERROR) {
            return PARSE_ERROR;
        }
        
        if (parse_rule(&cmd, &rule.rule, msg) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (rule_out != NULL) {
            *rule_out = rule;
        }
        
        return RULE_COMMAND;

    } else if(strcmp(command, "default") == 0) {

        if (parse_command_direction(&cmd, &default_pol.dir, msg, NULL) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (parse_default_policy_constant(&cmd, msg) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (parse_default_policy(&cmd, &default_pol.policy, msg) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (check_for_remaining_flags(cmd, NULL, msg) == FLAG_CHECK_ERROR) {
            return PARSE_ERROR;
        }

        if (default_pol_out != NULL) {
            *default_pol_out = default_pol;
        }
        
        return DEFAULT_COMMAND;

    } else if(strcmp(command, "rm") == 0) {

        if (parse_command_direction(&cmd, &rm.dir, msg, NULL) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (parse_rm_rule_id(&cmd, &rm.id, msg) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (check_for_remaining_flags(cmd, NULL, msg) == FLAG_CHECK_ERROR) {
            return PARSE_ERROR;
        }

        if (rm_out != NULL) {
            *rm_out = rm;
        }
        
        return RM_COMMAND;

    } else if(strcmp(command, "check") == 0) {
        rule.rule.act = ONLY_CHECK;
        
        if (parse_command_direction(&cmd, &rule.dir, msg, &rule.rule.r_flags) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (parse_rule(&cmd, &rule.rule, msg) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (check_for_remaining_flags(cmd, &rule.rule.r_flags, msg) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (rule_out != NULL) {
            *rule_out = rule;
        }
        
        return RULE_COMMAND;

    } else if(strcmp(command, "dump") == 0) {
        dump.dir = NO_DIRECTION;

        if (parse_command_direction(&cmd, &dump.dir, msg, NULL) == PARSE_ERROR) {
            return PARSE_ERROR;
        }

        if (check_for_remaining_flags(cmd, NULL, msg) == FLAG_CHECK_ERROR) {
            return PARSE_ERROR;
        }

        if (dump_out != NULL) {
            *dump_out = dump;
        }
        
        return DUMP_COMMAND;
     
    }

    return UNKNOWN_COMMAND;
}

static parse_command_status parse_command_direction(struct command_token **token, direction *dir, const char **errmsg, flags *flags) {
    if (*token == NULL) {
        *errmsg = UNEXPECTED_END_OF_COMMAND;
        return PARSE_ERROR;
    }
    
    check_flag_status stt = check_for_flag((*token)->token, flags, errmsg);

    if (stt == FOUND_FLAG) {
        return parse_command_direction(&(*token)->next, dir, errmsg, flags);
    } else if (stt == FLAG_CHECK_ERROR) {
        return PARSE_ERROR;
    }


    if(strcmp((*token)->token, "incoming") == 0) {
        *dir = INCOMING_RULE;
    } else if (strcmp((*token)->token, "outgoing") == 0) {
        *dir = OUTGOING_RULE;
    } else {
        *errmsg = UNKNOWN_RULE_DIRECTION_ERR;
        return PARSE_ERROR;
    }

    *token = (*token)->next;

    return PARSE_OK;
}

static parse_command_status parse_single_token(char *rule_section, struct rule_description *rule, rule_type *type_out, const char **errmsg) {
    ip_addr addr;
    rule_type rule_t;
    prefix pre_len;
    port_value p_begin;
    port_value p_end;
     
    parsed_token token_stt = parse_token(rule_section, &addr, &rule_t, &pre_len, &p_begin, &p_end);

    switch (token_stt) {
    case UNKNOWN_TOKEN_CLASS:
        *errmsg = UNKNOWN_VALUE_AS_RULE;
        return PARSE_ERROR;
        break;
    case ADDR_PARSED:
        rule->ip_rule = rule_t;
        rule->pre_len = pre_len;
                    
        rule->addrs = malloc(sizeof(ip_addr));
        *rule->addrs = addr;
        break;
    case PORT_PARSED:
        rule->ports = malloc(sizeof(port_value) * 2);
        rule->ports[0] = p_begin;
        rule->ports[1] = p_end;
        rule->p_rule = rule_t;
        break;
    case PROTO_PARSED:
        rule->proto_rule = rule_t;
        break;
    }

    *type_out = rule_t;

    return PARSE_OK;
}

static parse_command_status parse_set(char *rule_section, struct rule_description *rule, rule_type *rule_t, const char **errmsg) {
    ip_addr addr;
    rule_type token_type;
    prefix pre_len;
    port_value p_begin;
    port_value p_end;
    void *set_values;
    size_t set_values_index = 0;
     
    rule_type set_token_type = UNDEFINED_RULE;
    char *token;
     
    rule_section[strlen(rule_section) - 1] = '\0';
    rule_section++;

    token = strtok(rule_section, " ");

    while(token) {
        if(parse_token(token, &addr, &token_type, &pre_len, &p_begin, &p_end) == UNKNOWN_TOKEN_CLASS){
            *errmsg = UNKNOWN_VALUE_AS_RULE;
            return PARSE_ERROR;
        }
          

        if (token_type != SINGLE_ADDR_RULE && token_type != SINGLE_P_RULE) {
            *errmsg = INVALID_VALUE_INSIDE_SET;
            return PARSE_ERROR;
        }

        if (set_token_type == token_type || set_token_type == UNDEFINED_RULE) {
            if (set_token_type == UNDEFINED_RULE) {
                set_token_type = token_type;
                set_values = malloc((token_type == SINGLE_ADDR_RULE ? sizeof(ip_addr) : sizeof(port_value)) * 100);
            }

            if (token_type  == SINGLE_ADDR_RULE) {
                ((ip_addr*)set_values)[set_values_index++] = addr;
            } else {
                ((port_value*)set_values)[set_values_index++] = p_begin;
            }
        } else {
            *errmsg = INCONSISTENT_SET_TYPE;
            return PARSE_ERROR;
        }
          
        token = strtok(NULL, " ");
    }

    if (set_token_type == SINGLE_ADDR_RULE) {
        rule->ip_rule = ADDR_SET_RULE;
        rule->addrs = set_values;
        rule->addr_count = set_values_index;
    } else {
        rule->p_rule = P_SET_RULE;
        rule->ports = set_values;
        rule->port_count = set_values_index;
    }

    *rule_t = set_token_type;

    return PARSE_OK;
}

static parse_command_status parse_rule(struct command_token **token, struct rule_description *rule, const char **errmsg) {
    char *rule_out;
    check_flag_status stt;
    char *rule_sections[3];
    rule_type data_type;
    uint8_t section_count;
    unsigned char section_checking_result;
    struct parsed_sections parsed_scts = {.addr = false, .port = false, .proto = false};

    if (*token == NULL) {
        *errmsg = UNEXPECTED_END_OF_COMMAND;
        return PARSE_ERROR;
    }

    stt = check_for_flag((*token)->token, &rule->r_flags, errmsg);
    
    if (stt == FOUND_FLAG) {
        return parse_rule(&(*token)->next, rule, errmsg);
    } else if (stt == FLAG_CHECK_ERROR) {

        return PARSE_ERROR;
    }

    concat_rule_tokens(*token, &rule_out, token, errmsg);

    if((section_count = split_rule_sections(rule_out, rule_sections)) == TOO_MANY_SECTIONS) {
        *errmsg = UNEXPECTED_NUMBER_OF_SECTIONS_ON_RULE_ERR;
        return PARSE_ERROR;
    }

    for (uint8_t i = 0; i < section_count; i++) {
        section_checking_result = check_if_section_is_set(rule_sections[i]);

        switch (section_checking_result) {
        case SET_SECTION:
            if (parse_set(rule_sections[i], rule, &data_type, errmsg) == PARSE_ERROR) {
                return PARSE_ERROR;
            }

               
            if (data_type == SINGLE_ADDR_RULE) {
                    
                if (parsed_scts.addr == true) {
                    *errmsg = TWO_OR_MORE_SECTIONS_WITH_SAME_TYPE;
                    return PARSE_ERROR;
                } else {
                    parsed_scts.addr = true;
                }

            } else {
                    
                if(parsed_scts.port == true) {
                    *errmsg = TWO_OR_MORE_SECTIONS_WITH_SAME_TYPE;
                    return PARSE_ERROR;
                } else {
                    parsed_scts.port = true;
                }
            }
            break;
        case SINGLE_VALUE:
            if (parse_single_token(rule_sections[i], rule, &data_type, errmsg) == PARSE_ERROR) {
                return PARSE_ERROR;
            }

            if (data_type == SINGLE_ADDR_RULE) {
                if (parsed_scts.addr == true) {
                    *errmsg = TWO_OR_MORE_SECTIONS_WITH_SAME_TYPE;
                    return PARSE_ERROR;
                } else {
                    parsed_scts.addr = true;
                }

            } else if (data_type == SINGLE_P_RULE || data_type == P_RANGE_RULE) {
                if(parsed_scts.port == true) {
                    *errmsg = TWO_OR_MORE_SECTIONS_WITH_SAME_TYPE;
                    return PARSE_ERROR;
                } else {
                    parsed_scts.port = true;
                }
            } if (data_type == TCP_PROTO_RULE || data_type == UDP_PROTO_RULE) {
                if(parsed_scts.proto == true) {
                    *errmsg = TWO_OR_MORE_SECTIONS_WITH_SAME_TYPE;
                    return PARSE_ERROR;
                } else {
                    parsed_scts.proto = true;
                }
            }    
            break;
        case MALFORMATTED_SET:
            *errmsg = MALFORMATED_SET_RULE_ERR;
            return PARSE_ERROR;
            break;
        }
    }

    return PARSE_OK;
}

static parse_command_status parse_default_policy_constant(struct command_token **token, const char **errmsg) {
    if (*token == NULL) {
        *errmsg = UNEXPECTED_END_OF_COMMAND;
        return PARSE_ERROR;
    }

    if (check_for_flag((*token)->token, NULL, errmsg) == FLAG_CHECK_ERROR) {
        return PARSE_ERROR;
    }
    
    if (strcmp((*token)->token, "policy") != 0) {
        *errmsg = WRONG_DEFAULT_POLICY_SYNTAX_ERR;

        return PARSE_ERROR;
    }

    *token = (*token)->next;

    return PARSE_OK;
}

static parse_command_status parse_default_policy(struct command_token **token, policy *policy, const char **errmsg) {
    if (*token == NULL) {
        *errmsg = UNEXPECTED_END_OF_COMMAND;
        return PARSE_ERROR;
    }

    if (check_for_flag((*token)->token, NULL, errmsg) == FLAG_CHECK_ERROR) {
        return PARSE_ERROR;
    }
    
    if(strcmp((*token)->token, "accept") == 0) {
        *policy = POLICY_ACCEPT;
    } else if(strcmp((*token)->token, "drop") == 0) {
        *policy = POLICY_DROP;
    } else {
        *errmsg = UNKNOWN_DEFAULT_POLICY;

        return PARSE_ERROR;
    }

    return PARSE_OK;
}

static parse_command_status parse_rm_rule_id(struct command_token **token, r_id *rule_id, const char **errmsg) {
    char *token_cpy;
    
    if (*token == NULL) {
        *errmsg = UNEXPECTED_END_OF_COMMAND;
        return PARSE_ERROR;
    }
    
    token_cpy = (*token)->token;

    while(*token_cpy) {
        if(isdigit(*token_cpy) == 0) {
            *errmsg = RULE_ID_IS_NOT_A_NUMBER_ERR;

            return PARSE_ERROR;
        }
        token_cpy++;
    }

    *rule_id = atoi((*token)->token);

    *token = (*token)->next;
    
    return PARSE_OK;
}

static parsed_token parse_token(char *token, ip_addr *addr, rule_type *rule, prefix *pre_len, port_value *p_begin, port_value *p_end) {
    if (parse_addr(token, addr, rule, pre_len) == PARSE_OK) {
        return ADDR_PARSED;
    }

    if (parse_port(token, rule, p_begin, p_end) == PARSE_OK) {
        return PORT_PARSED;
    }

    if (parse_proto(token, rule) == PARSE_OK) {
        return PROTO_PARSED;
    }

    return UNKNOWN_TOKEN_CLASS;
}
