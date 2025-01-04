#include <parser-helpers.h>
#include <stdio.h>
#include <parser.h>
#include <stdbool.h>
#include <daemon-errors.h>
#include <errno.h>
#include <stdlib.h>
#include <parser.h>
#include <icewall.h>
#include <arpa/inet.h>
#include <string.h>

static parsed_token parse_token(char *token, ip_addr *addr, rule_type *rule, prefix *pre_len, port_value *p_begin, port_value *p_end);

check_flag_status check_for_flag(char *token, flags *flags, const char **errmsg) {
    if(*token == '@') {
        if (flags != NULL) {
            if(strcmp(&token[1], "LOG") == 0) {
                *flags |= LOG_FLAG;
                return FOUND_FLAG;
            } else {
                *errmsg = UNKNOWN_FLAG_ERR;
                return FLAG_CHECK_ERROR;
            }
        } else {
            *errmsg = FLAGS_NOT_ALLOWED;
            return FLAG_CHECK_ERROR;
        }
    }

    return NO_FLAG_FOUND;
}

uint8_t split_rule_sections(char *rule, char *sections[3]) {
    uint8_t scts_count = 0;

    char *section = strtok(rule, ":");

    while (section != NULL) {
        if (scts_count >= 3) {
            return TOO_MANY_SECTIONS;
        }

        sections[scts_count++] = section;

        section = strtok(NULL, ":");
    }

    return scts_count;
}

parse_command_status concat_rule_tokens(struct command_token *token, char **out, struct command_token **remaining_tokens, const char **errmsg) {
    size_t remaining_concat_len = 0;
    size_t concat_str_len = 0;
    char *concat_str = NULL;
    size_t concat_str_index = 0;
    char *token_cpy = token->token;
    bool keep_concat = true;
  
    while (keep_concat) {
        if (remaining_concat_len == 0) {
            concat_str_len += CONCAT_STR_CHUNK_SZ;
            remaining_concat_len = CONCAT_STR_CHUNK_SZ;
            concat_str = realloc(concat_str, concat_str_len);

            if (concat_str == NULL) {
                *errmsg = strerror(errno);
	
                return PARSE_ERROR;
            }
        }

        if (*token_cpy != '\0') {
            concat_str[concat_str_index] = *token_cpy;

            token_cpy++;
            concat_str_index++;
            remaining_concat_len--;
        } else {
            token = token->next;      
      
            if (token == NULL || token->token[0] == '@') {
                keep_concat = false;
            } else {
                token_cpy = token->token;
            }
        }
    }

    *remaining_tokens = token;
    *out = concat_str;
  
    return PARSE_OK;
}

parse_command_status check_for_remaining_flags(struct command_token *token, flags *flags, const char **errmsg) {
    check_flag_status stt;

    for (; token != NULL; token = token->next) {
        stt = check_for_flag(token->token, flags, errmsg);

        if (stt != FOUND_FLAG) {
            *errmsg = UNEXPECTED_TOKENS_ERR;

            return PARSE_ERROR;
        }
    }

    return PARSE_OK;
}

parse_status parse_port(char *token, rule_type *p_rule, port_value *p_begin, port_value *p_end) {
    uint16_t port_begin, port_end;
    int n;

    int matches = sscanf(token, "%hu-%hu%n", &port_begin, &port_end, &n);

    if(matches == 2) {
        if (token[n] == '\0') {
            *p_rule = P_RANGE_RULE;
            *p_begin = port_begin;
            *p_end = port_end;

            return PARSE_OK;
        }
    } else {
        matches = sscanf(token, "%hu%n", &port_begin, &n);

        if (matches == 1) {
            if (token[n] == '\0') {
                *p_rule = SINGLE_P_RULE;
                *p_begin = port_begin;

                return PARSE_OK;
            }
        }
    }

    return PARSE_ERROR;
}

parse_status parse_addr(char *token, ip_addr *addr, rule_type *ip_rule, prefix *pre_len) {
    char address[32];
    struct in_addr parsed_addr;
    prefix prelen;
    int my_value;

    if (strlen(token) > 31) {
        return PARSE_ERROR;
    }

    int matches = sscanf(token, "%[^/]/%hhu%n", address, &prelen, &my_value);

    if (matches != 2 || token[my_value] != '\0')  {
        matches = sscanf(token, "%s%n", address, &my_value);

        if (matches != 1 || token[my_value] != '\0') {
            return PARSE_ERROR;
        }
    }

    if (inet_pton(AF_INET, address, &parsed_addr) == 0) {
        return PARSE_ERROR;
    }
    
    if (matches == 2) {
        *ip_rule = ADDR_SET_RULE;
        *addr = ntohl(parsed_addr.s_addr);
        *pre_len = prelen;
    } else {
        *ip_rule = SINGLE_ADDR_RULE;
        *addr = ntohl(parsed_addr.s_addr);
    }

    return PARSE_OK;
}

parse_status parse_proto(char *token, rule_type *proto_rule) {
    int n;
    char proto[8];

    if (strlen(token) > 5) {
        return PARSE_ERROR;
    }

    int matches = sscanf(token, "%s%n", proto, &n);

    if (matches != 1 || token[n] != '\0') {
        return PARSE_ERROR;
    }

    if (strcmp(proto, "tcp") == 0) {
        *proto_rule = TCP_PROTO_RULE;
    } else if (strcmp(proto, "udp") == 0) {
        *proto_rule = UDP_PROTO_RULE;
    } else {
        return PARSE_ERROR;
    }

    return PARSE_OK;
}

unsigned char check_if_section_is_set(char *section) {
    char *token;
    size_t section_len = strlen(section);
     
    if (section[0] == '{' && section[section_len - 1] == '}') {
        return SET_SECTION;
        section[section_len - 1] = '\0';
        section++;

        token = strtok(section, " ");

        while (token) {
               
        }
    } else if (section[0] == '{' || section[section_len - 1] == '}') {
        return MALFORMATTED_SET;
    } else {
        return SINGLE_VALUE;
    }
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

