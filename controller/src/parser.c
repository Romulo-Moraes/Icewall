#include "../includes/parser.h"
#include "../../includes/icewall-ctrl.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <arpa/inet.h>

static struct rule_description desc;
static struct rule_description drop;
static struct drop_accept_cmd drop_accept;
static struct default_cmd dft_cmd;
static struct rm_cmd rm;
static struct list_cmd list;

static parse_status parse_token(char *token, struct rule_description *rule, struct parse_flags *flags);
static parse_status parse_port(char *token, struct rule_description *rule);
static parse_status parse_addr(char *token, struct rule_description *rule);
static parse_status parse_proto(char *token, struct rule_description *rule);
static uint8_t tokenize_rule(char *rule, char *tokens[3]);
static direction translate_direction(char *direction);

struct drop_accept_cmd* parse_drop_accept_cmd(int argc, char *argv[], unsigned char type) {
    char *tokens[3];
    uint8_t tkns_count;
    struct parse_flags flags = {.addr_parsed = false, .proto_parsed = false, .p_parsed = false};

    if (argc != 4) {
        return NULL;
    }

    drop_accept.rule.ip_rule = NO_ADDR_RULE;
    drop_accept.rule.p_rule = NO_P_RULE;
    drop_accept.rule.proto_rule = NO_PROTO_RULE;

    drop_accept.rule.act = (type == DROP ? POLICY_DROP : POLICY_ACCEPT);
    drop_accept.dir = translate_direction(argv[2]);

    if (drop_accept.dir == UNDEF_DIR) {
        return NULL;
    }

    tkns_count = tokenize_rule(argv[3], tokens);

    if (tkns_count == TOO_MANY_TOKENS || tkns_count == 0) {
        return NULL;
    }
    
    for (uint8_t i = 0; i < tkns_count; i++) {
        char *token = tokens[i];
        struct rule_description *rule = &drop_accept.rule;
        struct parse_flags *f = &flags;

        if (parse_token(token, rule, f) == PARSE_FAIL) {
            return NULL;
        }
    }

    return &drop_accept;
}

struct default_cmd* parse_default_cmd(int argc, char *argv[]) {
    if (argc != 4) {
        return NULL;
    }

    dft_cmd.dir = translate_direction(argv[2]);

    if (dft_cmd.dir == UNDEF_DIR) {
        return NULL;
    }
    
    if (strcmp(argv[3], "policy") != 0) {
        return NULL;
    }

    if (strcmp(argv[4], "accept") == 0) {
        dft_cmd.policy = POLICY_ACCEPT;
    } else if(strcmp(argv[4], "drop") == 0) {
        dft_cmd.policy = POLICY_DROP;
    } else {
        return NULL;
    }

    return &dft_cmd;
}

struct rm_cmd* parse_rm_cmd(int argc, char *argv[]) {
    int n;

    if (argc != 4) {
        return NULL;
    }

    rm.dir = translate_direction(argv[2]);

    if (rm.dir == UNDEF_DIR) {
        return NULL;
    }

    int matches = sscanf(argv[3], "%d%n", &rm.id, &n);

    if (matches != 1 || argv[3][n] != '\0') {
        return NULL;
    }

    return &rm;
}

struct list_cmd* parse_list_cmd(int argc, char *argv[]) {
    if (argc != 3) {
        return NULL;
    }

    list.dir = translate_direction(argv[2]);

    if (list.dir == UNDEF_DIR) {
        return NULL;
    }

    return &list;
}

static parse_status parse_port(char *token, struct rule_description *rule) {
    uint16_t p_begin, p_end;
    unsigned long n;

    int matches = sscanf(token, "%d-%d%n", &p_begin, &p_end, &n);

    if (matches == 3) {
        if (token[n] == '\0') {
            rule->p_rule = P_RANGE_RULE;
            rule->p_begin = p_begin;
            rule->p_end = p_end;

            return PARSE_OK;
        }
    } else {
        matches = sscanf(token, "%d%n", &p_begin, &n);

        if (matches == 2) {
            if (token[n] == '\0') {
                rule->p_rule = SINGLE_P_RULE;
                rule->p_begin = p_begin;

                return PARSE_OK;
            }
        }
    }

    return PARSE_FAIL;
}

static uint8_t tokenize_rule(char *rule, char *tokens[3]) {
    uint8_t tkns_count = 0;

    char *token = strtok(rule, ":");

    while (token != NULL) {
        if (tkns_count >= 3) {
            return TOO_MANY_TOKENS;
        }

        tokens[tkns_count++] = token;

        token = strtok(NULL, ":");
    }

    return tkns_count;
}

static direction translate_direction(char *direction) {
    if (strcmp(direction, "incoming") == 0) {
        return DIRECTION_IN;
    } else if (strcmp(direction, "outgoing") == 0) {
        return DIRECTION_OUT;
    } else {
        return UNDEF_DIR;
    }
}

static parse_status parse_addr(char *token, struct rule_description *rule) {
    char addr[32];
    struct in_addr parsed_addr;
    prefix prelen;
    int my_value;

    if (strlen(token) > 31) {
        return PARSE_FAIL;
    }

    int matches = sscanf(token, "%[^/]/%u%n", addr, &prelen, &my_value);

    if (matches != 2 || token[my_value] != '\0')  {
        matches = sscanf(token, "%s%n", addr, &my_value);

        if (matches != 1 || token[my_value] != '\0') {
            return PARSE_FAIL;
        }
    }

    if (inet_pton(AF_INET, addr, &parsed_addr) == 0) {
        return PARSE_FAIL;
    }

    if (matches == 2) {
        rule->ip_rule = ADDR_SET_RULE;
        rule->addr = ntohl(parsed_addr.s_addr);
        rule->pre_len = prelen;
    } else {
        rule->ip_rule = SINGLE_ADDR_RULE;
        rule->addr = ntohl(parsed_addr.s_addr);
    }

    return PARSE_OK;
}

static parse_status parse_proto(char *token, struct rule_description *rule) {
    unsigned long n;
    char proto[8];

    if (strlen(token) > 5) {
        return PARSE_FAIL;
    }

    int matches = sscanf(token, "%s%n", proto, &n);

    if (matches != 2 || token[n] != '\0') {
        return PARSE_FAIL;
    }

    if (strcmp(proto, "tcp") == 0) {
        rule->proto_rule = TCP_PROTO_RULE;
    } else if (strcmp(proto, "udp") == 0) {
        rule->proto_rule = UDP_PROTO_RULE;
    } else {
        return PARSE_FAIL;
    }

    return PARSE_OK;
}

static parse_status parse_token(char *token, struct rule_description *rule, struct parse_flags *flags) {
    if (parse_addr(token, rule) == PARSE_OK) {
        if (flags->addr_parsed == true) {
            
            return PARSE_FAIL;
        }
            
        flags->addr_parsed = true;

        return PARSE_OK;
    }

    if (parse_port(token, rule) == PARSE_OK) {
        if (flags->p_parsed == true) {
            return PARSE_FAIL;
        }

        flags->p_parsed = true;

        return PARSE_OK;
    }


    if (parse_proto(token, rule) == PARSE_OK) {
        if (flags->proto_parsed == true) {
            return PARSE_FAIL;
        }

        flags->proto_parsed = true;

        return PARSE_OK;
    }
}