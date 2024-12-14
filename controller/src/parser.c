#include "../includes/parser.h"
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
static struct default_cmd;
static struct rm_cmd;
static struct list_cmd;

static parse_status parse_token(char *token, struct rule_description *rule, struct parse_flags *flags);
static parse_status parse_port(char *token, struct rule_description *rule);
static parse_status parse_addr(char *token, struct rule_description *rule);
static parse_status parse_proto(char *token, struct rule_description *rule);
static uint8_t tokenize_rule(char *rule, char *tokens[3]);
static direction translate_direction(char *direction);

struct drop_accept_cmd* parse_drop_cmd(int argc, char *argv[]) {
    char *tokens[3];
    uint8_t tkns_count;
    struct parse_flags flags = {.addr_parsed = false, .addr_parsed = false, .p_parsed = false};

    drop_accept.rule.act = POLICY_DROP;
    drop_accept.dir = translate_direction(argv[2]);

    if (drop_accept.dir == UNDEF_DIR) {
        return NULL;
    }

    tkns_count = tokenize_rule(argv[3], tokens);

    if (tkns_count == TOO_MANY_TOKENS || tkns_count == 0) {
        return NULL;
    }

    for (uint8_t i = 0; i < tkns_count; i++) {
        if (parse_token(tokens[i], &drop_accept.rule, &flags) == PARSE_FAIL) {
            return NULL;
        }
    }

    return &drop_accept;
}

struct drop_accept_cmd* parse_accept_cmd(int argc, char *argv[]) {

}

struct default_cmd* parse_default_cmd(int argc, char *argv[]) {

}

struct rm_cmd* parse_rm_cmd(int argc, char *argv[]) {

}

struct list_cmd* parse_list_cmd(int argc, char *argv[]) {

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
        return INCOMING;
    } else if (strcmp(direction, "outgoing") == 0) {
        return OUTGOING;
    } else {
        return UNDEF_DIR;
    }
}

static parse_status parse_addr(char *token, struct rule_description *rule) {
    char addr[32];
    struct in_addr parsed_addr;
    prefix prelen;
    unsigned long n;

    if (strlen(token) > 31) {
        return PARSE_FAIL;
    }

    int matches = sscanf(token, "%[\^/]/%u%n", addr, &prelen, &n);

    if (matches != 3 || token[n] != '\0')  {
        matches = sscanf(token, "%[\^/]%n", addr, &n);

        if (matches != 2 || token[n] != '\0') {
            return PARSE_FAIL;
        }
    }

    if (inet_pton(AF_INET, addr, &parsed_addr) == 0) {
        return PARSE_FAIL;
    }

    if (matches == 3) {
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