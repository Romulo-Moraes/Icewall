#ifndef __RULES_MANAGER__
#define __RULES_MANAGER__

#include <stdbool.h>
#include <icewall-ctrl.h>
#include <stddef.h>
#include <parser.h>

#define MAX_LINE_LEN 2048
#define TOKENIZE_COMMAND_OK 1
#define TOKENIZE_COMMAND_ERROR 0

#define MANAGEMENT_OK 1
#define MANAGEMENT_ERROR 0

typedef unsigned char management_status;
typedef unsigned char tokenize_command_status;


struct command_list {
    struct command_token *tokens;
    struct command_list *next;
};

struct default_pol_storage {
    bool set;
    policy policy;
};

struct rule_list {
    struct rule_cmd rule;
    struct rule_list *next;
};

management_status manage_direct_rule(char *command);
management_status manage_source_file(char *path, struct management_error *err);
void get_rules_and_directions(struct rule_list **list, struct default_pol_storage *incoming, struct default_pol_storage *outgoing);

#endif
