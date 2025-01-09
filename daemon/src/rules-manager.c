#include <errno.h>
#include <daemon-errors.h>
#include <rules-manager.h>
#include <malloc.h>
#include <source-file-reader.h>
#include <stdbool.h>
#include <stddef.h>
#include <parser.h>
#include <stdlib.h>
#include <string.h>

static struct default_pol_storage incoming_policy;
static struct default_pol_storage outgoing_policy;
static struct rule_list *rule_list;

static tokenize_command_status tokenize_command(char *command, struct command_token **list_out, const char **err);
static struct command_token *create_command_token(char *token, const char **err);
static struct command_list *create_command_list(struct command_token *token_list,
                                                const char **err);
static struct rule_list* create_rule_list_node(struct rule_cmd rule, const char **err);
static void reset_manager_environment();


management_status manage_direct_rule(char *command){
    reset_manager_environment();
}

management_status manage_source_file(char *path, struct management_error *err) {
    char *line;
    size_t line_number;
    parse_status status;
    struct rule_list *rule_list_head = NULL;
    struct rule_cmd rule;
    struct default_cmd default_pol;
    struct command_token *tokenized_command;

    reset_manager_environment();
    
    if (open_rules_file(path, &err->msg) == OPEN_RULES_FILE_ERROR) {
        err->type = PROCESS_RELATED_ERROR;
        return MANAGEMENT_ERROR;
    }

    while(check_rules_file_eof() != true) {
        if (read_rules_file_line(&line, &line_number, &err->msg) == READ_RULES_FILE_ERROR) {
            err->type = PROCESS_RELATED_ERROR;
            return MANAGEMENT_ERROR;
        }

        if (tokenize_command(line, &tokenized_command, &err->msg) == TOKENIZE_COMMAND_ERROR) {
            err->type = PROCESS_RELATED_ERROR;
            return MANAGEMENT_ERROR;
        }

        // only parsers that result in rules and defaults are acceptable here
        status = parse_command(tokenized_command, &err->msg, &rule, &default_pol, NULL, NULL);

        switch (status) {
        case RULE_COMMAND:

            if (rule_list == NULL) {
                if ((rule_list = create_rule_list_node(rule, &err->msg)) == NULL) {
                    err->type = PROCESS_RELATED_ERROR;
                    return MANAGEMENT_ERROR;
                }
                
                rule_list_head = rule_list;
            } else {
                if ((rule_list_head->next = create_rule_list_node(rule, &err->msg)) == NULL) {
                    err->type = PROCESS_RELATED_ERROR;
                    return MANAGEMENT_ERROR;
                }
                
                rule_list_head = rule_list_head->next;
            }
            
            break;
        case DEFAULT_COMMAND:

            if (default_pol.dir == INCOMING_RULE) {
                incoming_policy.set = true;
                incoming_policy.policy = default_pol.policy;
            } else {
                outgoing_policy.set = true;
                outgoing_policy.policy = default_pol.policy;
            }
            
            break;
        case PARSE_ERROR:
        case UNKNOWN_COMMAND:
            err->type = SOURCE_FILE_RELATED_ERROR;
            err->line = line_number;

            return MANAGEMENT_ERROR;
            break;
        default:
            err->type = SOURCE_FILE_RELATED_ERROR;
            err->line = line_number;
            err->msg = CONTROL_COMMANDS_ON_RULES_SOURCE_FILE;

            return MANAGEMENT_ERROR;
            break;
        }
    }

    return MANAGEMENT_OK;
}

static struct command_token *create_command_token(char *token, const char **err) {
    struct command_token *t = malloc(sizeof(struct command_token));

    if (t == NULL) {
        *err = strerror(errno);
        return NULL;
    }

    t->token = malloc(sizeof(char) * strlen(token));

    if (t->token == NULL) {
        *err = strerror(errno);
        return NULL;
    }

    strcpy(t->token, token);
    t->next = NULL;
    
    return t;
}

static tokenize_command_status tokenize_command(char *command, struct command_token **list_out, const char **err) {
    struct command_token *token_list = NULL;
    struct command_token *list_end = NULL;
    char *command_copy = malloc(sizeof(char) * strlen(command));
    char *token;

    if (command_copy == NULL) {
        *err = strerror(errno);
        return TOKENIZE_COMMAND_ERROR;
    }

    strcpy(command_copy, command);
    
    token = strtok(command_copy, " ");

    while (token != NULL) {
        if (token_list == NULL) {
            if((token_list = create_command_token(token, err)) == NULL) {
                return TOKENIZE_COMMAND_ERROR;
            }

            list_end = token_list;
        } else {
            if((list_end->next = create_command_token(token, err)) == NULL) {
                return TOKENIZE_COMMAND_ERROR;
            }

            list_end = list_end->next;
        }

        token = strtok(NULL, " ");
    }

    return TOKENIZE_COMMAND_OK;
}

static struct command_list *create_command_list(struct command_token *token_list,
                                                const char **err) {
    struct command_list *l = malloc(sizeof(struct command_list));

    if (l == NULL) {
        *err = strerror(errno);
        return NULL;
    }

    l->tokens = token_list;
    l->next = NULL;

    return l;
}

static void reset_manager_environment() {
    incoming_policy.set = false;
    outgoing_policy.set = false;
    rule_list = NULL;
}

static struct rule_list* create_rule_list_node(struct rule_cmd rule, const char **err) {
    struct rule_list *n = malloc(sizeof(struct rule_list));

    if (n == NULL) {
        *err = strerror(errno);
        return NULL;
    }

    n->rule = rule;
    n->next = NULL;

    return n;
}

void get_rules_and_directions(struct rule_list **list,
                              struct default_pol_storage *incoming,
                              struct default_pol_storage *outgoing) {
    *list = rule_list;
    *incoming = incoming_policy;
    *outgoing = outgoing_policy;
}
