#ifndef __PARSER_GUARD__
#define __PARSER_GUARD__

#include <icewall.h>
#include <icewall-ctrl.h>
#include <stdbool.h>

#define PARSE_SUCCESS 1
#define UNKNOWN_COMMAND 2
#define INCOMING_RULE 1
#define OUTGOING_RULE 2
#define NO_DIRECTION 3

#define RULE_COMMAND 1
#define RM_COMMAND 2
#define DEFAULT_COMMAND 3
#define DUMP_COMMAND 4

#define FOUND_FLAG 2
#define NO_FLAG_FOUND 1
#define FLAG_CHECK_ERROR 0
#define PARSE_OK 1
#define PARSE_ERROR 0
#define CONCAT_STR_CHUNK_SZ 512
#define TOO_MANY_SECTIONS UINT8_MAX

#define ADDR_PARSED 1
#define PORT_PARSED 2
#define PROTO_PARSED 3
#define UNKNOWN_TOKEN_CLASS 4


typedef unsigned char check_flag_status;
typedef unsigned char parse_command_status;
typedef unsigned char parse_status;
typedef unsigned char parsed_token;
typedef uint8_t direction;

struct parsed_sections {
    bool addr : 1;
    bool port : 1;
    bool proto : 1;
};

struct command_token {
    char *token;
    struct command_token *next;
};

struct rule_cmd {
    direction dir;
    struct rule_description rule;
};

struct default_cmd {
    direction dir;
    policy policy;
};

struct rm_cmd {
    r_id id;
    direction dir;
};

struct dump_cmd {
    direction dir;
};

typedef unsigned char parse_status;

parse_status parse_command(struct command_token *cmd, const char **msg, struct rule_cmd *rule, struct default_cmd *default_pol, struct rm_cmd *rm, struct dump_cmd *dump);

#endif
