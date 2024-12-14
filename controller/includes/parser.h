#ifndef __PARSER_GUARD__
#define __PARSER_GUARD__

#include <stdint.h>
#include "../../includes/icewall.h"

#define INCOMING 1
#define OUTGOING 2
#define UNDEF_DIR 3
#define PROTO_TCP 4
#define PROTO_UDP 5
#define PARSE_OK 6
#define PARSE_FAIL 7
#define TOO_MANY_TOKENS -1
#define DROP 8
#define ACCEPT 9

typedef uint8_t direction;
typedef uint8_t protocol;
typedef uint8_t policy;
typedef uint32_t address;
typedef uint8_t parse_status;

struct parse_flags {
    unsigned char addr_parsed : 1;
    unsigned char p_parsed : 1;
    unsigned char proto_parsed : 1;
};

struct drop_accept_cmd {
    direction dir;
    struct rule_description rule;
};

struct default_cmd {
    direction dir;
    policy policy;
};

struct rm_cmd {
    uint32_t id;
};

struct list_cmd {
    direction dir;
};

struct drop_accept_cmd* parse_drop_accept_cmd(int argc, char *argv[], unsigned char type);
struct default_cmd* parse_default_cmd(int argc, char *argv[]);
struct rm_cmd* parse_rm_cmd(int argc, char *argv[]);
struct list_cmd* parse_list_cmd(int argc, char *argv[]);

#endif