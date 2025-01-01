#ifndef __PARSER_GUARD__
#define __PARSER_GUARD__

#define PARSE_SUCCESS 1
#define UNKNOWN_COMMAND 2
#define INCOMING_RULE 1
#define OUTGOING_RULE 2

struct command_token {
  char *token;
  struct command_token *next;
};

typedef unsigned char parse_status;
typedef unsigned char rule_direction;

parse_status parse_command(struct command_token *cmd);

#endif
