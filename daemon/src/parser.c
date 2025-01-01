#include <parser.h>
#include <string.h>
#include <ctype.h>

#include <icewall.h>

#define FOUND_FLAG 2
#define NO_FLAG_FOUND 1
#define FLAG_CHECK_ERROR 0
#define PARSE_OK 1
#define PARSE_ERROR 0

typedef unsigned char check_flag_status;
typedef unsigned char parse_command_status;

static rule_direction direction;
static struct rule_description rule;
static const char* unknown_flag_err = "The given @FLAG is not known";
static const char* unknown_rule_direction_err = "The given direction is not known. Only \"incoming\" and \"outgoing\" allowed";
static const char* wrong_default_policy_syntax_err = "Wrong syntax, the correct is: default <incoming/outgoing> policy <accept/drop>";
static const char* unknown_default_policy = "Unknown default policy, only \"accept\" and \"drop\" allowed";
static const char* unexpected_tokens_err = "Unexpected tokens found after the end of the command";
static const char* rule_id_is_not_a_number_err = "The rule id must be a number";

static unsigned char check_for_flag(char *token);
static parse_command_status check_for_remaining_flags(struct command_token *token, const char **errmsg);
static parse_command_status parse_command_direction(struct command_token *token, const char **errmsg);
static parse_command_status parse_rule();
static parse_command_status parse_default_policy_constant(struct command_token *token, const char **errmsg);
static parse_command_status parse_default_policy(struct command_token *token, const char **errmsg);
static parse_command_status parse_rm_rule_id(struct command_token *token, const char **errmsg);

parse_status parse_command(struct command_token *cmd) {
  rule = (struct rule_description) {
    .p_rule = NO_P_RULE,
    .ip_rule = NO_ADDR_RULE,
    .proto_rule = NO_PROTO_RULE
  };
  
  if(strcmp(cmd->token, "drop") == 0) {
    
  } else if(strcmp(cmd->token, "accept") == 0) {
    
  } else if(strcmp(cmd->token, "default") == 0) {
    
  } else if(strcmp(cmd->token, "rm") == 0) {
    
  } else if(strcmp(cmd->token, "check") == 0) {
    
  } else if(strcmp(cmd->token, "dump") == 0) {

  } else if (strcmp(cmd->token, "list") == 0) {
    
  } else {
    return UNKNOWN_COMMAND;
  }
}

static check_flag_status check_for_flag(char *token) {
  if(*token == '@') {
    if(strcmp(&token[1], "LOG") == 0) {
      
      return FOUND_FLAG;
    } else {
      return FLAG_CHECK_ERROR;
    }
  }

  return NO_FLAG_FOUND;
}

static parse_command_status parse_command_direction(struct command_token *token, const char **errmsg) {
  check_flag_status stt = check_for_flag(token->token);

  switch (stt) {
  case FOUND_FLAG:
    return parse_command_direction(token->next, errmsg);
    break;
  case FLAG_CHECK_ERROR:
    *errmsg = unknown_flag_err;
    return PARSE_ERROR;
    break;
  }

  if(strcmp(token->token, "incoming") == 0) {
    direction = INCOMING_RULE;
  } else if (strcmp(token->token, "outgoing") == 0) {
    direction = OUTGOING_RULE;
  } else {
    *errmsg = unknown_rule_direction_err;
    return PARSE_ERROR;
  }


  return parse_rule();
}

static parse_command_status parse_rule() {
  
}

static parse_command_status parse_default_policy_constant(struct command_token *token, const char **errmsg) {
  check_flag_status stt = check_for_flag(token->token);

  switch (stt) {
  case FOUND_FLAG:
    return parse_default_policy_constant(token->next, errmsg);
    break;
  case FLAG_CHECK_ERROR:
    *errmsg = unknown_flag_err;
    return PARSE_ERROR;
    break;
  }

  if (strcmp(token->token, "policy") != 0) {
    *errmsg = wrong_default_policy_syntax_err;

    return PARSE_ERROR;
  }

  return parse_default_policy(token->next, errmsg);
}

static parse_command_status parse_default_policy(struct command_token *token, const char **errmsg) {
  check_flag_status stt = check_for_flag(token->token);

  switch (stt) {
  case FOUND_FLAG:
    return parse_default_policy(token->next, errmsg);
    break;
  case FLAG_CHECK_ERROR:
    *errmsg = unknown_flag_err;
    return PARSE_ERROR;
    break;
  }

  if(strcmp(token->token, "accept") == 0) {
    rule.act = POLICY_ACCEPT;
  } else if(strcmp(token->token, "drop") == 0) {
    rule.act = POLICY_DROP;
  } else {
    *errmsg = unknown_default_policy;

    return PARSE_ERROR;
  }

  return check_for_remaining_flags(token->next, errmsg);
}

static parse_command_status parse_rm_rule_id(struct command_token *token, const char **errmsg) {
  char *token_cpy = token->token;

  while(*token_cpy) {
    if(isdigit(*token_cpy) == 0) {
      *errmsg = rule_id_is_not_a_number_err;

      return PARSE_ERROR;
    }
    token_cpy++;
  }

  return check_for_remaining_flags(token->next, errmsg);
}

static parse_command_status check_for_remaining_flags(struct command_token *token, const char **errmsg) {
  check_flag_status stt;

  for (; token != NULL; token = token->next) {
    stt = check_for_flag(token->token);

    if (stt != FOUND_FLAG) {
      *errmsg = unexpected_tokens_err;

      return PARSE_ERROR;
    }
  }

  return PARSE_OK;
}
