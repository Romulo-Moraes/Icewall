#ifndef __ERRORS_GUARD__
#define __ERRORS_GUARD__

#define UNKNOWN_FLAG_ERR "The given @FLAG is not known";
#define UNKNOWN_RULE_DIRECTION_ERR "The given direction is not known. Only \"incoming\" and \"outgoing\" allowed";
#define WRONG_DEFAULT_POLICY_SYNTAX_ERR "Wrong syntax, the correct is: default <incoming/outgoing> policy <accept/drop>";
#define UNKNOWN_DEFAULT_POLICY "Unknown default policy, only \"accept\" and \"drop\" allowed";
#define UNEXPECTED_TOKENS_ERR "Unexpected tokens found after the end of the command";
#define RULE_ID_IS_NOT_A_NUMBER_ERR "The rule id must be a number";
#define UNEXPECTED_NUMBER_OF_SECTIONS_ON_RULE_ERR "The correct way of declare a rule is: <[address]:[port]:[protocol]>";
#define MALFORMATED_SET_RULE_ERR "The correct way of declare a set is: { item1 item2 item3 }";
#define UNKNOWN_VALUE_AS_RULE "A given value doesn't seem to be a IP address, port or protocol";
#define INVALID_VALUE_INSIDE_SET "Only single IP addresses and ports are allowed inside sets";
#define INCONSISTENT_SET_TYPE "Inconsistent set type. A set can only contain items of the same type (addresses or ports)";
#define TWO_OR_MORE_SECTIONS_WITH_SAME_TYPE "The given rule contains the same kind of data in multiple sections. The correct way of declaring a rule is: <[address]:[port]:[protocol]>";
#define FLAGS_NOT_ALLOWED_ERR "This command doesn't accept flags";
#define UNEXPECTED_END_OF_COMMAND "The given command ended unexpectedly";
#define FLAGS_NOT_ALLOWED "This command doesn't allow flags";
#define CONTROL_COMMANDS_ON_RULES_SOURCE_FILE "This command have no meaning in a source file of rule";

#endif
