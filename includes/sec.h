#ifndef __SEC_GUARD__
#define __SEC_GUARD__

#include <stdbool.h>
#include "rules.h"

#define INTEGRITY_EV_OK 1
#define INTEGRITY_EV_FAIL 0

bool check_rule_integrity(struct rule_description);

#endif