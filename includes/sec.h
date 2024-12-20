#ifndef __SEC_GUARD__
#define __SEC_GUARD__

#include <linux/types.h>
#include <linux/limits.h>
#include "rules.h"
#include "icewall-ctrl.h"

#define INTEGRITY_EV_OK 1
#define INTEGRITY_EV_FAIL 0

bool check_dir_integrity(direction dir);
bool check_policy_integrity(policy policy);
bool check_rule_integrity(struct rule_description);

#endif