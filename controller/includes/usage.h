#ifndef __USAGE_GUARD__
#define __USAGE_GUARD__

#include <stdbool.h>

void print_drop_syntax(bool explain);
void print_accept_syntax(bool explain);
void print_default_syntax(bool explain);
void print_rm_syntax(bool explain);
void print_list_synxtax(bool explain);
void print_usage();

#endif