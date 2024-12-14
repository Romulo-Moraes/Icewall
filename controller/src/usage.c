#include "../includes/usage.h"
#include <stdio.h>

#define SYNTAX(explain) explain == true ? "\tsyntax: " : ""

void print_drop_syntax(bool explain) {
    puts(SYNTAX(explain) "drop <incoming/outgoing> <[address]:[port]:[protocol]>");

    if (explain == true) {
        puts("\ndescription: drops the incoming OR outgoing packets that match the filter. [x] is optional, but at least one is required.");
    }
}

void print_accept_syntax(bool explain) {
    puts(SYNTAX(explain) "accept <incoming/outgoing> <[address]:[port]:[protocol]>");

    if (explain == true) {
        puts("\ndescription: accepts the incoming OR outgoing packets that match the filter. [x] is optional, but at least is required.");
    }
}

void print_default_syntax(bool explain) {
    puts(SYNTAX(explain) "default <incoming/outgoing> policy <accept/drop>");

    if (explain == true) {
        puts("\ndescription: sets the default policy of incoming OR outgoing packets to accept OR drop.");
    }
}

void print_rm_syntax(bool explain){
    puts(SYNTAX(explain) "syntax: rm <id>");

    if (explain == true) {
        puts("\ndescription: removes the rule based on the given id.");
    }
}

void print_list_synxtax(bool explain) {
    puts(SYNTAX(explain) "list <incoming/outgoing>");

    if (explain == true) {
        puts("\ndescription: lists the current incoming OR outgoing rules");
    }
}

void print_usage() {
    puts("wallctl: the icewall firewall controller");
    
    puts("\nusage:");

    print_drop_syntax(false);
    print_accept_syntax(false);
    print_default_syntax(false);
    print_rm_syntax(false);
    print_list_synxtax(false);
}