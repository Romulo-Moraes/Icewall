#include "../includes/usage.h"
#include <stdio.h>

#define SYNTAX(explain) if(explain == true) { printf("Syntax: "); }

void print_drop_syntax(bool explain) {
    if (explain == true) {
        puts("Description: drops the incoming OR outgoing packets that match the filter.\n             [ address | port | protocol ] are optional, but at least one is required.");
    }

    SYNTAX(explain);
    puts("drop <incoming/outgoing> <[address]:[port]:[protocol]>");
}

void print_accept_syntax(bool explain) {
    if (explain == true) {
        puts("Description: accepts the incoming OR outgoing packets that match the filter.\n             [ address | port | protocol ] are optional, but at least one is required.");
    }

    SYNTAX(explain);
    puts("accept <incoming/outgoing> <[address]:[port]:[protocol]>");
}

void print_default_syntax(bool explain) {
    if (explain == true) {
        puts("Description: sets the default policy of incoming OR outgoing packets to accept OR drop.");
    }

    SYNTAX(explain);
    puts("default <incoming/outgoing> policy <accept/drop>");
}

void print_rm_syntax(bool explain){
    if (explain == true) {
        puts("Description: removes the incoming OR outgoing rule based on the given id.");
    }

    SYNTAX(explain);
    puts("rm <incoming/outgoing> <id>");
}

void print_list_synxtax(bool explain) {
    if (explain == true) {
        puts("Description: lists the current incoming OR outgoing rules");
    }

    SYNTAX(explain);
    puts("list <incoming/outgoing>");
}

void print_usage() {
    puts("wallctl: the icewall firewall controller");
    
    puts("\nwallctl controller usage:\n");

    print_drop_syntax(false);
    print_accept_syntax(false);
    print_default_syntax(false);
    print_rm_syntax(false);
    print_list_synxtax(false);
}