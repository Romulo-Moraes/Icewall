#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "../includes/usage.h"

// drop incoming/outgoing 127.0.0.1:8080:tcp
// drop incoming/outgoing 0.0.0.0/24:8080-9090:tcp
// accept incoming/outgoing 127.0.0.1:8080:tcp
// default incoming/outgoing policy accept/drop
// drops
// rm 10
// list incoming/outgoing

int main(int argc, char *argv[]) {
    bool act_performed = false;

    if (argc <= 1) {
        print_usage();
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "drop") == 0) {
        act_performed = true;
    }

    if (strcmp(argv[1], "accept") == 0) {
        act_performed = true;
    }

    if (strcmp(argv[1], "default") == 0) {
        act_performed = true;
    }

    if (strcmp(argv[1], "rm") == 0) {
        act_performed = true;
    }

    if (strcmp(argv[1], "drops") == 0) {
        act_performed = true;
    }

    if (strcmp(argv[1], "list") == 0) {
        act_performed = true;
    }

    if (act_performed == false) {
        print_usage();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}