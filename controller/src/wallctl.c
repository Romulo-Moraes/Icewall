#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include <usage.h>
#include <parser.h>
#include <icewall-ctrl.h>
#include <helpers.h>

#define RULES_DEV_FILE "/dev/" DEV_NAME

int main(int argc, char *argv[]) {

    if (argc < 2) {
        print_usage();
        return EXIT_FAILURE;
    }

    if (argv[1] == '-f') {

    } else {
        
    }

    return EXIT_SUCCESS;
}
