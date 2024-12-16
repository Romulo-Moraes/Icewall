#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include "../includes/usage.h"
#include "../includes/parser.h"
#include "../../includes/icewall-ctrl.h"
#include "../includes/helpers.h"

#define RULES_DEV_FILE "/dev/" DEV_NAME

int main(int argc, char *argv[]) {
    bool act_performed = false;
    int chrdev_fd;
    struct drop_accept_cmd *parsed_cmd;
    struct ioctl_list_result result;

    if (argc <= 1) {
        print_usage();
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "drop") == 0) {
        parsed_cmd = parse_drop_accept_cmd(argc, argv, DROP);

        if (parsed_cmd == NULL) {
            print_drop_syntax(true);
            return EXIT_FAILURE;
        }

        send_add_rule_cmd(parsed_cmd, RULES_DEV_FILE);

        act_performed = true;
    }

    if (strcmp(argv[1], "accept") == 0) {
        parsed_cmd = parse_drop_accept_cmd(argc, argv, ACCEPT);

        if (parsed_cmd == NULL) {
            print_accept_syntax(true);
            return EXIT_FAILURE;
        }

        send_add_rule_cmd(parsed_cmd, RULES_DEV_FILE);

        act_performed = true;
    }

    if (strcmp(argv[1], "default") == 0) {
        struct default_cmd *parsed_cmd = parse_default_cmd(argc, argv);

        if (parsed_cmd == NULL) {
            print_default_syntax(true);
            return EXIT_FAILURE;
        }

        int fd = open_rules_chrdev();

        if (parsed_cmd->dir == DIRECTION_IN) {
            ioctl(fd, _IOCTL_SET_INC_POLICY, &parsed_cmd->policy);
        } else {
            ioctl(fd, _IOCTL_SET_OUT_POLICY, &parsed_cmd->policy);
        }
            
        act_performed = true;
    }

    if (strcmp(argv[1], "rm") == 0) {
        struct rm_cmd *parsed_cmd = parse_rm_cmd(argc, argv);

        if (parsed_cmd == NULL) {
            print_rm_syntax(true);
            return EXIT_FAILURE;
        }

        if (rm_rule(parsed_cmd->id, parsed_cmd->dir, RULES_DEV_FILE) < 0) {
            printf("the %s rule id %d does not exist.\n", argv[2], parsed_cmd->id);
            return EXIT_FAILURE;
        }

        printf("%s rule id %d removed.\n", argv[2], parsed_cmd->id);

        act_performed = true;
    }

    if (strcmp(argv[1], "list") == 0) {
        struct list_cmd *parsed_cmd = parse_list_cmd(argc, argv);
        
        if (parsed_cmd == NULL) {
            print_list_synxtax(true);
            return EXIT_FAILURE;
        }

        list_rules(parsed_cmd->dir, &result, RULES_DEV_FILE);

        print_rules(&result, parsed_cmd->dir, result.policy);

        act_performed = true;
    }

    if (act_performed == false) {
        print_usage();
        return EXIT_FAILURE;
    }    

    return EXIT_SUCCESS;
}