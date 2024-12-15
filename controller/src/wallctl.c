#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "../includes/usage.h"
#include "../includes/parser.h"
#include "../../includes/icewall-ctrl.h"

#define RULES_DEV_FILE "/dev/" DEV_NAME

// drop incoming/outgoing 127.0.0.1:8080:tcp
// drop incoming/outgoing 0.0.0.0/24:8080-9090:tcp
// accept incoming/outgoing 127.0.0.1:8080:tcp
// default incoming/outgoing policy accept/drop
// drops
// rm 10
// list incoming/outgoing

int open_rules_chrdev() {
    int chrdev_fd = open(RULES_DEV_FILE, O_RDWR);

    if (chrdev_fd < 0) {
        perror("Error on open icewall channel: ");
        exit(1);
    }

    return chrdev_fd;
}

void send_add_rule_cmd(struct drop_accept_cmd *parsed_cmd) {
    int stt;
    int fd = open_rules_chrdev();

    if (parsed_cmd->dir == INCOMING) {
        stt = ioctl(fd, _IOCTL_ADD_INC_RULE, &parsed_cmd->rule);
    } else {
        stt = ioctl(fd, _IOCTL_ADD_OUT_RULE, &parsed_cmd->rule);
    }

    printf("status: %d\n", stt);
}

int main(int argc, char *argv[]) {
    bool act_performed = false;
    int chrdev_fd;
    struct drop_accept_cmd *parsed_cmd;

    if (argc <= 1) {
        print_usage();
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "drop") == 0) {
        parsed_cmd = parse_drop_accept_cmd(argc, argv, DROP);

        send_add_rule_cmd(parsed_cmd);

        act_performed = true;
    }

    if (strcmp(argv[1], "accept") == 0) {
        parsed_cmd = parse_drop_accept_cmd(argc, argv, ACCEPT);

        printf(">>%d\n", parsed_cmd->rule.act);

        send_add_rule_cmd(parsed_cmd);

        act_performed = true;
    }

    if (strcmp(argv[1], "default") == 0) {
        struct default_cmd *parsed_cmd = parse_default_cmd(argc, argv);
        act_performed = true;
    }

    if (strcmp(argv[1], "rm") == 0) {
        struct rm_cmd *parsed_cmd = parse_rm_cmd(argc, argv);
        act_performed = true;
    }

    if (strcmp(argv[1], "drops") == 0) {
        act_performed = true;
    }

    if (strcmp(argv[1], "list") == 0) {
        struct list_cmd *parsed_cmd = parse_list_cmd(argc, argv);
        act_performed = true;
    }

    if (act_performed == false) {
        print_usage();
        return EXIT_FAILURE;
    }


    if (parsed_cmd->dir == INCOMING) {
        
    } else {
        ioctl(chrdev_fd, _IOCTL_ADD_OUT_RULE, NULL);
    }
    

    return EXIT_SUCCESS;
}