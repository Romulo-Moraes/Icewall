#include <fcntl.h>
#include <arpa/inet.h>
#include "../includes/helpers.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

int open_rules_chrdev(char *chr_dev) {
    int chrdev_fd = open(chr_dev, O_RDWR);

    if (chrdev_fd < 0) {
        perror("Error on open icewall channel: ");
        exit(1);
    }

    return chrdev_fd;
}

void send_add_rule_cmd(struct drop_accept_cmd *parsed_cmd, char *chr_dev) {
    int stt;
    int fd = open_rules_chrdev(chr_dev);

    if (parsed_cmd->dir == INCOMING) {
        stt = ioctl(fd, _IOCTL_ADD_INC_RULE, &parsed_cmd->rule);
    } else {
        stt = ioctl(fd, _IOCTL_ADD_OUT_RULE, &parsed_cmd->rule);
    }
}

void list_rules(direction dir, struct ioctl_list_result *result, char *chr_dev) {
    int fd = open_rules_chrdev(chr_dev);
    int stt;

   if (dir == INCOMING) {
        ioctl(fd, _IOCTL_LIST_INC, result);
    } else {
        ioctl(fd, _IOCTL_LIST_OUT, result);
    }
}

void generate_p_rule(struct rule_description desc, bool *first_rule, char *buffer_out) {
    char tmp[32];

    if (desc.p_rule == SINGLE_P_RULE || desc.p_rule == P_RANGE_RULE) {
        switch (desc.p_rule) {
            case SINGLE_P_RULE:
                sprintf(tmp, "%s%d", !*first_rule ? ":" : "", desc.p_begin);
                break;
            case P_RANGE_RULE:
                sprintf(tmp, "%s%d-%d", !first_rule ? ":" : "", desc.p_begin, desc.p_end);                
                break;
        }

        strcat(buffer_out, tmp);
        *first_rule = false;
    }
}

void generate_proto_rule(rule_type proto_rule, bool *first_rule, char *buffer_out) {
    char tmp[32];

    if (proto_rule == TCP_PROTO_RULE || proto_rule == UDP_PROTO_RULE) {
        sprintf(tmp, "%s%s", !*first_rule ? ":" : "", proto_rule == TCP_PROTO_RULE ? "tcp" : "udp");
        strcat(buffer_out, tmp);
    }
}

void generate_addr_rule(rule_type ip_rule, ip_addr addr, bool *first_rule, prefix pre_len, char *buffer_out) {
    struct in_addr net_addr;
    char *ip;
    char tmp[32];

    if (ip_rule == SINGLE_ADDR_RULE || ip_rule == ADDR_SET_RULE) {
        net_addr.s_addr = htonl(addr);
        ip = inet_ntoa(net_addr);

        strcat(buffer_out, ip);

        if (ip_rule == ADDR_SET_RULE) {
            sprintf(tmp, "/%u", pre_len);
            strcat(buffer_out, tmp);
        }

        *first_rule = false;
    }
}

void generate_rule_cmd(r_id id, struct rule_description desc, char *output, size_t out_len, direction dir) {
    char buffer[256] = {0};
    bool first_rule = true;

    sprintf(buffer, "%d - ", id);
    strcat(buffer, (desc.act == POLICY_ACCEPT ? "accept " : "drop "));
    strcat(buffer, (dir == INCOMING ? "incoming " : "outgoing "));

    generate_addr_rule(desc.ip_rule, desc.addr, &first_rule, desc.pre_len, buffer);

    generate_p_rule(desc, &first_rule, buffer);
    
    generate_proto_rule(desc.proto_rule, &first_rule, buffer);

    strncpy(output, buffer, out_len);
}

void print_rules(struct ioctl_list_result *result, direction dir, policy policy) {
    const size_t buff_len = 1024;
    char rule[buff_len];

    printf("Listing: %s rules\n", dir == INCOMING ? "incoming" : "outgoing");
    printf("Default policy: %s\n\n", policy == POLICY_ACCEPT ? "accept" : "drop");

    for (uint8_t i = 0; i < result->count; i++) {
        generate_rule_cmd(result->values[i].id, result->values[i].rule, rule, buff_len, dir);
        puts(rule);
    }
}

int rm_rule(r_id id, direction dir, char *chr_dev) {
    int fd;
    struct ioctl_rm_rule rm = {
        .id = id,
        .dir = dir
    };

    fd = open_rules_chrdev(chr_dev);

    return ioctl(fd, _IOCTL_RM_RULE, &rm);
}