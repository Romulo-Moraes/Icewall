#ifndef __CLIENTS_GUARD__
#define __CLIENTS_GUARD__

#include <icewall.h>

#define NEW_CLIENT_MEM_FAILURE 1
#define NEW_CLIENT_OK 2

typedef unsigned char new_client_status;

struct client_list_node {
    int client_fd;
    struct client_list_node *next;
};

new_client_status add_client(int fd, const char **errmsg);
struct client_list_node* get_clients();

#endif
