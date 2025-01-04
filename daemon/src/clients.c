#include <clients.h>
#include <stdlib.h>
#include <string.h>

struct client_list_node *client_list = NULL;
const static char client_memory_err[] = "Not enough memory to allocate a new client";

new_client_status add_client(int fd, const char **errmsg) {
    
    struct client_list_node *n = malloc(sizeof(struct client_list_node));

    if(n == NULL) {
        *errmsg = client_memory_err;

        return NEW_CLIENT_MEM_FAILURE;
    }

    n->client_fd = fd;
    n->next = client_list;

    client_list = n;

    return NEW_CLIENT_OK;
}

struct client_list_node* get_clients(){
    return client_list;
}
