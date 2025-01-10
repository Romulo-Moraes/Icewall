#include "daemon-errors.h"
#include "rules-manager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <clients.h>
#include <daemon-interface.h>
#include <source-file-reader.h>

void handle_client_request(struct client_request request, int client_fd) {
    struct management_error err;
    management_status stt;
    struct rule_list *list;
    struct default_pol_storage *incoming;
    struct default_pol_storage *outgoing;
    char error_message[512];
    
    switch (request.req) {
    case DIRECT_RULE_COMMAND:
        break;
    case SOURCE_FILE_COMMAND:
        
        stt = manage_source_file(request.req_data, &err);

        if (stt == MANAGEMENT_OK) {
            get_rules_and_directions(&list, incoming, outgoing);

            // send to kernel...
        } else {
            send_error_message(client_fd, management_error_to_str(err, error_message));
        }
        
        break;
    default:
        break;
    }
}

int main(void) {
    const char *errmsg;
    struct client_request request;
    int client_fd;
    data_status client_read_status;
    accept_status stt;
    struct client_list_node *client_list;

    if (create_daemon_interface(&errmsg) == DAEMON_INTERFACE_ERROR) {
        fprintf(stderr, "Error while trying to create daemon interface: %s\n",
                errmsg);

        return 1;
    }

    while (1) {
        switch (accept_new_client(&client_fd, &errmsg)) {
        case NEW_CLIENT:
            if (add_client(client_fd, &errmsg) != NEW_CLIENT_OK) {
                fprintf(stderr, "Error while trying to accept a new client: %s\n",
                        errmsg);
            }
            break;
        case CLIENT_ERR:
            fprintf(stderr, "Error while trying to accept a new client: %s\n",
                    errmsg);
            break;
        }

        client_list = get_clients();

        for (; client_list != NULL; client_list = client_list->next) {
            client_read_status = read_data_from_client(client_fd, &request, &errmsg);

            switch (client_read_status) {
            case DATA_AVAILABLE:
                handle_client_request(request, client_list->client_fd);
                break;
            case DATA_ERR:
                fprintf(stderr, "Error while trying to read from client socket: %s\n", errmsg);
                break;
            }
        }

        sleep(1);
    }

    return 0;
}

