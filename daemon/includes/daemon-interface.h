#ifndef __DAEMON_INTERFACE__
#define __DAEMON_INTERFACE__

#include <stdint.h>

#define DATA_AVAILABLE 1
#define NO_DATA 0
#define UNIX_SOCKET_PATH "/usr/lib/systemd/system/icewall.socket"
#define DAEMON_INTERFACE_ERROR 1
#define DAEMON_INTERFACE_NO_ERROR 0
#define NEW_CLIENT 1
#define NO_CLIENT 0
#define MAX_CLIENT_MESSAGE_SZ 512

typedef uint8_t data_status;
typedef int daemon_socket;
typedef uint8_t error_status;
typedef uint8_t accept_status;
accept_status accept_new_client(int *fd_out);
void write_data_to_client(int client_fd);
data_status read_data_from_client(int client_fd, char buffer[MAX_CLIENT_MESSAGE_SZ]);
error_status create_socket();
void delete_socket();

#endif
