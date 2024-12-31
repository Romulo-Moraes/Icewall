#ifndef __DAEMON_INTERFACE__
#define __DAEMON_INTERFACE__

#include <stdint.h>

#define DATA_ERR 2
#define DATA_AVAILABLE 1
#define NO_DATA 0
#define UNIX_SOCKET_PATH "/usr/lib/systemd/system/icewall.socket"
#define DAEMON_INTERFACE_ERROR 1
#define DAEMON_INTERFACE_NO_ERROR 0
#define CLIENT_ERR 2
#define NEW_CLIENT 1
#define NO_CLIENT 0
#define MAX_CLIENT_MESSAGE_SZ 512
#define CLOSE_OK 1
#define CLOSE_ERR 0

typedef uint8_t close_interface_status;
typedef uint8_t data_status;
typedef int daemon_socket;
typedef uint8_t error_status;
typedef uint8_t accept_status;

accept_status accept_new_client(int *fd_out, char **errmsg);
void write_data_to_client(int client_fd);
data_status read_data_from_client(int client_fd, char buffer[MAX_CLIENT_MESSAGE_SZ], char **errmsg);
error_status create_daemon_interface(char **errmsg);
close_interface_status close_daemon_interface(char **errmsg);

#endif
