#include <daemon-interface.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>

static daemon_socket skct;

static error_status make_socket_nonblocking(int sock_fd);

accept_status accept_new_client(int *fd_out) {
  int client_fd = accept(skct);

  if (client_fd < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
	perror("Error while trying to accept new client: ");
      }

      return NO_CLIENT;
  }

  if (make_socket_nonblocking(client_fd) == DAEMON_INTERFACE_ERROR) {
    return NO_CLIENT;
  }

  *fd_out = client_fd;
  
  return NEW_CLIENT;
}

void write_data_to_client(int client_fd) {
  
}

data_status read_data_from_client(int client_fd, char buffer[512]) {
  if(recv(client_fd, buffer, MAX_CLIENT_MESSAGE_SZ, 0) < 0){
    if (errno != EAGAIN && errno != EWOULDBLOCK){
      perror("Error while trying to read data from client: ");
    }

    return NO_DATA;
  }

  return DATA_AVAILABLE;
}

error_status create_socket() {
  unlink(UNIX_SOCKET_PATH);
    
  skct = socket(AF_INET, SOCK_STREAM, 0);
  int socket_flags;
  
  if (skct < 0) {
    perror("Create UNIX socket error: ");

    return DAEMON_INTERFACE_ERROR;
  }

  return make_socket_nonblocking(skct);
}

void delete_socket() {
  if (unlink(UNIX_SOCKET_PATH) < 0) {
    perror("Error while trying to delete UNIX socket: ");
  }
}

static error_status make_socket_nonblocking(int sock_fd) {
  int socket_flags = fnctl(sock_fd, F_GETFD, 0);

  if (socket_flags < 0) {
    perror("Get UNIX socket flags error: ");
    
    return DAEMON_INTERFACE_ERROR;
  }

  socket_flags |= O_NONBLOCK;

  if (fnctl(sock_fd, F_SETFD, socket_flags) < 0) {
    perror("Set UNIX socket flags error: ");

    return DAEMON_INTERFACE_ERROR;
  }

  return DAEMON_INTERFACE_NO_ERROR;
}
