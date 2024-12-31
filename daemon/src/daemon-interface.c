#include <daemon-interface.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static daemon_socket skct;

static error_status make_socket_nonblocking(int sock_fd, const char **errmsg);

accept_status accept_new_client(int *fd_out, const char **errmsg) {
  struct sockaddr_un addr;
  socklen_t len = sizeof(addr);
  
  int client_fd = accept(skct, (struct sockaddr*)&addr, &len);

  if (client_fd < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
	*errmsg = strerror(errno);

	return CLIENT_ERR;
      }

      return NO_CLIENT;
  }

  if (make_socket_nonblocking(client_fd, errmsg) == DAEMON_INTERFACE_ERROR) {
    return NO_CLIENT;
  }

  *fd_out = client_fd;
  
  return NEW_CLIENT;
}

void write_data_to_client(int client_fd) {
  
}

data_status read_data_from_client(int client_fd, struct client_request *data, const char **errmsg) {
  ssize_t data_read;
  
  if((data_read = recv(client_fd, data, sizeof(struct client_request), 0)) < 0){
    if (errno != EAGAIN && errno != EWOULDBLOCK){
      *errmsg = strerror(errno);

      return DATA_ERR;
    }
    
    return NO_DATA;
  }

  if (data_read != sizeof(struct client_request)) {
    return DATA_ERR;
  }

  return DATA_AVAILABLE;
}

error_status create_daemon_interface(const char **errmsg) {
  struct sockaddr_un addr;
  socklen_t len = sizeof(struct sockaddr_un);
  
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, UNIX_SOCKET_PATH);
  
  unlink(UNIX_SOCKET_PATH);
    
  skct = socket(AF_UNIX, SOCK_STREAM, 0);
  
  if (skct < 0) {
    *errmsg = strerror(errno);

    return DAEMON_INTERFACE_ERROR;
  }
  
  if(bind(skct, (struct sockaddr*)&addr, len) < 0){
    *errmsg = strerror(errno);

    return DAEMON_INTERFACE_ERROR;
  }

  chmod(UNIX_SOCKET_PATH, S_IRUSR | S_IWUSR);

  listen(skct, 8);

  if (make_socket_nonblocking(skct, errmsg) == DAEMON_INTERFACE_ERROR) {
    return DAEMON_INTERFACE_ERROR;
  }
  
  return DAEMON_INTERFACE_NO_ERROR;
}

close_interface_status close_daemon_interface(const char **errmsg) {
  if (unlink(UNIX_SOCKET_PATH) < 0) {
    *errmsg = strerror(errno);

    return CLOSE_OK;
  }

  return CLOSE_OK;
}

static error_status make_socket_nonblocking(int sock_fd, const char **errmsg) {
  int socket_flags = fcntl(sock_fd, F_GETFL, 0);

  if (socket_flags < 0) {
    *errmsg = strerror(errno);
    
    return DAEMON_INTERFACE_ERROR;
  }

  socket_flags |= O_NONBLOCK;

  if (fcntl(sock_fd, F_SETFL, socket_flags) < 0) {
    *errmsg = strerror(errno);

    return DAEMON_INTERFACE_ERROR;
  }

  return DAEMON_INTERFACE_NO_ERROR;
}
