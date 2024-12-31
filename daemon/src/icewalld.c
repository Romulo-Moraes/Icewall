#include <stdio.h>
#include <unistd.h>

#include <daemon-interface.h>
#include <clients.h>

void receive_data_from_client(int client_fd);

int main(void) {
  const char *errmsg;
  int client_fd;
  accept_status stt;
  struct client_list_node *client_list;
  
  if (create_daemon_interface(&errmsg) == DAEMON_INTERFACE_ERROR) {
    fprintf(stderr, "Error while trying to create daemon interface: %s\n", errmsg);

    return 1;
  }

  while(1) {
    switch(accept_new_client(&client_fd, &errmsg)) {
    case NEW_CLIENT:
      if (add_client(client_fd, &errmsg) != NEW_CLIENT_OK) {
	fprintf(stderr, "Error while trying to accept a new client: %s\n", errmsg);
      }
      break;
    case CLIENT_ERR:
      fprintf(stderr, "Error while trying to accept a new client: %s\n", errmsg);
      break;
    }

    client_list = get_clients();
    
    for(; client_list != NULL; client_list = client_list->next) {
      receive_data_from_client(client_list->client_fd);
    }
    
    sleep(1);
  }
  
  return 0;
}

void receive_data_from_client(int client_fd) {
  const char *errmsg;
  struct client_request request;
  data_status stt;

  stt = read_data_from_client(client_fd, &request, &errmsg);
  
  switch (stt) {
  case DATA_AVAILABLE:
	
    break;
  case DATA_ERR:
    fprintf(stderr, "Error while trying to read data from client: %s\n", errmsg);
    break;
  }
}
