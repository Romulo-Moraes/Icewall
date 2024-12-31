#include <daemon-interface.h>
#include <stdio.h>

int main(void) {
  char *errmsg;
  
  if (create_daemon_interface(&errmsg) == DAEMON_INTERFACE_ERROR) {
    perror("Error while trying to create daemon interface");
  }
  
  return 0;
}
