#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <thread>

int createSocket(int domain, int type, int protocol) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { perror("ERROR opening socket\n"); exit(EXIT_FAILURE); }
  return fd;
}

void createReusableBind(int fd, struct sockaddr_in *serv_addr, int port, int opt) {
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
    perror("ERROR failed to set socket options");
    exit(EXIT_FAILURE);
  }

  bzero((char *) serv_addr, sizeof(*serv_addr));
  (*serv_addr).sin_family = AF_INET;
  (*serv_addr).sin_addr.s_addr = INADDR_ANY;
  (*serv_addr).sin_port = htons(port);

  if (bind(fd, (struct sockaddr *) serv_addr, sizeof(*serv_addr)) < 0) {
    perror("ERROR on binding\n");
    exit(EXIT_FAILURE);
  }
}

void clientConnect(int sockfd, int port, struct hostent *server, struct sockaddr_in *serv_addr) {
  bzero((char *) serv_addr, sizeof(*serv_addr));
  (*serv_addr).sin_family = AF_INET; 
  bcopy((char *)server->h_addr, (char *) &(*serv_addr).sin_addr.s_addr, server->h_length); 
  (*serv_addr).sin_port = htons(port);
  if(connect(sockfd, (struct sockaddr *) serv_addr, sizeof(*serv_addr)) < 0) {
      perror("ERROR connecting");
      exit(EXIT_FAILURE);
  } 
}