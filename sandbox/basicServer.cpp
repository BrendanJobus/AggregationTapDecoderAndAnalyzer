#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include "basicNetworking.h"

#define DEFAULT_PORT 2099

// Function prints that a client has connected, then sends a message and then waits for a message in return and prints it
//
// Args: the server socket file descriptor, the client socket file descriptor, the client address and the lenght of the client address
//
// Returns: Nothing
void acceptHandler(int sockfd, int clifd, struct sockaddr_in cli_addr, socklen_t clilen) {
  int n;
  char buffer[256];
  bzero((char *) buffer, sizeof(buffer));

  printf("server: got connection from %s port %d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
  send(clifd, "Hello, world!\n", 13, 0);

  n = read(clifd, buffer, 255);
  if (n < 0) { perror("ERROR reading from socket\n"); exit(EXIT_FAILURE); }
  printf("\nMessage from %s port %d: %s", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), buffer);
  close(clifd);
}


// Things that may need to change, currently we are using SOCK_STREAM which sets up a TCP socket, we may want to use another if
// We are trying to access data from further down the osi model

int main(int argc, char *argv[]) {
  int sockfd, newsockfd, portno, n, opt = 1;
  char buffer[255];
  struct sockaddr_in serv_addr, cli_addr;
  socklen_t clilen = sizeof(cli_addr);

  if (argc < 2) {
    printf("usage: %s port\nNow switching to default mode\n", argv[0]);
    portno = DEFAULT_PORT;
  } else {
    portno = atoi(argv[1]);
  }

  sockfd = createSocket(AF_INET, SOCK_STREAM, 0);

  createReusableBind(sockfd, &serv_addr, portno, opt);

  listen(sockfd, 5);

  while(1) {
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0) { 
      perror("ERROR on accept"); exit(EXIT_FAILURE); 
    }
    std::thread(acceptHandler, sockfd, newsockfd, cli_addr, clilen).detach();
  }

  close(sockfd);
  return 0;
}