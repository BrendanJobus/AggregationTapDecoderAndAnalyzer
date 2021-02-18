#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "basicNetworking.h"

#define DEFAULT_SERVER_PORT 2099
#define DEFAULT_SERVER "localhost"

void messagingProtocol(int sockfd) {
  int n;
  char buffer[256];

  printf("Please enter the message: ");
  bzero(buffer, 256);
  fgets(buffer, 255, stdin);
  n = write(sockfd, buffer, strlen(buffer));
  if (n < 0) { 
    perror("ERROR writing to socket"); 
    exit(EXIT_FAILURE); 
  }

  bzero(buffer, 256);
  n = read(sockfd, buffer, 255);
  if (n < 0) { 
    perror("ERROR reading from socket"); 
    exit(EXIT_FAILURE); 
  }

  printf("%s\n", buffer);
}

int main(int argc, char *argv[]) {
  int sockfd, portno, n;
  struct sockaddr_in serv_addr;
  struct hostent *server;

  if (argc < 3) {
    printf("usage %s hostname port\nNow switching to default case\n", argv[0]);
    portno = DEFAULT_SERVER_PORT;
    server = gethostbyname(DEFAULT_SERVER);
    if (server == NULL) {
      fprintf(stderr, "ERROR: no such host\n");
      exit(EXIT_FAILURE);
    }
  } else {
    portno = atoi(argv[2]);
    server = gethostbyname(argv[1]);
    if (server == NULL) {
      fprintf(stderr, "ERROR: no such host\n");
      exit(EXIT_FAILURE);
    }
  }
  sockfd = createSocket(AF_INET, SOCK_STREAM, 0);
  clientConnect(sockfd, portno, server, &serv_addr);
  messagingProtocol(sockfd);

  close(sockfd);
  return 0;
}