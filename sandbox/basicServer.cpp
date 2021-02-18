#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>

#define DEFAULT_PORT 2099

void acceptHandler(int sockfd, int clisockfd, struct sockaddr_in cli_addr, socklen_t clilen) {
  int n;
  char buffer[256];
  bzero((char *) buffer, sizeof(buffer));

  printf("server: got connection from %s port %d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
  send(clisockfd, "Hello, world!\n", 13, 0);

  n = read(clisockfd, buffer, 255);
  if (n < 0) { perror("ERROR reading from socket\n"); exit(EXIT_FAILURE); }
  printf("\nMessage from %s port %d: %s", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), buffer);
  close(clisockfd);
}

int main(int argc, char *argv[]) {
  int sockfd, newsockfd, portno;
  int sockbinding, opt = 1;

  socklen_t clilen;
  char buffer[255];

  struct sockaddr_in serv_addr, cli_addr;
  int n;

  if (argc < 2) {
    printf("usage: %s port\nNow switching to default mode\n", argv[0]);
    portno = DEFAULT_PORT;
  } else {
    portno = atoi(argv[1]);
  }

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) { perror("ERROR opening socket\n"); exit(EXIT_FAILURE); }

  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);

  if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
    perror("ERROR on binding\n");
    exit(EXIT_FAILURE);
  }

  listen(sockfd, 5);

  clilen = sizeof(cli_addr);

  while(1) {
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0) { perror("ERROR on accept"); exit(EXIT_FAILURE); }
    std::thread(acceptHandler, sockfd, newsockfd, cli_addr, clilen).detach();
  }

  close(sockfd);
  return 0;
}
