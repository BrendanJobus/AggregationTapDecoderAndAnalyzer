// Function creates a socket and deals with a failed opening of said socket
//
// Args: the communication domain, the communication semantics, the protocol to use
//
// Returns: the socket file descriptor
//
// For more info on this visit: https://man7.org/linux/man-pages/man2/socket.2.html
int createSocket(int domain, int type, int protocol);

// Creates reusable socket bind by seting the socket options before binding so as to avoid a port already in use error
//
// Args: the server file descriptor, the server address as a pointer, the port number and the option to set
//
// Returns: nothing
//
// We change the server address to a pointer so that the changes are persistent when setting the server address settings
int createReusableBind(int fd, struct sockaddr_in *serv_addr, int port, int opt);


// Initiates a connect call and handles possible errors while also setting server address data
//
// Args: the socket fd of the object initiating the connect, port number of object initiating the connect
//       hostent pointer, contains information on the host server such as its name and address type,
//       server address as a pointer
//
// Returns: nothing
void clientConnect(int sockfd, int port, struct hostent *server, struct sockaddr_in *serv_addr);