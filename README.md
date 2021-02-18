# Aggregation Tap Decoder And Analyzer ##
Decoder of Aggregation Taps from header and analysis of data from the Aggregation Taps.

## How to compile the server and client in sandbox ##
Using your compiler of choice, for example clang++, simply run `clang++ -std=c++20 -pthread basicServer.cpp -o server` to compile the server, when in the directory with basicServer.cpp in it, and run `clang++ -std=c++20 -pthread basicClient.cpp -o client` to compile the client. To run them, first run the server and then run the client, you will need a second terminal to run the client. By default, the port used is 2099, however, you can change this by adding a different port number after `./server`, and do `./client localhost portNo` to change the port for the client, ensure that you give the client and server the same port. 
