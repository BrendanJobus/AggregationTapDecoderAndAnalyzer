# Aggregation Tap Decoder And Analyzer ##
Decoder of Aggregation Taps from header and analysis of data from the Aggregation Taps.

## How to compile the server and client in sandbox ##
Using your compiler of choice, for example clang++, simply compile the client and server files with `clang++ -c -std=c++17 -pthread filename.cpp` and do the same with the networking file excluding the pthread option, then compile the server and client object file each together with the networking object file like so, `clang++ -pthread basicServer.o basicNetworking.o -o server`, and do the same with the client. To then run the executables, simply running ./filename, and the default values will be run.