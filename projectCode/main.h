#include <iostream>
#include <vector>

using namespace std;

typedef struct packet
{
	short int timestampVersion;
	int seconds;
	int nanoseconds;
} packet;

vector<packet> readPacketsFromFile();
void printPacketData(packet inputPacket);