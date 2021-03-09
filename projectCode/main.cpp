#include "main.h"

int main()
{   
	vector<packet> packets = readPacketsFromFile();
	for (int i = 0; i < packets.size(); i++)
	{
		printPacketData(packets[i]);
	}
}

vector<packet> readPacketsFromFile()
{
	vector<packet> packets;






	//sample output until libPcap configuration complete
	packet newPacket;
	for (int i = 0; i < 10; i++)
	{
		newPacket.timestampVersion = i;
		newPacket.seconds = i;
		newPacket.nanoseconds = i;
		packets.push_back(newPacket);
	}

	return packets;
}

void printPacketData(packet inputPacket)
{
	printf("Version: %d Seconds: %d Nanoseconds: %d\n", inputPacket.timestampVersion, inputPacket.seconds, inputPacket.nanoseconds);
}