#pragma once

#include <iostream>
#include <vector>

typedef struct packet
{
	short int timestampVersion;
	int seconds;
	int nanoseconds;
} packet;

std::vector<packet> readPacketsFromFile();
void printPacketData(packet inputPacket);