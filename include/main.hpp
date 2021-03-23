#pragma once

#include <pcap.h> 
#include <iostream>

typedef struct packet
{
	short int timestampVersion;
	int seconds;
	int nanoseconds;
} packet;

void analysePacketsFromFile(const char * filePath);
void printPacketData(packet inputPacket);