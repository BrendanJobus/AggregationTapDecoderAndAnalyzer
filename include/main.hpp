#pragma once

#include <iostream>
#include <vector>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <pcap.h>

namespace packet {
	typedef struct packet
	{
		short int timestampVersion;
		int seconds;
		int nanoseconds;
	} packet;
};

std::vector<packet::packet> readPacketsFromFile();
void printPacketData(packet::packet inputPacket);