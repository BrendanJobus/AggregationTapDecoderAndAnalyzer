#pragma once

#include <iostream>
#include <vector>

#include <chrono>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <dirent.h>

namespace headerStructure {
	constexpr int SIZE_ETHERNET{14};
	constexpr int ETHER_ADDR_LEN{6};
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN];
		u_char ether_shost[ETHER_ADDR_LEN];
		u_short ether_type;
	};

	// length in bytes of the arista types struct
	constexpr int ARISTA_TYPES_LENGTH{4};
	constexpr u_short taiCode{0x10};
	constexpr u_short sixtyFourBitCode{0x1};
	// Version is the TAI or UTC
	// TAI is 0010 and UTC is 0110
	// subType is 64 or 48 bit
	// 64 bit is 0001 and 48 bit is 
	struct sniff_arista_types {
		u_short subType;
		u_short version;
	};

	struct sniff_arista_times_64 {
		u_int seconds;
		u_int nanoseconds;
	};

	struct sniff_arista_times_48 {
		u_short seconds;
		u_int nanoseconds;
	};
};