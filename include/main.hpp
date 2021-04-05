#pragma once

#include <iostream>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


// These are the headers we are definitley using right now
#include <pcap.h>
#include <dirent.h>
#include <unordered_map>
#include <chrono>

namespace headerStructure {
	enum format_code {
		arista_code = 0xd28b,
		ipv4_code = 0x800
	};

	constexpr int ETHER_ADDR_LEN{6};
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN];
		u_char ether_shost[ETHER_ADDR_LEN];
		u_short ether_type;
	};

	// information related to vss timestamp header format
	namespace vss {
		
	}

	// information related to arista timestamp header format
	namespace arista {
		// length in bytes of the arista types struct
		constexpr int TYPES_POS{14};
		constexpr int TIMES_POS{18};
		constexpr u_short taiCode{0x10};
		constexpr u_short sixtyFourBitCode{0x1};

			// Version is the TAI or UTC
		// TAI is 0010 and UTC is 0110
		// subType is 64 or 48 bit
		// 64 bit is 0001 and 48 bit is 
		struct sniff_types {
			u_short subType;
			u_short version;
		};

		struct sniff_times_64 {
			u_int seconds;
			u_int nanoseconds;
		};

		struct sniff_times_48 {
			u_short seconds;
			u_int nanoseconds;
		};
	}
};

class PCAP_READER {
	private:
		const headerStructure::sniff_ethernet *ethernet;
		const headerStructure::arista::sniff_types *aristaTypes;
		const headerStructure::arista::sniff_times_64 *aristaTime64;
		const headerStructure::arista::sniff_times_48 *aristaTime48;

		int packetCount;

		u_short data_format;
		u_short timestampLength;
		u_short timeFormat;

		FILE *fp;

		const u_char *packet;

		struct pcap_pkthdr *header;

		const int TAI_UTC_OFFSET;

		int getTaiToUtcOffset();

		u_int taiToUtc(u_int);

		void extractTimeAristaFormat();

		void timestampAnalysis(u_int , u_int);

		void printPacketMetadata(const u_char *);

		void CSV();

	public:
		PCAP_READER();

		void workOnPCAPs(pcap_t *);

		void destroy();
};
