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


// These are the headers we are definitely using right now
#include <pcap.h>
#include <dirent.h>
#include <unordered_map>
#include <chrono>

//for file shenanigans
#include <string>
#include <fstream>
#include <vector>
#include <utility> // std::pair
#include <stdexcept> // std::runtime_error
#include <sstream> // std::stringstream

namespace headerStructure {
	enum format_code {
		arista_code = 0xd28b,
		example_code = 0x9999,
	};

	constexpr int ETHER_ADDR_LEN{6};
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN];
		u_char ether_shost[ETHER_ADDR_LEN];
		u_short ether_type;
	};

	// Sizes of headers that are constant
	constexpr int ETHER_SIZE{14};
	constexpr int VIRTUAL_LAN_SIZE{4};
	constexpr int IP_SIZE{20};
	constexpr int UDP_SIZE{8};

	// information related to arista timestamp header format
	namespace arista {
		// Size of the packet and other position information
		constexpr int TOTAL_SIZE{14};
		constexpr int TYPES_POS{ETHER_SIZE};
		constexpr int TYPES_SIZE{4};
		constexpr int TIMES_POS{TYPES_POS + TYPES_SIZE};
		// Codes to identify timestamp formats
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

	// This is an example alternate format that will have a code that represents it
	// and an extract function in the PCAP_READER, this function will be called if the switch in
	// workOnPCAPs finds a packet with a this formats code, we will create pointers that will point to the data
	// at the top of PCAP_READER
	//
	// for this example, I will assume that the only differences between the arista format
	// and this format is that this one has its metadata header after the ip header and that the seconds
	// will come after the nanoseconds ontop of a varying identifying code
	namespace exampleVendor {
		constexpr int TOTAL_SIZE{14};
		constexpr int TYPES_POS{ETHER_SIZE + VIRTUAL_LAN_SIZE + IP_SIZE};
		constexpr int TYPES_SIZE{4};
		constexpr int TIMES_POS{TYPES_POS + TYPES_SIZE};
		constexpr u_short taiCode{0x10};
		constexpr u_short sixtyFourBitCode{0x1};

		struct sniff_types {
			u_short subType;
			u_short version;
		};

		struct sniff_times_64 {
			u_int nanoseconds;
			u_int seconds;
		};

		struct sniff_times_48 {
			u_int nanoseconds;
			u_short seconds;
		};
	}
};

class PCAP_READER {
	private:
		const headerStructure::sniff_ethernet *ethernet;
		const headerStructure::arista::sniff_types *aristaTypes;
		const headerStructure::arista::sniff_times_64 *aristaTime64;
		const headerStructure::arista::sniff_times_48 *aristaTime48;
		const headerStructure::exampleVendor::sniff_types *exTypes;
		const headerStructure::exampleVendor::sniff_times_64 *exTime64;
		const headerStructure::exampleVendor::sniff_times_48 *exTime48;

		int packetCount;

		int sec_adjust;
		double nanosec_adjust;

		u_short data_format;
		u_short timestampLength;
		u_short timeFormat;

		// output stream
		std::ofstream csv;

		// pointers to the new packet and new packet header
		const u_char *packet;
		struct pcap_pkthdr *header;

		// holds the size of the current packets propreitary header
		int vendorSize;

		// This is the pcap times
		u_int packetSeconds;
		u_int packetNanoseconds;

		// This is the converted metadata times
		u_long seconds;
		u_long nanoseconds;

		// This is the raw metadata times that are still the wrong way around
		u_int rawSeconds;
		u_int rawNanoseconds;

		// This is the previous metadata times
		u_long preSeconds;
		u_long preNanoseconds;

		const int TAI_UTC_OFFSET;

		int getTaiToUtcOffset();
		u_int taiToUtc(u_int);

		void extractTimeAristaFormat();
		void extractTimeExampleFormat();

		void timestampAnalysis();

		void initializeCSV();
		void addToCSV(u_int, u_int, u_int, u_int);

	public:
		PCAP_READER();

		void workOnPCAPs(pcap_t *);

		void destroy();
};
