#pragma once

// These are the headers we are definitley using right now
#include <pcap.h>
#include <dirent.h>
#include <unordered_map>
#include <chrono>
#include <iostream>

//for file shenanigans
#include <string>
#include <fstream>
#include <vector>
#include <utility> // std::pair
#include <stdexcept> // std::runtime_error
#include <sstream> // std::stringstream

namespace headerStructure {
	enum format_code {
		arista7280_code = 0xd28b,
		arista7130_code = 0x0800, // actually the IPv4 code
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

	// information related to arista7280 timestamp header format
	namespace arista7280 {
		// Size of the packet and other position information
		constexpr int SIZE_WO_TIMESTAMP{10};
		constexpr int TYPES_POS{ETHER_SIZE};
		constexpr int TYPES_SIZE{4};
		constexpr int TIMES_POS{TYPES_POS + TYPES_SIZE};
		// Codes to identify timestamp formats
		constexpr u_short taiCode{0x10};
		constexpr u_short sixtyFourBitCode{0x1};
		constexpr int SIZE_OF_SECONDS{4};
		constexpr int SIZE_OF_NANOSECONDS_64{4};
		constexpr int SIZE_OF_NANOSECONDS_48{3};

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

	namespace arista7130 {
		constexpr int SIZE_OF_FCS{4};
		constexpr int TIMES_POS{ETHER_SIZE + SIZE_OF_FCS};
		constexpr int SIZE_OF_SECONDS{4};
		constexpr int SIZE_OF_NANOSECONDS{4};

		struct sniff_times_64 {
			u_int seconds;
			u_int nanoseconds;
		};
	}


	// This is an example alternate format that will have a code that represents it
	// and an extract function in the PCAP_READER, this function will be called if the switch in
	// workOnPCAPs finds a packet with a this formats code, we will create pointers that will point to the data
	// at the top of PCAP_READER
	//
	// for this example, I will assume that the only differences between the arista7280 format
	// and this format is that this one has its metadata header after the ip header and that the seconds
	// will come after the nanoseconds ontop of a varying identifying code
	namespace exampleVendor {
		constexpr int SIZE_WO_TIMESTAMP{10};
		constexpr int TYPES_POS{ETHER_SIZE + VIRTUAL_LAN_SIZE + IP_SIZE};
		constexpr int TYPES_SIZE{4};
		constexpr int TIMES_POS{TYPES_POS + TYPES_SIZE};
		constexpr u_short taiCode{0x10};
		constexpr u_short sixtyFourBitCode{0x1};
		constexpr int SIZE_OF_SECONDS{4};
		constexpr int SIZE_OF_NANOSECONDS_64{4};
		constexpr int SIZE_OF_NANOSECONDS_48{3};

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
		const headerStructure::arista7280::sniff_types *arista7280_types;
		const headerStructure::arista7280::sniff_times_64 *arista7280_time64;
		const headerStructure::arista7280::sniff_times_48 *arista7280_time48;
		const headerStructure::exampleVendor::sniff_types *exTypes;
		const headerStructure::exampleVendor::sniff_times_64 *exTime64;
		const headerStructure::exampleVendor::sniff_times_48 *exTime48;
		const headerStructure::arista7130::sniff_times_64 *arista7130_time64;

		int packetCount;
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
		int payloadSize;

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

		void extractTimeArista7280Format();
		void extractTimeArista7130Format();
		void extractTimeExampleFormat();

		void timestampAnalysis();
		void getPacketAndPrintPayload();

		void initializeCSV();
		void addToCSV(long, long, long, long);

	public:
		PCAP_READER();
		void workOnPCAPs(pcap_t *);
		void setOutputFile(std::string);
		void destroy();
};

const std::string helpString = "Agg tap decoder and analyzer using libpcap designed "
							   "for Pico Quantitative Trading LLC.\n\nBasic operation: "
							   "takes in pcap files that contain agg tap timestamps, "
							   "decodes and analyzes their agg tap content\n\nCommands:\n"
							   "    --help / -h: print help\n    -s / -ns: adjusts the agg "
							   "tap timestamp by x seconds or x nanoseconds\n    -ps / -pns: "
							   "adjusts the pcap timestamp by x seconds or x nanoseconds\n"
							   "\nDesigned By:\n  Alannah Henry    Brendan Jobus\n  Cillian Fogarty  "
							   "Darren Aragones\n  Finn Jaksland    Owen Gallagher\n";