#include "../include/main.hpp"

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

// This corresponds to 
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

// length in bytes of the arista types struct
constexpr int ARISTA_TYPES_LENGTH{4};
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




int main() {   
	// This is the buffer that pcap uses to output the error into
	char errbuff[PCAP_ERRBUF_SIZE];

	// Opening the pcap file in memory, pcap_t will point to the start of the file
	pcap_t *handler = pcap_open_offline("./data/pCaps1.pcap", errbuff);

	// This will store the pcap header, which holds information pertinent to pcap
	struct pcap_pkthdr *header;

	// This is the pointer that will hold the packet once we do pcap_next_ex
	const u_char *packet;
	int packetCount = 0;

	// Opens a file to print to, this will be a csv file
	FILE *fp = fopen("./out/result.txt", "w");

	// each struct corresponds to a number of bits in the packets memory, to find out what each means, look at the structs
	const struct sniff_ethernet *ethernet;
	const struct sniff_arista_types *aristaTypes;
	const struct sniff_arista_times_64 *aristaTime64;
	const struct sniff_arista_times_48 *aristaTime48;

	// pcap_next_ex returns a 1 so long as every thing is ok, so keep looping until its not 1
	while(pcap_next_ex(handler, &header, &packet) >= 0) {
		// printing the packet count
		printf("Packet # %i\n", ++packetCount);
		fprintf(fp, "Packet # %i\n", packetCount);

		// printing the length of the data
		printf("Packet size: %d bytes\n", header->len);
		fprintf(fp, "Packet size: %d\n", header->len);

		// making sure the captured length is the same as the data length
		if(header->len != header->caplen)
			printf("Warning! Capture size different than packet size: %d bytes\n", header->len);

		// printing out time that we captured the data
		printf("Epoch Time: %ld:%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
		fprintf(fp, "Epoch Time: %ld:%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);

		// putting data into the ethernet variable
		ethernet = (struct sniff_ethernet*)(packet);
		std::cout << std::hex << ntohs(ethernet->ether_type) << '\n';

		// putting data into the aristaTypes variable, the packet + SIZE_ETHERNET means start at the memory address of packet + the length of the ethernet
		// header
		aristaTypes = (struct sniff_arista_types*)(packet + SIZE_ETHERNET);
		std::cout << "subType: " << ntohs(aristaTypes->subType) << " Version: " << ntohs(aristaTypes->version) << '\n';

		// if the sub type is 0x1, then the timestamp is in 64 bits, otherwise its in 48 bits
		if (ntohs(aristaTypes->subType) == 0x1) {
			// put the data at packet + SIZE_ETHERNET + ARISTA_TYPES_LENGTH into aristaTime64
			aristaTime64 = (struct sniff_arista_times_64*)(packet + SIZE_ETHERNET + ARISTA_TYPES_LENGTH);
			std::cout << std::dec << "seconds: " << ntohl(aristaTime64->seconds) << " nanoseconds: " << ntohl(aristaTime64->nanoseconds) << '\n';
		} else {
			aristaTime48 = (struct sniff_arista_times_48*)(packet + SIZE_ETHERNET + ARISTA_TYPES_LENGTH);
			std::cout << std::dec << "seconds: " << ntohl(aristaTime48->seconds) << " nanoseconds: " << ntohl(aristaTime48->nanoseconds) << '\n';
		}


		// NOTE: the ntohl and ntohs is to convert from the standard network order into your machines order of bits, for efficiency of typing, 
		// I have just run the function on the data, however, this actual creates a new variable each time implicitly, and then passes it to cout
		// for production, we should have a pointer that actually holds this data, that we predefine and always use, so that we are not wasting memory.

		printf("\n");
		fprintf(fp, "\n");
	}

	fclose(fp);
	return 0;
}

void capture() {
	
}