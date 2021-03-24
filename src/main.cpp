#include "../include/main.hpp"

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

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
	char errbuff[PCAP_ERRBUF_SIZE];

	pcap_t *handler = pcap_open_offline("./data/pCaps1.pcap", errbuff);

	struct pcap_pkthdr *header;

	const u_char *packet;
	int packetCount = 0;

	FILE *fp = fopen("result.txt", "w");

	const struct sniff_ethernet *ethernet;
	const struct sniff_arista_types *aristaTypes;
	const struct sniff_arista_times_64 *aristaTime64;
	const struct sniff_arista_times_48 *aristaTime48;

	while(pcap_next_ex(handler, &header, &packet) >= 0) {
		printf("Packet # %i\n", ++packetCount);
		fprintf(fp, "Packet # %i\n", packetCount);

		printf("Packet size: %d bytes\n", header->len);
		fprintf(fp, "Packet size: %d\n", header->len);

		if(header->len != header->caplen)
			printf("Warning! Capture size different than packet size: %d bytes\n", header->len);

		printf("Epoch Time: %ld:%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
		fprintf(fp, "Epoch Time: %ld:%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);

		ethernet = (struct sniff_ethernet*)(packet);
		std::cout << std::hex << ntohs(ethernet->ether_type) << '\n';
		aristaTypes = (struct sniff_arista_types*)(packet + SIZE_ETHERNET);
		std::cout << "subType: " << ntohs(aristaTypes->subType) << " Version: " << ntohs(aristaTypes->version) << '\n';
		if (ntohs(aristaTypes->subType) == 0x1) {
			aristaTime64 = (struct sniff_arista_times_64*)(packet + SIZE_ETHERNET + ARISTA_TYPES_LENGTH);
			std::cout << std::dec << "seconds: " << ntohl(aristaTime64->seconds) << " nanoseconds: " << ntohl(aristaTime64->nanoseconds) << '\n';
		} else {
			aristaTime48 = (struct sniff_arista_times_48*)(packet + SIZE_ETHERNET + ARISTA_TYPES_LENGTH);
			std::cout << std::dec << "seconds: " << ntohl(aristaTime48->seconds) << " nanoseconds: " << ntohl(aristaTime48->nanoseconds) << '\n';
		}

		printf("\n");
		fprintf(fp, "\n");
	}

	fclose(fp);
	return 0;
}