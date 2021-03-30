#include "../include/main.hpp"

// Put into a class primarily for increased readability and portability
class PCAP_Reader {
private:
	// each struct corresponds to a number of bits in the packets memory, to find out what each means, look at the structs
	const headerStructure::sniff_ethernet *ethernet;
	const headerStructure::sniff_arista_types *aristaTypes;
	const headerStructure::sniff_arista_times_64 *aristaTime64;
	const headerStructure::sniff_arista_times_48 *aristaTime48;

	int packetCount;

	// Opens a file to print to, this will be a csv file
	FILE *fp;

public:
	// This is the pointer that will hold the packet once we do pcap_next_ex
	const u_char *packet;

	// This will store the pcap header, which holds information pertinent to pcap
	struct pcap_pkthdr *header;

	PCAP_Reader(): packetCount{0}, fp{fopen("./out/result.txt", "w")}
	{
	}

	// does the actual work on the pcaps
	void workOnPCAP(pcap_t *file) {
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
		ethernet = (headerStructure::sniff_ethernet*)(packet);
		const u_short dataFormat{ntohs(ethernet->ether_type)};
		std::cout << std::hex << dataFormat << '\n';

		// switching depending on the type of packet we have received (e.g. arista format)
		switch(dataFormat) {
			case 0xd28b:
				aristaFormat();
				break;
			default:
				// either output an unkown format error, or just ignore, maybe do a warning instead of an error
				break;
		}

		// NOTE: the ntohl and ntohs is to convert from the standard network order into your machines order of bits, for efficiency of typing, 
		// I have just run the function on the data, however, this actual creates a new variable each time implicitly, and then passes it to cout
		// for production, we should have a pointer that actually holds this data, that we predefine and always use, so that we are not wasting memory.

		printf("\n");
		fprintf(fp, "\n");
	}

	void aristaFormat() {
		// putting data into the aristaTypes variable, the packet + SIZE_ETHERNET means start at the memory address of packet + the length of the ethernet
		// header
		aristaTypes = (headerStructure::sniff_arista_types*)(packet + headerStructure::SIZE_ETHERNET);
		std::cout << "subType: " << ntohs(aristaTypes->subType) << " Version: " << ntohs(aristaTypes->version) << '\n';

		// if the sub type is 0x1, then the timestamp is in 64 bits, otherwise its in 48 bits
		if (ntohs(aristaTypes->subType) == 0x1) {
			// put the data at packet + SIZE_ETHERNET + ARISTA_TYPES_LENGTH into aristaTime64
			aristaTime64 = (headerStructure::sniff_arista_times_64*)(packet + headerStructure::SIZE_ETHERNET + headerStructure::ARISTA_TYPES_LENGTH);
			std::cout << std::dec << "seconds: " << ntohl(aristaTime64->seconds) << " nanoseconds: " << ntohl(aristaTime64->nanoseconds) << '\n';
		} else {
			aristaTime48 = (headerStructure::sniff_arista_times_48*)(packet + headerStructure::SIZE_ETHERNET + headerStructure::ARISTA_TYPES_LENGTH);
			std::cout << std::dec << "seconds: " << ntohl(aristaTime48->seconds) << " nanoseconds: " << ntohl(aristaTime48->nanoseconds) << '\n';
		}
	}

	// here we will do the basic analysis of the timestamps
	void timestampAnalysis() {

	}

	// pre-emptive creation of function to deal with csv things
	void CSV() {

	}

	// deallocates memory after we have finished
	void destroy() {
		fclose(fp);
	}
};

int main() {   
	// This is the buffer that pcap uses to output the error into
	char errbuff[PCAP_ERRBUF_SIZE];

	// Opening the pcap file in memory, pcap_t will point to the start of the file
	pcap_t *file = pcap_open_offline("./data/pCaps1.pcap", errbuff);

	PCAP_Reader r{};

	// pcap_next_ex returns a 1 so long as every thing is ok, so keep looping until its not 1
	while(pcap_next_ex(file, &r.header, &r.packet) >= 0) {
		r.workOnPCAP(file);
	}

	return 0;
}