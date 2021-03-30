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

	u_short dataFormat;
	u_short timestampLength;
	u_short timeFormat;

	// Opens a file to print to, this will be a csv file
	FILE *fp;

	//Get offset between TAI and UTC
	long getTaiToUtcOffset()
	{
	    //Get current TAI Time
	    u_long timeTAI = 0;
	    //Get current UTC Time
	    u_long timeUTC = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	    //temporary test value
	    return -37;
	    return timeTAI - timeUTC;
	}

	//Offset between TAI and UTC
	const int TAI_UTC_OFFSET = getTaiToUtcOffset();

	//Convert TAI to UTC
	u_int taiToUtc(u_int taiTime)
	{
	    return taiTime + TAI_UTC_OFFSET;
	}

	void aristaFormat() {
		// putting data into the aristaTypes variable
		aristaTypes = (headerStructure::sniff_arista_types*)(packet + headerStructure::SIZE_ETHERNET);
		timestampLength = ntohs(aristaTypes->subType);
		timeFormat  = ntohs(aristaTypes->version);
		std::cout << "subType: " << timestampLength << " Version: " << timeFormat << '\n';

		// 0x1 corresponds to 64 bit timestamp
		if (timestampLength == headerStructure::sixtyFourBitCode) {
			aristaTime64 = (headerStructure::sniff_arista_times_64*)(packet + headerStructure::SIZE_ETHERNET + headerStructure::ARISTA_TYPES_LENGTH);
			std::cout << std::dec << "seconds: " << ntohl(aristaTime64->seconds) << " nanoseconds: " << ntohl(aristaTime64->nanoseconds) << '\n';
			if(timeFormat == headerStructure::taiCode) {
				std::cout << "Convert TAI to UTC\n";
				std::cout << std::dec << "UTCseconds: " << taiToUtc(ntohl(aristaTime64->seconds)) << " nanoseconds: " << ntohl(aristaTime64->nanoseconds) << '\n';
			}
		} else {
			aristaTime48 = (headerStructure::sniff_arista_times_48*)(packet + headerStructure::SIZE_ETHERNET + headerStructure::ARISTA_TYPES_LENGTH);
			std::cout << std::dec << "seconds: " << ntohl(aristaTime48->seconds) << " nanoseconds: " << ntohl(aristaTime48->nanoseconds) << '\n';
			if(timeFormat == headerStructure::taiCode) {
				std::cout << "Convert TAI to UTC\n";
				std::cout << std::dec << "UTCseconds: " << taiToUtc(ntohl(aristaTime48->seconds)) << " nanoseconds: " << ntohl(aristaTime48->nanoseconds) << '\n';
			}
		}
	}

	// here we will do the basic analysis of the timestamps
	void timestampAnalysis() {

	}

	// pre-emptive creation of function to deal with csv things
	void CSV() {

	}

public:
	// This is the pointer that will hold the packet once we do pcap_next_ex
	const u_char *packet;

	// This will store the pcap header, which holds information pertinent to pcap
	struct pcap_pkthdr *header;

	PCAP_Reader(): packetCount{0}, dataFormat{0}, fp{fopen("./out/result.txt", "w")}
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
		dataFormat = ntohs(ethernet->ether_type);
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

		printf("\n");
		fprintf(fp, "\n");
	}

	// deallocates memory after we have finished
	void destroy() {
		fclose(fp);
	}
};

int main(int argc, char **argv) {   
	PCAP_Reader r{};

	// This is the buffer that pcap uses to output the error into
	char errbuff[PCAP_ERRBUF_SIZE];

	if(argc > 1) { // if arguments are specified, run those files
		for(int i{1}; i < argc; i++){
			std::cout << argv[i] << '\n';
			// Opening the pcap file in memory, pcap_t will point to the start of the file
			pcap_t *file = pcap_open_offline(argv[i], errbuff);

			// pcap_next_ex returns a 1 so long as every thing is ok, so keep looping until its not 1
			while(pcap_next_ex(file, &r.header, &r.packet) >= 0) {
				r.workOnPCAP(file);
			}
		}
	} else {
		DIR *dir;
		struct dirent *diread;
		std::string directory = "./data/";

		if ((dir = opendir(directory.c_str())) != nullptr) {
			while ((diread = readdir(dir)) != nullptr) {
				std::string str(diread->d_name);
				str.insert(0, directory);
				if(str.find(".pcap") != std::string::npos) {
					pcap_t *file = pcap_open_offline(str.c_str(), errbuff);
					while(pcap_next_ex(file, &r.header, &r.packet) >= 0) {
						r.workOnPCAP(file);
					}
				} 
			}
			closedir(dir);
		}
	}

	r.destroy();
	return 0;
}