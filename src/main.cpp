#include "../include/main.hpp"

// Put into a class primarily for increased readability and portability
class PCAP_Reader {
	private:
		// each struct corresponds to a number of bits in the packets memory, to find out what each means, look at the structs
		const headerStructure::sniff_ethernet *ethernet;
		const headerStructure::arista::sniff_types *aristaTypes;
		const headerStructure::arista::sniff_times_64 *aristaTime64;
		const headerStructure::arista::sniff_times_48 *aristaTime48;

		int packetCount;

		u_short dataFormat;
		u_short timestampLength;
		u_short timeFormat;

		// Opens a file to print to, this will be a csv file
		FILE *fp;

		// This is the pointer that will hold the packet once we do pcap_next_ex
		const u_char *packet;

		// This will store the pcap header, which holds information pertinent to pcap
		struct pcap_pkthdr *header;

		u_long seconds;
		u_long nanoseconds;

		u_long previousSeconds;
		u_long previousNanoseconds;

		//Offset between TAI and UTC
		const int TAI_UTC_OFFSET = getTaiToUtcOffset();

		//Get offset between TAI and UTC
		//@author Cillian Fogarty
		int getTaiToUtcOffset() {
			//Get current TAI Time
			u_long timeTAI = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() + 37;
			//Get current UTC Time
			u_long timeUTC = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			return timeUTC - timeTAI;
		}

		//Convert TAI to UTC
		//@author Cillian Fogarty
		u_long taiToUtc(u_long taiTime) {
			return taiTime + TAI_UTC_OFFSET;
		}

///////////// These functions extract the agg tap times from the packets, each one will work for its corresponding packet format /////////////
		void extractTimeAristaFormat() {
			// putting data into the aristaTypes variable
			aristaTypes = (headerStructure::arista::sniff_types*)(packet + headerStructure::arista::TYPES_POS);

			timestampLength = ntohs(aristaTypes->subType);
			timeFormat  = ntohs(aristaTypes->version);

			previousSeconds = seconds;
			previousNanoseconds = nanoseconds;

			if (timestampLength == headerStructure::arista::sixtyFourBitCode) {
				aristaTime64 = (headerStructure::arista::sniff_times_64*)(packet + headerStructure::arista::TIMES_POS);
								
				seconds = ntohl(aristaTime64->seconds);
				nanoseconds = ntohl(aristaTime64->nanoseconds);

				if(timeFormat == headerStructure::arista::taiCode) {
					printf("Converted Timestamp from TAI to UTC\n");
					fprintf(fp, "Converted Timestamp from TAI to UTC\n");
					seconds = taiToUtc(seconds);
				}
			} 
			else {
				aristaTime48 = (headerStructure::arista::sniff_times_48*)(packet + headerStructure::arista::TIMES_POS);

				seconds = ntohl(aristaTime48->seconds);
				nanoseconds = ntohl(aristaTime48->nanoseconds);

				if(timeFormat == headerStructure::arista::taiCode) {
					printf("Converted Timestamp from TAI to UTC\n");
					fprintf(fp, "Converted Timestamp from TAI to UTC\n");
					seconds = taiToUtc(seconds);
				}
			}
		}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// timestamp analysis
		//@author Cillian Fogarty
		void timestampAnalysis(u_int epochSeconds, u_int epochNanoseconds) {

			//Time Packet was captured at (UTC)
			printf("UTC Timestamp: %ld:%ld seconds\n", seconds, nanoseconds);
			fprintf(fp, "UTC Timestamp: %ld:%ld seconds\n", seconds, nanoseconds);

			// get offset between current and previous packet
			long secondsFromPreviousPacket = seconds - previousSeconds;
			long nanosecondsFromPreviousPacket = 0;
			int packetsInOrder = 1;
			//ensures there has been a previous packet
			if (previousSeconds != 0 && previousNanoseconds != 0) {
				if (secondsFromPreviousPacket > 0  && nanoseconds < previousNanoseconds) {
					// add 1 second in nanoseconds to current nanoseconds
					nanosecondsFromPreviousPacket = (1000000000 + nanoseconds) - previousNanoseconds;
				}
				else if (secondsFromPreviousPacket < 0 && nanoseconds > previousNanoseconds) {
					// add 1 second in nanoseconds to previous nanoseconds
					nanosecondsFromPreviousPacket = nanoseconds - (1000000000 + previousNanoseconds);
					packetsInOrder = 0;
				}
				else
				{
					nanosecondsFromPreviousPacket = nanoseconds - previousNanoseconds;
				}
			}
			else {
				secondsFromPreviousPacket = 0;
				nanosecondsFromPreviousPacket = 0;
			}
			printf("Offset from previous packet: %ld:%ld seconds\n", secondsFromPreviousPacket, nanosecondsFromPreviousPacket);
			fprintf(fp, "Offset from previous packet: %ld:%ld seconds\n", secondsFromPreviousPacket, nanosecondsFromPreviousPacket);

			// check packets arrived in the correct order
			if (packetsInOrder == 1) {
				printf("Packets are in order\n");
				fprintf(fp, "Packets are in order\n");
			}
			else {
				printf("Packets are not in order\n");
				fprintf(fp, "Packets are not in order\n");
			}

			// get offset between current packet and Aggregation Tap
			long secondsFromAggregationTap = seconds - epochSeconds;
			long nanosecondsFromAggregationTap = 0;
			int timesConsistent = 1;
			if (secondsFromAggregationTap > 0 && nanoseconds < epochNanoseconds) {
				// add 1 second in nanoseconds to current nanoseconds
				nanosecondsFromAggregationTap = (1000000000 + nanoseconds) - epochNanoseconds;
			}
			else if (secondsFromPreviousPacket < 0 && nanoseconds > epochNanoseconds) {
				// add 1 second in nanoseconds to epoch nanoseconds
				nanosecondsFromAggregationTap = nanoseconds - (1000000000 + epochNanoseconds);
				timesConsistent = 0;
			}
			else {
				nanosecondsFromAggregationTap = nanoseconds - epochNanoseconds;
			}
			printf("Offset from Aggregation Tap: %ld:%ld seconds\n", secondsFromAggregationTap, nanosecondsFromAggregationTap);
			fprintf(fp, "Offset from Aggregation Tap: %ld:%ld seconds\n", secondsFromAggregationTap, nanosecondsFromAggregationTap);

			// check packet time and Aggregation Tap time consistent
			if (timesConsistent == 1) {
				printf("Packet time and Aggregation Tap time are consistent\n");
				fprintf(fp, "Packet time and Aggregation Tap time are consistent\n");
			}
			else {
				printf("Packet time and Aggregation Tap time are not consistent\n");
				fprintf(fp, "Packet time and Aggregation Tap time are not consistent\n");
			}
		}

		// extract and print the packet metadata
		//@author Cillian Fogarty
		void printPacketMetadata() {

			// extract the length of the ip_data from the file
			int ethernet_header_length = 32; //constant length in bytes
			const u_char *ip_header = packet + ethernet_header_length;
			u_int ip_header_length = (((*ip_header) & 0x0F) * 4);

			// extract the length of the udp_data from the file
			int length_udp_source = 2;
			const u_char *udp_header = packet + ethernet_header_length + ip_header_length + (length_udp_source * 2);
			const u_char *udp_header2 = udp_header + 1;
			int udp_header_length = ((*udp_header) << 8) + (*udp_header2);

			// extract the length of the metadata from the file
			int length_udp_info = (length_udp_source * 4); //num of bytes taken up to represent the length of UDP, the sources and checksum
			const u_char *metadata_header = packet + ethernet_header_length + ip_header_length + length_udp_info;
			int metadata_length = udp_header_length - length_udp_info;

			// extract the metadata from the file and output it
			printf("Metadata:\n");
			fprintf(fp, "Metadata:\n");
			if (metadata_length > 0) {
		        const u_char *temp_pointer = metadata_header;
		        int byte_count = 0;
		        while (byte_count++ < metadata_length) {
		            printf("%X", *temp_pointer);
		            fprintf(fp, "%X", *temp_pointer);
		            temp_pointer++;
		        }
		        printf("\n");
		        fprintf(fp, "\n");
		    }
		}


		// pre-emptive creation of function to deal with csv things
		void CSV() {

		}



	public:
		PCAP_Reader(): packetCount{0}, dataFormat{0}, fp{fopen("./out/result.txt", "w")}, TAI_UTC_OFFSET{getTaiToUtcOffset()}
		{
		}

		// takes in a pcap file, outputs certain data about the pcap itself, then figures out what format the packet is in, and sends it to the corresponding function
		void workOnPCAPs(pcap_t *file) {
			// pcap_next_ex returns a 1 so long as every thing is ok, so keep looping until its not 1
			while(pcap_next_ex(file, &header, &packet) >= 0) {
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
				std::cout << "Data Format: " << std::hex << dataFormat << '\n';

				// extract the metadata and output it
				printPacketMetadata();

				// switching depending on the type of packet we have received (e.g. arista format)
				switch(dataFormat) {
					case headerStructure::arista_code:
						extractTimeAristaFormat();
						break;
					default:
						// either output an unkown format error, or just ignore, maybe do a warning instead of an error
						break;
				}

				// run analysis on the timestamps to flag errors
				timestampAnalysis(header->ts.tv_sec, header->ts.tv_usec);

				printf("\n");
				fprintf(fp, "\n");
			}
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

			r.workOnPCAPs(file);
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
					r.workOnPCAPs(file);
				} 
			}
			closedir(dir);
		}
	}

	r.destroy();
	return 0;
}
