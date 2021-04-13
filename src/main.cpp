#include "../include/main.hpp"

// Put into a class primarily for increased readability and portability
class PCAP_Reader {
	private:
		enum error_codes {
			packet_before_aggTap = 0xA,
			aggTap_behind_previous = 0xA0,
		};

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

		int sec_adjust;
		int nanosec_adjust;

		std::vector<std::string> adjustments;

		//Offset between TAI and UTC
		const u_int TAI_UTC_OFFSET;

		//Get offset between TAI and UTC
		u_int getTaiToUtcOffset() {
			//Get current TAI Time (to be completed)
			u_long timeTAI = 0;
			//Get current UTC Time
			u_long timeUTC = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			//temporary test value
			return -37;
			return timeTAI - timeUTC;
		}

		//Convert TAI to UTC
		u_long taiToUtc(u_long taiTime) {
			return taiTime + TAI_UTC_OFFSET;
		}

///////////// These functions extract the agg tap times from the packets, each one will work for its corresponding packet format /////////////
		void extractTimeAristaFormat() {
			// putting data into the aristaTypes variable
			aristaTypes = (headerStructure::arista::sniff_types*)(packet + headerStructure::arista::TYPES_POS);

			timestampLength = ntohs(aristaTypes->subType);
			timeFormat  = ntohs(aristaTypes->version);

			if (timestampLength == headerStructure::arista::sixtyFourBitCode) {
				aristaTime64 = (headerStructure::arista::sniff_times_64*)(packet + headerStructure::arista::TIMES_POS);
								
				seconds = ntohl(aristaTime64->seconds);
				nanoseconds = ntohl(aristaTime64->seconds);

				if(timeFormat == headerStructure::arista::taiCode) {
					std::cout << "Convert TAI to UTC\n";
					seconds = taiToUtc(seconds);
				}
			} 
			else {
				aristaTime48 = (headerStructure::arista::sniff_times_48*)(packet + headerStructure::arista::TIMES_POS);

				seconds = ntohl(aristaTime48->seconds);
				nanoseconds = ntohl(aristaTime48->nanoseconds);

				if(timeFormat == headerStructure::arista::taiCode) {
					std::cout << "Convert TAI to UTC\n";
					seconds = taiToUtc(seconds);
				}
			}
		}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		long errorCode;
		// timestamp analysis
		//@author Cillian Fogarty
		void timestampAnalysis() {
			errorCode = 0;
			//Time Packet was captured at (UTC)
			printf("UTC Timestamp: %ld:%ld seconds\n", seconds, nanoseconds);

			printf("Raw Timestamp: %x:%x\n", rawSeconds, rawNanoseconds);

			// get offset between current and previous packet
			long secondDelta = seconds - preSeconds;
			long nanosecondDelta = 0;
			bool arePacketsInOrder = true;

			//ensures there has been a previous packet
			if (preSeconds != 0 && preNanoseconds != 0) {
				// case: the seconds are ahead, but the nanoseconds are behind
				if (secondDelta > 0  && nanoseconds < preNanoseconds) {
					// add 1 second in nanoseconds to current nanoseconds
					nanosecondDelta = (1000000000 + nanoseconds) - preNanoseconds;
					secondDelta -= 1;
				}
				// case: the seconds are behind, but the nanoseconds are ahead
				else if (secondDelta < 0 && nanoseconds > preNanoseconds) {
					// add 1 second in nanoseconds to previous nanoseconds
					nanosecondDelta = nanoseconds - (1000000000 + preNanoseconds);
					secondDelta += 1;
					arePacketsInOrder = false;
					errorCode = aggTap_behind_previous;
				}
				// case: both are behind
				else if (secondDelta < 0 && nanoseconds < preNanoseconds) {
					nanosecondDelta = nanoseconds - preNanoseconds;
					arePacketsInOrder = false;
					errorCode = aggTap_behind_previous;
				}
				// case: both are ahead
				else {
					nanosecondDelta = nanoseconds - preNanoseconds;
				}
			}
			else {
				secondDelta = 0;
				nanosecondDelta = 0;
			}

///////////// makes no sense why the ag tap is greater that the pcap time
///////////// should be the other way around

			// get offset between current packet and Aggregation Tap
			long aggTapArrivalDelta_s = packetSeconds - seconds;
			long aggTapArrivalDelta_us = 0;
			bool areTimesConsistent = true;
			// case: the seconds are ahead, but the nanoseconds are behind
			if (aggTapArrivalDelta_s > 0 && packetNanoseconds < nanoseconds) {
				// add 1 second in nanoseconds to current nanoseconds
				aggTapArrivalDelta_us = (1000000000 + packetNanoseconds) - nanoseconds;
				aggTapArrivalDelta_s -= 1;
			}
			// case: the seconds are behind, but the nanoseconds are ahead
			else if (aggTapArrivalDelta_s <= 0 && packetNanoseconds > nanoseconds) {
				// add 1 second in nanoseconds to epoch nanoseconds
				aggTapArrivalDelta_us = packetNanoseconds - (1000000000 + nanoseconds);
				aggTapArrivalDelta_s += 1;
				areTimesConsistent = false;
				errorCode |= packet_before_aggTap;
			} 
			// case: both are behind
			else if (aggTapArrivalDelta_s <=0 && packetNanoseconds < nanoseconds) {
				aggTapArrivalDelta_us = packetNanoseconds - nanoseconds;
				areTimesConsistent = false;
				errorCode |= packet_before_aggTap;
			}
			// case: both are ahead
			else {
				aggTapArrivalDelta_us = packetNanoseconds - nanoseconds;
			}

//////////////////////// printing
			addToCSV(secondDelta, nanosecondDelta, aggTapArrivalDelta_s, aggTapArrivalDelta_us);

			printf("Offset from previous packet: %ld:%ld seconds\n", secondDelta, nanosecondDelta);

			// check packets arrived in the correct order
			if (arePacketsInOrder == true) {
				printf("Packets are in order\n");
			} else {
				printf("Packets are not in order\n");
			}

			printf("Offset from Aggregation Tap: %ld:%ld seconds\n", aggTapArrivalDelta_s, aggTapArrivalDelta_us);

			// check packet time and Aggregation Tap time consistent
			if (areTimesConsistent == true) {
				printf("Packet time and Aggregation Tap time are consistent\n");
			} else {
				printf("Packet time and Aggregation Tap time are not consistent\n");
			}
		}

		// extract and print the packet metadata
		//@author Cillian Fogarty
		void getPacketAndPrintPayload() {

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
			printf("Payload:\n");
			if (metadata_length > 0) {
		        const u_char *temp_pointer = metadata_header;
		        int byte_count = 0;
		        char payload[4];
		        while (byte_count++ < metadata_length) {
					sprintf(payload, "%02X ", *temp_pointer);
					printf("%s", payload);
					csv << payload;
		            temp_pointer++;
		        }
		        printf("\n");
		    }
		}

		// output the first row as to display the what is in each column
		void initializeCSV() {
			csv << "Packet Timestamp, Raw Timestamp Metadata, Converted Timestamp Metadata, ";
			csv << "Previous Packet Offset, Agg Tap and Packet Delta, Error Code, ";
			csv << "Payload\n";
		}

		// outputing the data to the csv
		void addToCSV(long interPacketOffset_s, long interPacketOffset_us, long aggTapArrivalDelta_s, long aggTapArrivalDelta_us) {
			csv << packetSeconds << ":" << packetNanoseconds << ", " << std::hex << rawSeconds << ":" << rawNanoseconds << std::dec << ", " << seconds << ":" << nanoseconds <<  ", ";
			csv << interPacketOffset_s << ":" << interPacketOffset_us << ", " << aggTapArrivalDelta_s << ":" << aggTapArrivalDelta_us << ", 0x" << std::hex << errorCode << std::dec <<  ", ";

			// print payload
			getPacketAndPrintPayload();

			csv << "\n";
		}

		
		// takes in a the filename of the pcap input file and sets the csv output file to be a .csv file with the same name as the input file but in the ./out/ folder
		void setOutputFile(std::string inputFilename) {
			std::string outputFile;
			outputFile = inputFilename.substr(inputFilename.rfind("/") + 1);
			outputFile.erase(outputFile.rfind(".pcap"), 5);
			outputFile.insert(0, "out/");
			outputFile += ".csv";
			csv.close();
			csv.open(outputFile);
			initializeCSV();
		}

	public:
		PCAP_Reader(): packetCount{0}, dataFormat{0}, preSeconds{0}, preNanoseconds{0}, TAI_UTC_OFFSET{getTaiToUtcOffset()}, errorCode{0}
		{
		}

		// TODO: add a way to pass the size of the header being used to the payload extraction
		// make workOnPCAPs take in a file name string instead and do everything inside the workOnPCAPs funtion
	
		// takes in a pcap file, outputs certain data about the pcap itself, then figures out what format the packet is in, and sends it to the corresponding function
		void workOnPCAPs(std::string filename) {
			char errbuff[PCAP_ERRBUF_SIZE];
			pcap_t *file = pcap_open_offline(filename.c_str(), errbuff);
			setOutputFile(filename);
			preSeconds = 0;
			preNanoseconds = 0;
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
				printf("Epoch Time: %ld:%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec );
				fprintf(fp, "Epoch Time: %ld:%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);

				// putting data into the ethernet variable
				ethernet = (headerStructure::sniff_ethernet*)(packet);
				dataFormat = ntohs(ethernet->ether_type);
				std::cout << "Data Format: " << std::hex << dataFormat << '\n';

				// switching depending on the type of packet we have received (e.g. arista format)
				switch(dataFormat) {
					case headerStructure::arista_code:
						extractTimeAristaFormat();
						break;
					default:
						// either output an unkown format error, or just ignore, maybe do a warning instead of an error
						break;
				}

				timestampAnalysis();

				printf("\n");
				fprintf(fp, "\n");
			}
			csv.close();
		}

		// deallocates memory after we have finished
	void destroy() {
		fclose(fp);
	}

	void adjustNanoseconds(int adj) {
		nanosec_adjust += adj;
	}

	void adjustSeconds(int adj) {
		sec_adjust += adj;
	}

	void timestampAdjustment(std::vector<std::string> adj) {
		if(adj[0] == "-ns-adjust") {
			nanosec_adjust += std::stoi(adj[1]);
		}
		else if(adj[0]=="-s-adjust") {
			sec_adjust += std::stoi(adj[1]);
		}
		
		if(adj[2]=="-ns-adjust"){
			nanosec_adjust += std::stoi(adj[3]);
		}
		else if(adj[2]=="-s-adjust"){
			sec_adjust += std::stoi(adj[3]);
		}
	}
};

int main(int argc, char **argv) {   
	PCAP_Reader r{};

	if(argc > 1) { // if arguments are specified, run those files

		std::vector<std::string> adj;
		if (argc >= 4)
		{
			for (int i = argc-4; i < argc; i++)
			{ adj.push_back(argv[i]); }
			r.timestampAdjustment(adj);
		}

		for(int i{1}; i < argc; i++){
			
			std::cout << argv[i] << '\n';
			r.workOnPCAPs(argv[i]);
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
					r.workOnPCAPs(str);
				}
			}
			closedir(dir);
		}
	}

	return 0;
}
