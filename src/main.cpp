#include "../include/main.hpp"

// Put into a class primarily for increased readability and portability
class PCAP_Reader {
	private:
		enum error_codes {
			// the agg tap timestamp is ahead of the packets timestamp
			packet_before_aggTap = 0xB,
			// the current packet's agg tap timestamp is behind the previous packet's agg tap timestamp
			aggTap_behind_previous = 0xA0,
		};

		// each struct corresponds to a number of bits in the packets memory, to find out what each means, look at the structs
		const headerStructure::sniff_ethernet *ethernet;
		// For packets of arista7280 7280/7500 format
		const headerStructure::arista7280::sniff_types *arista7280_types;
		const headerStructure::arista7280::sniff_times_64 *arista7280_time64;
		const headerStructure::arista7280::sniff_times_48 *arista7280_time48;
		// For packet of example format
		const headerStructure::exampleVendor::sniff_types *exTypes;
		const headerStructure::exampleVendor::sniff_times_64 *exTime64;
		const headerStructure::exampleVendor::sniff_times_48 *exTime48;
		// For packet of example format
		const headerStructure::arista7130::sniff_times_64 *arista7130_time64;

		int packetCount;

		// variables for other packet data
		u_short dataFormat;
		u_short timestampLength;
		u_short timeFormat;

		// output stream
		std::ofstream csv;

		// pointers for pcap_next_ex()
		const u_char *packet;
		struct pcap_pkthdr *header;

		// Packet header and data sizes
		int headerSize;

		// forward declaration of variables that hold the different times
		u_int packetSeconds;
		u_int packetNanoseconds;
		u_long seconds;
		u_long nanoseconds;
		u_int rawSeconds;
		u_int rawNanoseconds;
		u_long preSeconds;
		u_long preNanoseconds;

		// forward declaration of variables needed for adjustment command
		int sec_adjust;
		int nanosec_adjust;
		int packet_sec_adjust;
		int packet_nanosec_adjust;

		//Offset between TAI and UTC
		const int TAI_UTC_OFFSET = getTaiToUtcOffset();

		//Get offset between TAI and UTC
		int getTaiToUtcOffset() {
			//Get current TAI Time
			u_long timeTAI = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() + 37;
			//Get current UTC Time
			u_long timeUTC = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			return timeUTC - timeTAI;
		}

		//Convert TAI to UTC
		u_long taiToUtc(u_long taiTime) {
			return taiTime + TAI_UTC_OFFSET;
		}

///////////// These functions extract the agg tap times from the packets, each one will work for its corresponding packet format /////////////

		// returns the size of the timestamp in bytes
		int extractTimeArista7280Format() {
			// putting data into the arista7280_types variable
			arista7280_types = (headerStructure::arista7280::sniff_types*)(packet + headerStructure::arista7280::TYPES_POS);

			timestampLength = ntohs(arista7280_types->subType);
			timeFormat  = ntohs(arista7280_types->version);

			if (timestampLength == headerStructure::arista7280::sixtyFourBitCode) {
				arista7280_time64 = (headerStructure::arista7280::sniff_times_64*)(packet + headerStructure::arista7280::TIMES_POS);

				rawSeconds = arista7280_time64->seconds;
				rawNanoseconds = arista7280_time64->nanoseconds;	

				seconds = ntohl(arista7280_time64->seconds);
				nanoseconds = ntohl(arista7280_time64->nanoseconds);

				if(timeFormat == headerStructure::arista7280::taiCode) {
					seconds = taiToUtc(seconds);
				}
				return headerStructure::arista7280::SIZE_OF_SECONDS + headerStructure::arista7280::SIZE_OF_NANOSECONDS_64;
			} 
			else {
				arista7280_time48 = (headerStructure::arista7280::sniff_times_48*)(packet + headerStructure::arista7280::TIMES_POS);

				rawSeconds = arista7280_time48->seconds;
				rawNanoseconds = arista7280_time48->nanoseconds;

				seconds = ntohl(arista7280_time48->seconds);
				nanoseconds = ntohl(arista7280_time48->nanoseconds);

				if(timeFormat == headerStructure::arista7280::taiCode) {
					seconds = taiToUtc(seconds);
				}
				return headerStructure::arista7280::SIZE_OF_SECONDS + headerStructure::arista7280::SIZE_OF_NANOSECONDS_48;
			}
		}

		// This function is exactly the same as the previous, only now its using the types from exampleVendor and is using the ex variables
		int extractTimeExampleFormat() {
			exTypes = (headerStructure::exampleVendor::sniff_types*)(packet + headerStructure::exampleVendor::TYPES_POS);

			timestampLength = ntohs(exTypes->subType);
			timeFormat  = ntohs(exTypes->version);

			if (timestampLength == headerStructure::exampleVendor::sixtyFourBitCode) {
				exTime64 = (headerStructure::exampleVendor::sniff_times_64*)(packet + headerStructure::exampleVendor::TIMES_POS);

				rawSeconds = exTime64->seconds;
				rawNanoseconds = exTime64->nanoseconds;	

				seconds = ntohl(exTime64->seconds);
				nanoseconds = ntohl(exTime64->nanoseconds);

				if(timeFormat == headerStructure::exampleVendor::taiCode) {
					seconds = taiToUtc(seconds);
				}
				return headerStructure::exampleVendor::SIZE_OF_SECONDS + headerStructure::exampleVendor::SIZE_OF_NANOSECONDS_64;
			} 
			else {
				exTime48 = (headerStructure::exampleVendor::sniff_times_48*)(packet + headerStructure::exampleVendor::TIMES_POS);

				rawSeconds = exTime48->seconds;
				rawNanoseconds = exTime48->nanoseconds;

				seconds = ntohl(exTime48->seconds);
				nanoseconds = ntohl(exTime48->nanoseconds);

				if(timeFormat == headerStructure::exampleVendor::taiCode) {
					seconds = taiToUtc(seconds);
				}
				return headerStructure::exampleVendor::SIZE_OF_SECONDS + headerStructure::exampleVendor::SIZE_OF_NANOSECONDS_48;
			}
		}

		int extractTimeArista7130Format(u_int packet_len) {
			arista7130_time64 = (headerStructure::arista7130::sniff_times_64*)(packet + packet_len - headerStructure::arista7130::SIZE_WO_FCS);

			// Timestamp is always UTC in metamako/7130 format
			rawSeconds = arista7130_time64->seconds;
			rawNanoseconds = arista7130_time64->nanoseconds;	

			seconds = ntohl(arista7130_time64->seconds);
			nanoseconds = ntohl(arista7130_time64->nanoseconds);

			// returns 0 as the timestamp data is not infront of the payload, so it can be ignored for the purpose of extracting the payload
			return 0;
		}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		long errorCode;
		// timestamp analysis
		void timestampAnalysis(int headerSize) {

			seconds += sec_adjust;
			nanoseconds += nanosec_adjust;

			errorCode = 0;

			// get offset between current and previous packet
			long secondDelta = seconds - preSeconds;
			long nanosecondDelta = 0;

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
					errorCode = aggTap_behind_previous;
				}
				// case: both are behind
				else if (secondDelta < 0 && nanoseconds < preNanoseconds) {
					nanosecondDelta = nanoseconds - preNanoseconds;
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

			// get offset between current packet and Aggregation Tap
			long aggTapArrivalDelta_s = packetSeconds - seconds;
			long aggTapArrivalDelta_us = 0;

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
				errorCode |= packet_before_aggTap;
			} 
			// case: both are behind
			else if (aggTapArrivalDelta_s <= 0 && packetNanoseconds < nanoseconds) {
				aggTapArrivalDelta_us = packetNanoseconds - nanoseconds;
				errorCode |= packet_before_aggTap;
			}
			// case: both are ahead
			else {
				aggTapArrivalDelta_us = packetNanoseconds - nanoseconds;
			}

			addTimestampDataToCSV(secondDelta, nanosecondDelta, aggTapArrivalDelta_s, aggTapArrivalDelta_us, headerSize);
		}

		// extract and print the packet metadata
		void extractPacketPayload(int headerSize) {
			// extract the length of the ip_data from the file
			int ethernet_header_length = headerStructure::ETHER_SIZE + headerSize; //constant length in bytes
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
			int udp_payload_length = udp_header_length - length_udp_info;

			// extract the metadata from the file and output it
			if (udp_payload_length > 0) {
		        const u_char *temp_pointer = metadata_header;
		        int byte_count = 0;
		        char payload[4];
		        while (byte_count++ < udp_payload_length) {
					sprintf(payload, "%02X ", *temp_pointer);
					csv << payload;
		            temp_pointer++;
		        }
		    }
		}

		// output the first row as to display the what is in each column
		void initializeCSV() {
			csv << "Packet #, Packet Timestamp, Raw Timestamp Metadata, Converted Timestamp Metadata, ";
			csv << "Previous Packet Offset, Agg Tap and Packet Delta, Error Code, ";
			csv << "Payload\n";
		}

		// outputting the data to the csv
		void addTimestampDataToCSV(long interPacketOffset_s, long interPacketOffset_us, long aggTapArrivalDelta_s, long aggTapArrivalDelta_us, int headerSize) {
			csv << packetCount << ", " << packetSeconds << ":" << packetNanoseconds << ", " << std::hex << rawSeconds << ":" << rawNanoseconds << std::dec << ", " << seconds << ":" << nanoseconds <<  ", ";
			csv << interPacketOffset_s << ":" << interPacketOffset_us << ", " << aggTapArrivalDelta_s << ":" << aggTapArrivalDelta_us << ", 0x" << std::hex << errorCode << std::dec <<  ", ";

			extractPacketPayload(headerSize);

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
		PCAP_Reader(): packetCount{0}, dataFormat{0}, preSeconds{0}, preNanoseconds{0}, sec_adjust{0}, nanosec_adjust{0}, packet_sec_adjust{0}, packet_nanosec_adjust{0}, TAI_UTC_OFFSET{getTaiToUtcOffset()}, errorCode{0}
		{ }
	
		// takes in a pcap file, outputs certain data about the pcap itself, then figures out what format the packet is in, and sends it to the corresponding function
		void workOnPCAPs(std::string filename) {
			char errbuff[PCAP_ERRBUF_SIZE];
			pcap_t *file = pcap_open_offline(filename.c_str(), errbuff);
			setOutputFile(filename);
			preSeconds = 0;
			preNanoseconds = 0;
			packetCount = 0;
			// pcap_next_ex returns a 1 so long as every thing is ok, so keep looping until its not 1
			while(pcap_next_ex(file, &header, &packet) >= 0) {
				// printing the packet count
				packetCount++;

				// making sure the captured length is the same as the data length
				if(header->len != header->caplen)
					printf("Warning! Capture size different than packet size: %d bytes\n", header->len);

				packetSeconds = header->ts.tv_sec;
				packetNanoseconds = header->ts.tv_usec;

				packetSeconds += packet_sec_adjust;
				packetNanoseconds += packet_nanosec_adjust;

				// putting data into the ethernet variable
				ethernet = (headerStructure::sniff_ethernet*)(packet);
				dataFormat = ntohs(ethernet->ether_type);

				// switching depending on the type of packet we have received (e.g. arista7280 format)
				switch(dataFormat) {
					case headerStructure::arista7280_code:
						headerSize = headerStructure::arista7280::SIZE_WO_TIMESTAMP;
						headerSize += extractTimeArista7280Format();
						break;

					case headerStructure::example_code:
						headerSize = headerStructure::exampleVendor::SIZE_WO_TIMESTAMP;
						headerSize += extractTimeExampleFormat();
						break;

					case headerStructure::arista7130_code:
						// This format takes in an argument as the timestamps are at the end, so we pass the size of
						// the packet, and go from the back
						headerSize = extractTimeArista7130Format(header->len);
						break;

					default:
						break;
				}

				seconds += sec_adjust;
				nanoseconds += nanosec_adjust;

				timestampAnalysis(headerSize);

				preSeconds = seconds;
				preNanoseconds = nanoseconds;
			}
			std::cout << "Finished analyzing " << filename << '\n';
			csv.close();
		}
		
		void setAdjustSec(int adj) {
			sec_adjust += adj;
		}

		void setAdjustNanosec(int adj) {
			nanosec_adjust += adj;
		}

		void setAdjustPacketSec(int adj) {
			packet_sec_adjust += adj;
		}

		void setAdjustPacketNanosec(int adj) {
			packet_nanosec_adjust += adj;
		}
};

int main(int argc, char **argv) {   
	PCAP_Reader r{};

	if(argc > 1) { // if arguments are specified, run those files
		if ( (argc == 2) && (( (std::string)argv[1] == "--help") || ((std::string)argv[1] == "-h")) ) {
			std::cout << helpString;
		}
		else {
			std::vector<std::string> files;
			for(int i{1}; i < argc; i++) {
				// if the first character of the string is a "-"" assume that it is an argument, else, assume it is a file
				if ( argv[i][0] == '-') {
					if ( (std::string)argv[i] == "-s") {
						r.setAdjustSec(std::stoi(argv[++i]));
					}
					else if ( (std::string)argv[i] == "-ns") {
						r.setAdjustNanosec(std::stoi(argv[++i]));
					}
					else if ( (std::string)argv[i] == "-ps") {
						r.setAdjustPacketSec(std::stoi(argv[++i]));
					}
					else if ( (std::string) argv[i] == "-pns") {
						r.setAdjustPacketNanosec(std::stoi(argv[++i]));
					}
					else {
						printf("Invalid input\nFor help, use argument -h or --help\n");
					}
				} else {
					files.push_back(argv[i]);
				}
			}

			for(std::string file : files) {
				std::cout << file << '\n';
				r.workOnPCAPs(file);
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
					r.workOnPCAPs(str);
				}
			}
			closedir(dir);
		}
	}

	return 0;
}
