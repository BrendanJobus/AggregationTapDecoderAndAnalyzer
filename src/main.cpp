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
			u_long timeTAI = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() - 37;
			//Get current UTC Time
			u_long timeUTC = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			return timeTAI - timeUTC;
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

		// here we will do the basic analysis of the timestamps
		//@author Cillian Fogarty
		void timestampAnalysis() {

			//Time Packet was captured at (UTC)
			printf("UTC Timestamp: %ld:%ld seconds\n", seconds, nanoseconds);
			fprintf(fp, "UTC Timestamp: %ld:%ld seconds\n", seconds, nanoseconds);

			//get offset between current and previous packet
			long secondsFromPreviousPacket = seconds - previousSeconds;
			long nanosecondsFromPreviousPacket = 0;
			int packetsInOrder = 1;
			if (secondsFromPreviousPacket > 0)
			{
				//add 1 second in nanoseconds to current nanoseconds
				nanosecondsFromPreviousPacket = (1000000000 + nanoseconds) - previousNanoseconds;
			}
			else if (secondsFromPreviousPacket < 0)
			{
				//add 1 second in nanoseconds to previous nanoseconds
				nanosecondsFromPreviousPacket = nanoseconds - (1000000000 + previousNanoseconds);
				packetsInOrder = 0;
			}
			else
			{
				nanosecondsFromPreviousPacket = nanoseconds - previousNanoseconds;
			}
			printf("Offset from previous packet: %ld:%ld seconds\n", secondsFromPreviousPacket, nanosecondsFromPreviousPacket);
			fprintf(fp, "Offset from previous packet: %ld:%ld seconds\n", secondsFromPreviousPacket, nanosecondsFromPreviousPacket);

			//check packets arrived in the correct order
			if (packetsInOrder == 1)
			{
				printf("Packets in order\n");
				fprintf(fp, "Packets in order\n");
			}
			else
			{
				printf("Packets not in order\n");
				fprintf(fp, "Packets not in order\n");
			}

			//get offset between current packet and Aggregation Tap
			u_long currentTimeNanosecondsUTC = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			u_long currentTimeSecondsUTC = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();;

			printf("Current: %ld:%ld seconds\n", currentTimeSecondsUTC, currentTimeNanosecondsUTC);
			long secondsFromAggregationTap = seconds - previousSeconds;
			long nanosecondsFromAggregationTap = 0;
			int timesConsistent = 1;
			if (secondsFromAggregationTap > 0)
			{
				//add 1 second in nanoseconds to current nanoseconds
				nanosecondsFromAggregationTap = (1000000000 + nanoseconds) - previousNanoseconds;
			}
			else if (secondsFromPreviousPacket < 0)
			{
				//add 1 second in nanoseconds to previous nanoseconds
				nanosecondsFromAggregationTap = nanoseconds - (1000000000 + previousNanoseconds);
				timesConsistent = 0;
			}
			else
			{
				nanosecondsFromPreviousPacket = nanoseconds - previousNanoseconds;
			}
			printf("Offset from Aggregation Tap: %ld:%ld seconds\n", secondsFromAggregationTap, nanosecondsFromAggregationTap);
			fprintf(fp, "Offset from Aggregation Tap: %ld:%ld seconds\n", secondsFromAggregationTap, nanosecondsFromAggregationTap);

			//check packet time and Aggregation Tap time consistent
			if (timesConsistent == 1)
			{
				printf("Packet time and Aggregation Tap time consistent\n");
				fprintf(fp, "Packet time and Aggregation Tap time consistent\n");
			}
			else
			{
				printf("Packet time and Aggregation Tap time not consistent\n");
				fprintf(fp, "Packet time and Aggregation Tap time not consistent\n");
			}
		}

		// extract and print the packet metadata
		//@author Cillian Fogarty
		void printPacketMetadata() {
			printf("Metadata: TO COMPLETE\n");
			fprintf(fp, "Metadata: TO COMPLETE\n");
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

				timestampAnalysis();

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
