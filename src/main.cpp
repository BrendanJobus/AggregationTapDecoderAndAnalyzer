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
		std::string csvpath = "outpit.csv";
		// This is the pointer that will hold the packet once we do pcap_next_ex
		const u_char *packet;

		// This will store the pcap header, which holds information pertinent to pcap
		struct pcap_pkthdr *header;

		u_long seconds;
		u_long nanoseconds;

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

		// here we will do the basic analysis of the timestamps
		void timestampAnalysis() {

		}

		// might need to change the vector type depending on what we pass in.
		//vector<int> maybe do a vector<string> instead
		// it looks messy but this seems to be the best way to do it in C++
		void write_CSV(std::vector<std::pair<std::string, std::vector<int>>> dataset)
		{
			std::ofstream myFile(csvpath);
			for(int j = 0; j < dataset.size(); ++j)
    		{
			// copy over column names
       	 	myFile << dataset.at(j).first;
        	if(j != dataset.size() - 1) myFile << ",";
    		}
			myFile << "\n";

			for(int i = 0; i < dataset.at(0).second.size(); ++i)
				{
					for(int j = 0; j < dataset.size(); ++j)
					{
						myFile << dataset.at(j).second.at(i);
						if(j != dataset.size() - 1) myFile << ",";
					}
					myFile << "\n";
				}
			myFile.close();
		}

		std::vector<std::pair<std::string, std::vector<int>>> read_csv(std::string filename){
			// Reads a CSV file into a vector of <string, vector<int>> pairs where
			// each pair represents <column name, column values>
			// Create a vector of <string, int vector> pairs to store the result
			std::vector<std::pair<std::string, std::vector<int>>> result;
			// Create an input filestream
			std::ifstream myFile(filename);
			// Make sure the file is open
			if(!myFile.is_open()) throw std::runtime_error("Could not open file");
			// Helper vars
			std::string line, colname;
			int val;
			// Read the column names
			if(myFile.good())
			{
				// Extract the first line in the file
				std::getline(myFile, line);
				// Create a stringstream from line
				std::stringstream ss(line);
				// Extract each column name
				while(std::getline(ss, colname, ','))
				{
					// Initialize and add <colname, int vector> pairs to result
					result.push_back({colname, std::vector<int> {}});
				}
			}

			// Read data, line by line
			while(std::getline(myFile, line))
			{
				// Create a stringstream of the current line
				std::stringstream ss(line);
				
				// Keep track of the current column index
				int colIdx = 0;
				
				// Extract each integer
				while(ss >> val){
					
					// Add the current integer to the 'colIdx' column's values vector
					result.at(colIdx).second.push_back(val);
					
					// If the next token is a comma, ignore it and move on
					if(ss.peek() == ',') ss.ignore();
					
					// Increment the column index
					colIdx++;
				}
			}

			// Close file
			myFile.close();

			return result;
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
