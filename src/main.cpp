#include "../include/main.hpp"

int main()
{   
	analysePacketsFromFile("./data/pCaps1.pcap");
}

void analysePacketsFromFile(const char * filePath)
{
	struct pcap_pkthdr *header;
	const u_char *data;
	
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* packetData = pcap_open_offline(filePath, errbuf);
    packet newPacket; 
	while (int returnValue = pcap_next_ex(packetData, &header, &data) == 1)
	{
		//extract
		newPacket.timestampVersion = 1;
		newPacket.seconds = header->ts.tv_sec;
		newPacket.nanoseconds = header->ts.tv_usec;

		//do some analysis
		printPacketData(newPacket);
	}
	pcap_close(packetData);	
}

void printPacketData(packet inputPacket)
{
	printf("Version: %d Seconds: %d Nanoseconds: %d\n", inputPacket.timestampVersion, inputPacket.seconds, inputPacket.nanoseconds);
}