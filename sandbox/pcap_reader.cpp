#include <stdio.h> 
#include <pcap.h> 
#include <sys/time.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>

using namespace std;
 
int main(int argc, char *argv[]) { 
		struct pcap_pkthdr *header;
		const u_char *data;
		
        char errbuf[PCAP_ERRBUF_SIZE]; 
        pcap_t* packet = pcap_open_offline("7280_64_bit_10_packets.pcap",errbuf); 
		
		//pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf); // or PCAP_CHAR_ENC_UTF_8
		//if (pcap_is_swapped(thing))
		//	 cout << "swapped" << endl;
		//else
		//	cout << "NOT swapped" << endl;
			
		
		u_int packetCount = 0;
		while (int returnValue = pcap_next_ex(packet,&header,&data) == 1)
		{
			cout << "opened packet " << packetCount << endl;
			cout << header->caplen << endl;
			struct timeval tv;
			tv = header->ts;
			cout << "Number of whole seconds of elapsed time: " << tv.tv_sec << endl;
			cout << "Number of microseconds of rest of elapsed time minus tv_sec: " << tv.tv_usec << endl;
			//cout << header->len << endl;
			// cout << *data << endl; (empty output as data is empty)
			packetCount++;
		}
		
		pcap_dumper_t *nP = pcap_dump_open(packet, "7280_64_bit_10_packets_edited.pcap");		
		pcap_close(packet);
				
		//pcap_dump(nP, header, data);
		pcap_dump_close(nP);
			
		cout << "----------------- OPENING NEW PACKET -----------------" << endl;
		pcap_t* newPacket = pcap_open_offline("7280_64_bit_10_packets_edited.pcap",errbuf); 
		
		packetCount = 0;
		while (int returnValue = pcap_next_ex(newPacket,&header,&data) == 1)
		{
			cout << "opened packet " << packetCount << endl;
			cout << header->caplen << endl;
			struct timeval tv;
			tv = header->ts;
			cout << "Number of whole seconds of elapsed time: " << tv.tv_sec << endl;
			cout << "Number of microseconds of rest of elapsed time minus tv_sec: " << tv.tv_usec << endl;
			packetCount++;
		}
		
		pcap_close(newPacket);
		
		
		
}


