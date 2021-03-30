#include "../include/main.hpp"

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

// This corresponds to 
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

// length in bytes of the arista types struct
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

void process_packet(u_char*, const struct pcap_pkthdr*, const u_char *);
FILE *logfile;
int packetCount = 0;
const struct sniff_ethernet *ethernet;

int main() {   
	pcap_if_t *alldevsp, *device;
	pcap_t *handle;

	/* 
	// These two lines are examples of how to hardcode a devname 
	//char devname[5] = {'w', 'l', 'o', '1'};
	//devname[4] = 0;
	*/

	char errbuf[100], *devname, devs[100][100];
	int count = 1, n;

	printf("Finding available devices...");
	if(pcap_findalldevs(&alldevsp, errbuf)) {
		printf("Error finding devices: %s", errbuf);
		exit(1);
	}
	printf("Done\n");

	printf("Available Devices are: \n");
	for(device = alldevsp; device != NULL; device = device->next) {
		printf("%d. %s - %s\n", count, device->name, device->description);
		if(device->name != NULL) {
			strcpy(devs[count], device->name);
		}
		count++;
	}

	printf("Enter the number of devices you want to sniff: ");
	scanf("%d", &n);
	devname = devs[n];

	printf("Opening device %s for sniffing...", devname);
	handle = pcap_open_live(devname, 65536, 1, 0, errbuf);

	if(handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", devname, errbuf);
		exit(1);
	}
	printf("Done\n");

	logfile = fopen("log.txt", "w");
	if(logfile == NULL) {
		printf("Unable to create file.");
	}

	pcap_loop(handle, -1, process_packet, NULL);
	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
	printf("Packet # %i\n", ++packetCount);

	printf("Packet size: %d bytes\n", header->len);

	if(header->len != header->caplen)
		printf("Warning! Capture size different that packet size: %d bytes\n", header->len);

	printf("Epoch Time: %ld:%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);

	ethernet = (struct sniff_ethernet*)(buffer);
	std::cout << std::hex << ntohs(ethernet->ether_type) << '\n';
}