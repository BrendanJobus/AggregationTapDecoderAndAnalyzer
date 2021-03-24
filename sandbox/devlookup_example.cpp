#include <stdio.h>
#include <pcap.h>
#include <cstdlib>

using namespace std;

int main(int argc, char *argv[]) {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t * alldevs;

	if(pcap_findalldevs(&alldevs, errbuf) == -1)
		fprintf(stderr, "Error: %s\n", errbuf);

	int i = 0;
	pcap_if_t *d;
	for(d = alldevs; d != NULL; d = d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" - (%s)\n", d->description);
		else 
			printf(" - (No desc available)\n");
		if (i == 0)
			printf("\nNothing found.\n");
	}

	pcap_freealldevs(alldevs);
}
