### Memory Used ###

100% necessary:
pcap_t *handle
char errbuf[100], *devname(We will give this a value that pico will specify it is null terminated)

If we add in the choice of what device to listen to:
pcap_if_t *alldevsp, *device
char *devname, devs[100][100]
int count = 1, n


### Explanation ###

This will be the first thing that is run, it will either take in a user specified device to listen on, or use a default(The device that pico will want us to listen on), we then call pcap_open_live(), and the create a loop on the output of pcap_open_live(), we will specify a function that will deal with the packets in the paramaters of pcap_loop().