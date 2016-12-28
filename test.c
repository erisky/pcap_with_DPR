#include <stdio.h>
#include <pcap.h>



int test_find(void)
{
    struct pcap_if *pIf_list, *pTemp;
    int ret;
    char errbuf[128];

    ret = pcap_findalldevs(&pIf_list, errbuf);

    if (ret == 0) {
        pTemp = pIf_list;
        while(pTemp) {
            printf("If: %s : %s\r\n", pTemp->name, pTemp->description);
            pTemp = pTemp->next;
        }
    
        pcap_freealldevs(pIf_list);
    
    }

}

//#define BUFSIZ  (10240)
int test_sniff(char *dev)
{
    pcap_t *handle;
    const u_char *packet;   
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "port 22";  /* The filter expression */
    struct pcap_pkthdr header;  /* The header that pcap gives us */

    handle = pcap_open_live(dev,BUFSIZ, 1, 1000, errbuf);
     if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n",  dev, errbuf);
        return(2);
     }


    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }

    
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
             return(2);
                                                }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
                                            }

    /* Grab a packet */
    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    pcap_close(handle);
    return(0);

}



int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
    

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);


    test_find();
    test_sniff("eth2");
    //test_sniff("any");



	return(0);
}
