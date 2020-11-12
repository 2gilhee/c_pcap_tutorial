#include <iostream>
#include <pcap.h>
#include <iomanip>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <typeinfo>
#include <arpa/inet.h>
#include <bitset>

using namespace std;

void printLine(){
	cout << "-----------------------------------------" << endl;
}

void printByHexData(u_int8_t *printArr, int length){
	for(int i=0; i<length; i++){
		if(i%16 == 0)
			cout << endl;
		cout << setfill('0');
		cout << setw(2) << hex << (int)printArr[i] << " ";
	}
	cout << dec << endl;
	printLine();
}

void printMac(u_int8_t *addr){
    int sizeOfMac=6;//mac address => 48bit
                    //mac use hexadecimal number
                    //Ex) AB:CD:EF:GH:YJ:KL
                    //hexadecimal number use 4bit per 1 num
                    //0 0 0 0 => 0
                    //1 1 1 1 => F => 15

    for(int i=0; i<sizeOfMac;i++)
    {
            printf("%02x",addr[i]);
            if(i!=sizeOfMac-1)
                    printf(":");
    }
		printf("\n");

}

bool print_ethernet(struct ether_header* eth){
	unsigned short ether_type = ntohs(eth->ether_type);
	bool is_ip = false;

	cout << "-------ETHERNET HEADER-------" << endl;
	cout << "ether_dest: ";
	printMac(eth->ether_dhost);
	cout << "ether_sour: ";
	printMac(eth->ether_shost);
	cout << "ether_type: ";
	printf("%04x\n\n", ether_type);

	if(ether_type == ETHERTYPE_IP) {
		is_ip = true;
	}

	return is_ip;
}

void print_fragment(unsigned short frag) {
	// int rf = frag & IP_RF;
	// int df = frag & IP_DF;
	// int mf = frag & IP_MF;
	// unsigned short off = frag & IP_OFFMASK;

	bitset<16> temp = bitset<16>(frag);
	// cout << bitset<16>(frag) <<endl;
	// cout << temp <<endl;

	cout << "IP_OFF_RF	: " << temp[15] << endl;
	cout << "IP_OFF_DF	: " << temp[14] << endl;
	cout << "IP_OFF_MF	: " << temp[13] << endl;
	cout << "IP_OFF_SET	: ";
	for(int i=12; i>=0; i--) {
		if(i == 12 || i == 8 || i ==4)
			cout << temp[i] << " ";
		else
			cout << temp[i];
	}
	cout << endl;
}

void print_IP(struct ip* ip_header){
	printf("-------IP HEADER-------\n");
	printf("version		: 0x%x\n", ip_header->ip_v);
	printf("Header Len	: %d\n", ip_header->ip_hl);
	printf("Type of Service	: 0x%02x\n", ip_header->ip_tos);
	printf("Length		: %d\n", ntohs(ip_header->ip_len));
	printf("Ident		: 0x%04x\n", ntohs(ip_header->ip_id));
	printf("Fragmentation	: 0x%04x\n", ntohs(ip_header->ip_off));
	print_fragment(ntohs(ip_header->ip_off));
	printf("TTL		: 0x%02x\n", ip_header->ip_ttl);
	printf("Protocol	: 0x%02x\n", ip_header->ip_p);
	printf("Check		: 0x%04x\n", ntohs(ip_header->ip_sum));
	printf("Src Address	: %s\n", inet_ntoa(ip_header->ip_src));
	//printf("%s\n", ip_header->saddr.str())
	printf("Dst address	: %s\n\n", inet_ntoa(ip_header->ip_dst));
	//printIPAddress(ip_header->daddr);
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 1;
	struct ether_header* eth_header;
	struct ip* ip_header;
	bool is_ip;
	int chcnt = 0;
	int length = pkthdr->len;

	printf("-------PACKET START-------\n");

	// GET Ethernet header & GET protocol
	eth_header = (struct ether_header*)packet;
	is_ip = print_ethernet(eth_header);

	// set offset packet for ip header
	packet += sizeof(struct ether_header);

	//GET IP header
	ip_header = (struct ip*) packet;
	print_IP(ip_header);
}


int main(int argc, char* argv[]){
	char* device = argv[1];
	// cout << device << endl;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcd = pcap_open_live(device, BUFSIZ, 1, 200, errbuf);
	struct pcap_pkthdr *hdr;
	const u_char* pkt_data;

	int value_of_next_ex;
	pcap_loop(pcd, 10, callback, NULL);
}
