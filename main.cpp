#include <iostream>
#include <pcap.h>
#include <iomanip>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <typeinfo>
#include <arpa/inet.h>

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

void printIPAddress(uint32_t *addr) {
	int sizeOfIP = 4;

	for(int i=0; i<sizeOfIP;i++)
	{
					printf("%02x ",addr[i]);
					if(i!=sizeOfIP-1)
									printf(".");
	}
	printf("\n");
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	static int count = 1;
	struct ether_header* eth_header;
	struct iphdr* ip_header;
	bool is_ip;
	int chcnt = 0;
	int length = pkthdr->len;

	// GET Ethernet header & GET protocol
	eth_header = (struct ether_header*)packet;
	is_ip = print_ethernet(eth_header);

	// set offset packet for ip header
	packet += sizeof(struct ether_header);

	//GET IP header
	ip_header = (struct iphdr*) packet;
	printf("-------IP HEADER-------\n");
	printf("version  : 0x%x\n", ip_header->version);
	printf("Header Len  : 0x%x\n", ip_header->ihl);
	printf("Type of Service  : 0x%02x\n", ip_header->tos);
	printf("Ident       : 0x%04x\n", ip_header->id);
	printf("Fragmentation  : 0x%04x\n", ip_header->frag_off);
	printf("TTL         : 0x%04x\n", ip_header->ttl);
	printf("Protocol  : 0x%02x\n", ip_header->protocol);
	printf("Check  : 0x%04x\n", ip_header->check);
	printf("Src Address : %04x\n", ip_header->saddr);
	//printf("%s\n", ip_header->saddr.str())
	printf("Dst Address : %04x\n\n", ip_header->daddr);
	//printIPAddress(ip_header->daddr);
}


int main(int argc, char* argv[]){
	char* device = argv[1];
	cout << device << endl;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcd = pcap_open_live(device, BUFSIZ, 1, 200, errbuf);
	struct pcap_pkthdr *hdr;
	const u_char* pkt_data;

	int value_of_next_ex;
	pcap_loop(pcd, 10, callback, NULL);
}

//
// int main(int argc, char* argv[])
// {
//
//     char* device = "ens33";
//     cout<<device<<endl;
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t* pcd =  pcap_open_live(device, BUFSIZ, 1, 200, errbuf);
//
//     struct pcap_pkthdr *hdr;
//     const u_char* pkt_data;
//
//     int value_of_next_ex;
//
//       while(true)
//       {
//           value_of_next_ex = pcap_next_ex(pcd,&hdr,&pkt_data);
//
//           switch (value_of_next_ex)
//           {
//               case 1:
//                   //do something with pkt_data and hdr
//
//                   printByHexData((uint8_t*)pkt_data, hdr->len);
//                   break;
//               case 0:
//                   cout<<"need a sec.. to packet capture"<<endl;
//                   continue;
//               case -1:
//                   perror("pcap_next_ex function has an error!!!");
//                   exit(1);
//               case -2:
//                   cout<<"the packet have reached EOF!!"<<endl;
//                   exit(0);
//               default:
//                   break;
//           }

//
//       }
//     return 0;
// }
