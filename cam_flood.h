#ifndef CAM_FLOOD_H
#define CAM_FLOOD_H

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

#define ETHER_HEADER_LEN 14

void stringToMac(const char *macStr, u_char *mac);
void generate_random_mac(u_char *mac_addr);
int generate_random_numbers();
void generate_random_ip(char *ip_addr);
unsigned short checksum(unsigned short *buf, int len);
void generate_ip_payload(struct ip *ip_header, char *SRC_IP, char *DST_IP);
void generate_basic_packets(struct ether_header *packet_list, int num_packets, u_char *THA, int assigned);
void generate_complex_packets(struct ether_header *packet_list, unsigned char **eth_frames, int num_packets, char SRC_IP[], char DST_IP[]);
void cam_complex_overflow(unsigned char **eth_frames, int num_packets, char *INTERFACE, size_t frame_len);

#endif /* CAM_FLOOD_H */

