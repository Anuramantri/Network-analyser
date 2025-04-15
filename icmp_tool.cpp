#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <cmath>
#include <limits>
#include <fstream>
#include <map>


#define MAX_PACKET_SIZE 1028
#define DEFAULT_MAX_HOPS 30
#define DEFAULT_TIMEOUT 3
#define DEFAULT_PROBES 3

std::string get_timestamp() {
    time_t now = time(0);
    struct tm timeinfo;
    char buffer[80];
    
    #ifdef _WIN32
    localtime_s(&timeinfo, &now);
    #else
    timeinfo = *localtime(&now);
    #endif
    
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(buffer);
}

int get_and_update_usage_count(const std::string& destination) {
    std::map<std::string, int> usage_counts;
    std::ifstream usage_file("usage_counts.txt");
    
    if (usage_file.is_open()) {
        std::string dest;
        int count;
        while (usage_file >> dest >> count) {
            usage_counts[dest] = count;
        }
        usage_file.close();
    }
    
    // Increment the usage count for this destination
    usage_counts[destination]++;
    
    // Write updated counts back to file
    std::ofstream out_file("usage_counts.txt");
    if (out_file.is_open()) {
        for (const auto& pair : usage_counts) {
            out_file << pair.first << " " << pair.second << std::endl;
        }
        out_file.close();
    }
    
    return usage_counts[destination];
}


// Function to calculate ICMP checksum
unsigned short calculate_checksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++; // sum up 16 bits at a time
        nleft -= 2; // move to next 16 bits
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w; // copy the first byte of w into the first byte of answer
        sum += answer; // add the last byte 
    }

    sum = (sum >> 16) + (sum & 0xFFFF); // adds the upper 16 bits to the lower 16 bits
    sum += (sum >> 16); // fold again to add any carry
    answer = ~sum; // 1s complement
    return answer;
}

// Create ICMP socket
int create_icmp_socket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        std::cerr << "Error creating socket. Root privileges required." << std::endl;
        exit(1);
    }
    return sock;
}

// Create ICMP echo request packet
void create_icmp_packet(ICMPPacket *packet, int seq, int size) {
    memset(packet, 0, sizeof(ICMPPacket)); // init packet to zero
    packet->header.type = ICMP_ECHO; // ICMP echo request type
    packet->header.code = 0; // code 0 for echo request
    packet->header.un.echo.id = htons(getpid() & 0xFFFF); // set process ID
    packet->header.un.echo.sequence = htons(seq); //  sequence number
    
    // Fill data part with pattern
    for (int i = 0; i < size - sizeof(struct icmphdr); i++) {
        packet->data[i] = 'x';
    }
    
    
    packet->header.checksum = 0;
    packet->header.checksum = calculate_checksum((unsigned short *)packet, size);
}


