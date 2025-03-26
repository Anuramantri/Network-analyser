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
#include <fstream>

#define MAX_PACKET_SIZE 4096
#define DEFAULT_MAX_HOPS 30
#define DEFAULT_TIMEOUT 1
#define DEFAULT_PROBES 3

// Structure to store hop information
struct HopInfo {
    int hop;
    std::string ip_address;
    double rtt;
    double bandwidth;
    bool is_bottleneck;
};

// ICMP packet structure
struct ICMPPacket {
    struct icmphdr header;
    char data[MAX_PACKET_SIZE - sizeof(struct icmphdr)];
};

// Function to calculate ICMP checksum
unsigned short calculate_checksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
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
    memset(packet, 0, sizeof(ICMPPacket));
    packet->header.type = ICMP_ECHO;
    packet->header.code = 0;
    packet->header.un.echo.id = htons(getpid() & 0xFFFF);
    packet->header.un.echo.sequence = htons(seq);
    
    // Fill data part with pattern
    for (int i = 0; i < size - sizeof(struct icmphdr); i++) {
        packet->data[i] = 'x';
    }
    
    // Calculate checksum
    packet->header.checksum = 0;
    packet->header.checksum = calculate_checksum((unsigned short *)packet, size);
}

// Improved bandwidth estimation using packet pair technique
double estimate_bandwidth(const char *dest_addr, int ttl) {
    int sock = create_icmp_socket();
    
    // Set TTL value
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        std::cerr << "Error setting TTL" << std::endl;
        close(sock);
        return -1;
    }
    
    // Prepare destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_addr);
    
    // Packet sizes for bandwidth estimation - use larger difference
    int small_size = 64;   // Smaller packet
    int large_size = 1400; // Larger packet
    int num_probes = 5;    // Increased number of probes for better statistics
    
    std::vector<double> bandwidths;
    
    // Run multiple packet pair tests
    for (int i = 0; i < num_probes; i++) {
        // Send two back-to-back packets of the same size (large)
        ICMPPacket packet1, packet2;
        create_icmp_packet(&packet1, i*2 + 1, large_size);
        create_icmp_packet(&packet2, i*2 + 2, large_size);
        
        // Send first packet
        if (sendto(sock, &packet1, large_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            continue;
        }
        
        // Send second packet immediately (back-to-back)
        if (sendto(sock, &packet2, large_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            continue;
        }
        
        // Receive responses
        char recv_buffer1[MAX_PACKET_SIZE], recv_buffer2[MAX_PACKET_SIZE];
        struct sockaddr_in from1, from2;
        socklen_t from_len1 = sizeof(from1), from_len2 = sizeof(from2);
        
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sock, &read_set);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        // Receive first packet
        auto start_time = std::chrono::high_resolution_clock::now();
        
        if (select(sock + 1, &read_set, NULL, NULL, &timeout) <= 0) {
            continue;
        }
        
        if (recvfrom(sock, recv_buffer1, sizeof(recv_buffer1), 0, (struct sockaddr *)&from1, &from_len1) < 0) {
            continue;
        }
        
        auto first_arrival = std::chrono::high_resolution_clock::now();
        
        // Reset for second packet
        FD_ZERO(&read_set);
        FD_SET(sock, &read_set);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        // Receive second packet
        if (select(sock + 1, &read_set, NULL, NULL, &timeout) <= 0) {
            continue;
        }
        
        if (recvfrom(sock, recv_buffer2, sizeof(recv_buffer2), 0, (struct sockaddr *)&from2, &from_len2) < 0) {
            continue;
        }
        
        auto second_arrival = std::chrono::high_resolution_clock::now();
        
        // Calculate time interval between packet arrivals in microseconds
        auto interval = std::chrono::duration_cast<std::chrono::microseconds>(
            second_arrival - first_arrival).count();
        
        // Skip if interval is too small (likely measurement error)
        if (interval <= 0) continue;
        
        // Calculate bandwidth using the formula: B = packet size / interval
        // Convert to Mbps: (bytes * 8) / (microseconds / 1,000,000) / 1,000,000
        double bw = (large_size * 8.0) / interval;
        bandwidths.push_back(bw);
    }
    
    close(sock);
    
    // Filter and calculate final bandwidth estimate
    if (bandwidths.size() >= 3) {
        // Sort bandwidths for median filtering
        std::sort(bandwidths.begin(), bandwidths.end());
        
        // Use median value to filter out outliers
        double median_bw;
        if (bandwidths.size() % 2 == 0) {
            median_bw = (bandwidths[bandwidths.size()/2 - 1] + bandwidths[bandwidths.size()/2]) / 2.0;
        } else {
            median_bw = bandwidths[bandwidths.size()/2];
        }
        
        return median_bw;
    } else if (bandwidths.size() > 0) {
        // If we don't have enough samples for median, use average
        return std::accumulate(bandwidths.begin(), bandwidths.end(), 0.0) / bandwidths.size();
    }
    
    return -1; // Unable to estimate bandwidth
}

// Perform traceroute with bandwidth estimation
std::vector<HopInfo> traceroute(const char *destination, int max_hops, int timeout, int probes) {
    std::vector<HopInfo> hop_info;
    
    // Resolve destination hostname to IP address
    struct hostent *host = gethostbyname(destination);
    if (!host) {
        std::cerr << "Unknown host: " << destination << std::endl;
        return hop_info;
    }
    
    char *dest_addr = inet_ntoa(*(struct in_addr *)host->h_addr);
    
    std::cout << "Traceroute to " << destination << " (" << dest_addr << "), " << max_hops << " hops max" << std::endl;
    std::cout << "Hop\tIP Address\t\tRTT (ms)\t\tBandwidth (Mbps)" << std::endl;
    std::cout << std::string(70, '-') << std::endl;
    
    for (int ttl = 1; ttl <= max_hops; ttl++) {
        int sock = create_icmp_socket();
        
        // Set TTL value
        if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            std::cerr << "Error setting TTL" << std::endl;
            close(sock);
            continue;
        }
        
        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            std::cerr << "Error setting timeout" << std::endl;
            close(sock);
            continue;
        }
        
        // Prepare destination address
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(dest_addr);
        
        // Send ICMP echo request
        ICMPPacket packet;
        create_icmp_packet(&packet, ttl, sizeof(struct icmphdr) + 56);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        if (sendto(sock, &packet, sizeof(struct icmphdr) + 56, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            std::cerr << "Error sending packet" << std::endl;
            close(sock);
            continue;
        }
        
        // Receive ICMP response
        char recv_buffer[MAX_PACKET_SIZE];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        
        int bytes_received = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&from, &from_len);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        HopInfo hop;
        hop.hop = ttl;
        
        if (bytes_received < 0) {
            std::cout << ttl << "\t*\t\tRequest timed out" << std::endl;
            hop.ip_address = "*";
            hop.rtt = -1;
            hop.bandwidth = -1;
            hop.is_bottleneck = false;
        } else {
            // Calculate RTT
            double rtt = duration.count() / 1000.0; // Convert to milliseconds
            
            // Get IP address of the hop
            char from_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from.sin_addr, from_addr, sizeof(from_addr));
            
            // Estimate bandwidth
            double bandwidth = estimate_bandwidth(dest_addr, ttl);
            
            hop.ip_address = from_addr;
            hop.rtt = rtt;
            hop.bandwidth = bandwidth;
            hop.is_bottleneck = (bandwidth > 0 && bandwidth < 10); // Arbitrary threshold
            
            if (bandwidth > 0) {
                std::cout << ttl << "\t" << from_addr << "\t" << rtt << " ms\t\t" << bandwidth << " Mbps";
                
                // Identify potential bottlenecks
                if (hop.is_bottleneck) {
                    std::cout << "\n  [!] Potential bottleneck detected: low bandwidth (" << bandwidth << " Mbps)";
                }
                std::cout << std::endl;
            } else {
                std::cout << ttl << "\t" << from_addr << "\t" << rtt << " ms\t\tUnable to estimate bandwidth" << std::endl;
            }
            
            // Check if we reached the destination
            if (strcmp(from_addr, dest_addr) == 0) {
                std::cout << "Destination reached in " << ttl << " hops!" << std::endl;
                hop_info.push_back(hop);
                break;
            }
        }
        
        hop_info.push_back(hop);
        close(sock);
    }
    
    return hop_info;
}

// Calculate total bandwidth and find bottleneck
std::string calculate_network_stats(const std::vector<HopInfo>& hops) {
    std::ostringstream stats;
    
    stats << "\n--- Network Statistics ---\n";
    stats << "Total Hops: " << hops.size() << "\n";
    
    double total_rtt = 0;
    double min_bandwidth = std::numeric_limits<double>::max();

    for (const auto& hop : hops) {
        total_rtt += hop.rtt;
        if (hop.bandwidth < min_bandwidth) {
            min_bandwidth = hop.bandwidth;
        }
    }

    if (!hops.empty()) {
        stats << "Average RTT: " << (total_rtt / hops.size()) << " ms\n";
        stats << "Bottleneck Bandwidth: " << min_bandwidth << " Mbps\n";
    } else {
        stats << "No hops recorded.\n";
    }

    return stats.str(); // Return statistics as a string
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <destination> [max_hops] [timeout] [probes]" << std::endl;
        return 1;
    }
    
    const char *destination = argv[1];
    int max_hops = (argc > 2) ? atoi(argv[2]) : DEFAULT_MAX_HOPS;
    int timeout = (argc > 3) ? atoi(argv[3]) : DEFAULT_TIMEOUT;
    int probes = (argc > 4) ? atoi(argv[4]) : DEFAULT_PROBES;
    
    std::ofstream file("traceroute_output.txt");
    if (!file) {
        std::cerr << "Error: Could not open output file." << std::endl;
        return 1;
    }

    std::cout << "Traceroute to " << destination << ", " << max_hops << " hops max\n\n";
    // std::cout << "Hop\tIP Address\t\tRTT (ms)\t\tBandwidth (Mbps)\n";
    // std::cout << std::string(70, '-') << "\n";

    file << "Traceroute to " << destination << ", " << max_hops << " hops max\n\n";
    file << "Hop\tIP Address\t\tRTT (ms)\t\tBandwidth (Mbps)\n";
    file << std::string(70, '-') << "\n";

    std::vector<HopInfo> hops = traceroute(destination, max_hops, timeout, probes);

    for (size_t i = 0; i < hops.size(); ++i) {
        std::ostringstream hop_info;
        hop_info << (i + 1) << "\t" << hops[i].ip_address << "\t\t"
                 << hops[i].rtt << "\t\t" << hops[i].bandwidth << "\n";
        // std::cout << hop_info.str();
        file << hop_info.str();
    }

    std::string stats = calculate_network_stats(hops);
    std::cout << "\n" << stats;
    file << "\n" << stats;

    file.close();
    std::cout << "\nResults saved in 'traceroute_output.txt'" << std::endl;
    return 0;
}