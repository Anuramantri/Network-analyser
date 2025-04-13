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
#include <cmath>
#include <limits>

#define MAX_PACKET_SIZE 1028
#define DEFAULT_MAX_HOPS 30
#define DEFAULT_TIMEOUT 3
#define DEFAULT_PROBES 3

// ICMP packet structure
struct ICMPPacket {
    struct icmphdr header;
    char data[MAX_PACKET_SIZE - sizeof(struct icmphdr)];
};


struct UnexpectedHop {
    int hop_number;
    std::string expected_ip;
    std::string actual_ip;
    int probe_number;
};

// Global vector to store all unexpected hops
std::vector<UnexpectedHop> unexpected_hops;

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

// Improved bandwidth estimation using packet pair technique

std::pair<double, int> estimate_bandwidth(const char *dest_addr, const char *from_addr, int ttl) {
    int sock = create_icmp_socket();
    if (sock < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        return {-1, 0};
    }

    // Set TTL
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        std::cerr << "Error setting TTL" << std::endl;
        close(sock);
        return {-1, 0};
    }

    // Destination setup
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_addr);

    int large_size = 1400;
    int num_probes = 10;
    std::vector<double> bandwidths;

    int valid_probes = 0;
    std::string expected_reply_ip = from_addr;

    for (int i = 0; i < num_probes; i++) {
        ICMPPacket packet1, packet2;
        create_icmp_packet(&packet1, i*2 + 1, large_size);
        create_icmp_packet(&packet2, i*2 + 2, large_size);

        if (sendto(sock, &packet1, large_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) continue;
        if (sendto(sock, &packet2, large_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) continue;

        char recv_buffer1[MAX_PACKET_SIZE], recv_buffer2[MAX_PACKET_SIZE];
        struct sockaddr_in from1, from2;
        socklen_t from_len1 = sizeof(from1), from_len2 = sizeof(from2);

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sock, &read_set);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        auto start_time = std::chrono::high_resolution_clock::now();

        if (select(sock + 1, &read_set, NULL, NULL, &timeout) <= 0) continue;
        if (recvfrom(sock, recv_buffer1, sizeof(recv_buffer1), 0, (struct sockaddr *)&from1, &from_len1) < 0) continue;

        auto first_arrival = std::chrono::high_resolution_clock::now();

        FD_ZERO(&read_set);
        FD_SET(sock, &read_set);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        if (select(sock + 1, &read_set, NULL, NULL, &timeout) <= 0) continue;
        if (recvfrom(sock, recv_buffer2, sizeof(recv_buffer2), 0, (struct sockaddr *)&from2, &from_len2) < 0) continue;

        auto second_arrival = std::chrono::high_resolution_clock::now();

        // Check if both replies came from expected address
        char buffer1[INET_ADDRSTRLEN], buffer2[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from1.sin_addr, buffer1, sizeof(buffer1));
        inet_ntop(AF_INET, &from2.sin_addr, buffer2, sizeof(buffer2));

        std::string reply_ip1 = buffer1;
        std::string reply_ip2 = buffer2;

        // std::cout << "Expected IP: " << expected_reply_ip << std::endl;
        // std::cout << "Reply IP 1: " << reply_ip1 << std::endl;
        // std::cout << "Reply IP 2: " << reply_ip2 << std::endl;

        if (reply_ip1 != expected_reply_ip || reply_ip2 != expected_reply_ip) {
            if (reply_ip1 != expected_reply_ip) {
                unexpected_hops.push_back({
                    ttl,                // hop number
                    expected_reply_ip,  // expected IP
                    reply_ip1,          // actual IP received
                    i*2 + 1             // probe number
                });
            }
            
            if (reply_ip2 != expected_reply_ip) {
                unexpected_hops.push_back({
                    ttl,                // hop number
                    expected_reply_ip,  // expected IP
                    reply_ip2,          // actual IP received
                    i*2 + 2             // probe number
                });
            }
            continue;
        }

        // Time difference in microseconds
        auto interval = std::chrono::duration_cast<std::chrono::microseconds>(
            second_arrival - first_arrival).count();

        if (interval <= 0) continue;

        double bw = (large_size * 8.0) / interval;
        bandwidths.push_back(bw);
        valid_probes++;
    }

    close(sock);

    double final_bw = -1;
    if (bandwidths.size() >= 3) {
        std::sort(bandwidths.begin(), bandwidths.end());
        if (bandwidths.size() % 2 == 0) {
            final_bw = (bandwidths[bandwidths.size()/2 - 1] + bandwidths[bandwidths.size()/2]) / 2.0;
        } else {
            final_bw = bandwidths[bandwidths.size()/2];
        }
    } else if (!bandwidths.empty()) {
        final_bw = std::accumulate(bandwidths.begin(), bandwidths.end(), 0.0) / bandwidths.size();
    }

    return {final_bw, valid_probes};
}

struct ProbeReply {
    std::string ip_address;
    double rtt;
    std::pair<double, int> bandwidth;
    bool is_bottleneck;
};

struct HopProbes {
    int ttl;
    std::vector<ProbeReply> replies;
};

std::vector<HopProbes> traceroute(const char *destination, int max_hops, int timeout, int probes_per_hop = DEFAULT_PROBES) {
    std::vector<HopProbes> all_hops;

    std::ofstream outfile("traceroute_output.txt");
    if (!outfile.is_open()) {
        std::cerr << "Error: Could not open traceroute_output.txt\n";
        return all_hops;
    }

    struct hostent *host = gethostbyname(destination);
    if (!host) {
        std::cerr << "Unknown host: " << destination << std::endl;
        return all_hops;
    }

    char *temp_addr = inet_ntoa(*(struct in_addr *)host->h_addr);
    char dest_addr[INET_ADDRSTRLEN];
    strcpy(dest_addr, temp_addr);
    outfile << "Traceroute to " << destination << " (" << dest_addr << "), " << max_hops << " hops max" << std::endl;
    outfile << std::string(70, '-') << std::endl;

    for (int ttl = 1; ttl <= max_hops; ttl++) {
        HopProbes hop;
        hop.ttl = ttl;
        std::vector<double> rtts;
        std::vector<double> bws;

        outfile << "Hop " << ttl << ":" << std::endl;

        for (int probe = 0; probe < probes_per_hop; probe++) {
            int sock = create_icmp_socket();

            setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            struct timeval tv = {timeout, 0};
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = inet_addr(dest_addr);

            ICMPPacket packet;
            create_icmp_packet(&packet, ttl, sizeof(struct icmphdr) + 56);

            auto start = std::chrono::high_resolution_clock::now();
            sendto(sock, &packet, sizeof(struct icmphdr) + 56, 0, (struct sockaddr *)&dest, sizeof(dest));

            char recv_buffer[MAX_PACKET_SIZE];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);

            int bytes = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&from, &from_len);
            auto end = std::chrono::high_resolution_clock::now();

            if (bytes > 0) {
                char from_addr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from.sin_addr, from_addr, sizeof(from_addr));

                double rtt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
                std::pair<double, int> bw = estimate_bandwidth(dest_addr, from_addr, ttl);

                ProbeReply reply = {
                    .ip_address = from_addr,
                    .rtt = rtt,
                    .bandwidth = bw,
                    .is_bottleneck = (bw.first > 0 && bw.first < 10)
                };
                
                hop.replies.push_back(reply);
                rtts.push_back(rtt);
                if (bw.first > 0) bws.push_back(bw.first);
                int successful_probes = bw.second;
                outfile << "  Probe " << (probe + 1) << ": " << from_addr
                          << " | RTT: " << rtt << " ms"
                          << " | BW: " << (bw.first > 0 ? std::to_string(bw.first) + " Mbps" : "N/A")
                          << " | Successful probes(/10):"<<successful_probes;

                if (reply.is_bottleneck)
                outfile << "  [!] Bottleneck";
                outfile << std::endl;
                // std::cout <<"heyy"<< from_addr <<dest_addr<< std::endl;
                if (strcmp(from_addr, dest_addr) == 0) {
                    outfile << "Destination reached at hop " << ttl << std::endl;
                    all_hops.push_back(hop);
                    return all_hops;
                }
            } else {
                outfile << "  Probe " << (probe + 1) << ": * Request timed out" << std::endl;
            }

            close(sock);
        }

        // --- Per-hop stats ---
        if (!rtts.empty()) {
            double rtt_avg = std::accumulate(rtts.begin(), rtts.end(), 0.0) / rtts.size();
            double rtt_jitter = 0.0;
            for (auto rtt : rtts) rtt_jitter += (rtt - rtt_avg) * (rtt - rtt_avg);
            rtt_jitter = std::sqrt(rtt_jitter / rtts.size());

            double bw_avg = !bws.empty() ? std::accumulate(bws.begin(), bws.end(), 0.0) / bws.size() : -1;

            outfile << "  [Stats] Avg RTT: " << rtt_avg << " ms | Jitter: " << rtt_jitter << " ms"
                      << " | Avg BW: " << (bw_avg > 0 ? std::to_string(bw_avg) + " Mbps" : "N/A") << std::endl;
        }

        all_hops.push_back(hop);
        outfile << std::string(70, '-') << std::endl;
    }

    return all_hops;
}


std::string calculate_network_stats(const std::vector<HopProbes>& hops) {
    std::ostringstream stats;

    stats << "Total Hops: " << hops.size() << "\n";

    std::vector<double> all_rtts;
    std::vector<double> all_bandwidths;

    for (const auto& hop : hops) {
        for (const auto& reply : hop.replies) {
            if (reply.rtt > 0)
                all_rtts.push_back(reply.rtt);
            if (reply.bandwidth.first > 0)
                all_bandwidths.push_back(reply.bandwidth.first);
        }
    }

    if (!all_rtts.empty()) {
        double total_rtt = std::accumulate(all_rtts.begin(), all_rtts.end(), 0.0);
        double avg_rtt = total_rtt / all_rtts.size();
        stats << "Average RTT: " << avg_rtt << " ms\n";
    } else {
        stats << "No valid RTT data.\n";
    }

    if (!all_bandwidths.empty()) {
        double total_bw = std::accumulate(all_bandwidths.begin(), all_bandwidths.end(), 0.0);
        double avg_bw = total_bw / all_bandwidths.size();
        double min_bw = *std::min_element(all_bandwidths.begin(), all_bandwidths.end());

        stats << "Average Bandwidth: " << avg_bw << " Mbps\n";
        stats << "Effective Bandwidth (Bottleneck): " << min_bw << " Mbps\n";
    } else {
        stats << "No valid Bandwidth data.\n";
    }

    return stats.str();
}

void print_unexpected_hops() {
    if (unexpected_hops.empty()) {
        std::cout << "No unexpected hops detected." << std::endl;
        return;
    }
    
    std::cout << "Unexpected IPs encountered during traceroute:" << std::endl;
    std::cout << std::string(60, '-') << std::endl;
    std::cout << "Hop\tExpected IP\t\tActual IP\t\tProbe" << std::endl;
    std::cout << std::string(60, '-') << std::endl;
    
    for (const auto& hop : unexpected_hops) {
        std::cout << hop.hop_number << "\t"
                  << hop.expected_ip << "\t\t"
                  << hop.actual_ip << "\t\t"
                  << hop.probe_number << std::endl;
    }
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

    std::vector<HopProbes> hops = traceroute(destination, max_hops, timeout, probes);   

    std::ofstream stat_file("stats.txt");
    std::string stats = calculate_network_stats(hops);
    stat_file<< stats;
    stat_file.close();
    print_unexpected_hops();
    
    return 0;
}
