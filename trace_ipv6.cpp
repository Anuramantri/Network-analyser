// NOTE: This is an extended version with IPv6 support.
// To compile: g++ -std=c++11 -o traceroute traceroute.cpp
// Run with sudo: sudo ./traceroute <destination>

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <fstream>
#include <sstream>


#define MAX_PACKET_SIZE 4096
#define DEFAULT_MAX_HOPS 30
#define DEFAULT_TIMEOUT 1
#define DEFAULT_PROBES 3

enum IPVersion {
    IPV4,
    IPV6
};

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

struct ICMPv6Packet {
    struct icmp6_hdr header;
    char data[MAX_PACKET_SIZE - sizeof(struct icmp6_hdr)];
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

int create_icmp_socket(IPVersion version) {
    int sock;
    if (version == IPV4) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    } else {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }

    if (sock < 0) {
        std::cerr << "Error creating socket. Root privileges required." << std::endl;
        exit(1);
    }

    return sock;
}

void create_icmp_packet(ICMPPacket *packet, int seq, int size) {
    memset(packet, 0, sizeof(ICMPPacket));
    packet->header.type = ICMP_ECHO;
    packet->header.code = 0;
    packet->header.un.echo.id = htons(getpid() & 0xFFFF);
    packet->header.un.echo.sequence = htons(seq);

    for (int i = 0; i < size - sizeof(struct icmphdr); i++) {
        packet->data[i] = 'x';
    }

    packet->header.checksum = 0;
    packet->header.checksum = calculate_checksum((unsigned short *)packet, size);
}

void create_icmpv6_packet(ICMPv6Packet *packet, int seq, int size) {
    memset(packet, 0, sizeof(ICMPv6Packet));
    packet->header.icmp6_type = ICMP6_ECHO_REQUEST;
    packet->header.icmp6_code = 0;
    packet->header.icmp6_id = htons(getpid() & 0xFFFF);
    packet->header.icmp6_seq = htons(seq);

    for (int i = 0; i < size - sizeof(struct icmp6_hdr); i++) {
        packet->data[i] = 'x';
    }

    // No need for checksum here, kernel calculates it
}

// Unified address resolver for IPv4/IPv6
bool resolve_address(const char *hostname, sockaddr_storage &addr, socklen_t &addr_len, IPVersion &ip_version, std::string &ip_str, int address_family) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_RAW;

    // Use the requested address family (AF_INET, AF_INET6)
    hints.ai_family = address_family;

    if (getaddrinfo(hostname, nullptr, &hints, &res) != 0 || res == nullptr) {
        return false;
    }

    if (res->ai_family == AF_INET) {
        ip_version = IPV4;
        addr_len = sizeof(sockaddr_in);
        memcpy(&addr, res->ai_addr, addr_len);
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((sockaddr_in *)res->ai_addr)->sin_addr, buffer, sizeof(buffer));
        ip_str = buffer;
    } else if (res->ai_family == AF_INET6) {
        ip_version = IPV6;
        addr_len = sizeof(sockaddr_in6);
        memcpy(&addr, res->ai_addr, addr_len);
        char buffer[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &((sockaddr_in6 *)res->ai_addr)->sin6_addr, buffer, sizeof(buffer));
        ip_str = buffer;
    } else {
        freeaddrinfo(res);
        return false;
    }

    freeaddrinfo(res);
    return true;
}


// Traceroute (unified for IPv4/IPv6)
std::vector<HopInfo> traceroute(const char *destination, int max_hops, int timeout, int probes, int address_family) {
    std::vector<HopInfo> hop_info;

    sockaddr_storage target_addr{};
    socklen_t addr_len;
    IPVersion version;
    std::string ip_str;

    if (!resolve_address(destination, target_addr, addr_len, version, ip_str, address_family)) {
        std::cerr << "Unable to resolve address." << std::endl;
        return hop_info;
    }

    std::cout << "Traceroute to " << destination << " (" << ip_str << "), " << max_hops << " hops max, " << probes << " probes per hop\n";
    std::cout << "Hop\tIP Address\t\tRTT 1\tRTT 2\tRTT 3 (ms)" << std::endl;
    std::cout << std::string(70, '-') << std::endl;

    bool destination_reached = false;

    for (int ttl = 1; ttl <= max_hops && !destination_reached; ttl++) {
        std::vector<double> rtts;
        std::string hop_ip = "*";

        std::cout << ttl << "\t";

        for (int probe = 0; probe < probes; ++probe) {
            int sock = create_icmp_socket(version);

            if (version == IPV4) {
                setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            } else {
                setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
            }

            struct timeval tv{timeout, 0};
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            auto start = std::chrono::high_resolution_clock::now();

            if (version == IPV4) {
                ICMPPacket packet;
                create_icmp_packet(&packet, ttl * 100 + probe, sizeof(struct icmphdr) + 56);  // unique seq
                sendto(sock, &packet, sizeof(struct icmphdr) + 56, 0, (sockaddr *)&target_addr, addr_len);
            } else {
                ICMPv6Packet packet;
                create_icmpv6_packet(&packet, ttl * 100 + probe, sizeof(struct icmp6_hdr) + 56);  // unique seq
                sendto(sock, &packet, sizeof(struct icmp6_hdr) + 56, 0, (sockaddr *)&target_addr, addr_len);
            }

            char buffer[MAX_PACKET_SIZE];
            sockaddr_storage recv_addr{};
            socklen_t recv_len = sizeof(recv_addr);

            int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr *)&recv_addr, &recv_len);
            auto end = std::chrono::high_resolution_clock::now();
            close(sock);

            double rtt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

            if (bytes < 0) {
                rtts.push_back(-1);
                std::cout << "*\t";
            } else {
                char addr_str[INET6_ADDRSTRLEN];
                if (version == IPV4) {
                    inet_ntop(AF_INET, &((sockaddr_in *)&recv_addr)->sin_addr, addr_str, sizeof(addr_str));
                } else {
                    inet_ntop(AF_INET6, &((sockaddr_in6 *)&recv_addr)->sin6_addr, addr_str, sizeof(addr_str));
                }

                hop_ip = addr_str;
                rtts.push_back(rtt);
                std::cout << std::fixed << std::setprecision(2) << rtt << "\t";

                if (hop_ip == ip_str) {
                    destination_reached = true;
                }
            }
        }

        std::cout << std::endl;

        // Add a single entry per hop with average RTT
        double avg_rtt = std::accumulate(rtts.begin(), rtts.end(), 0.0,
                                         [](double sum, double val) { return val >= 0 ? sum + val : sum; });
        int count = std::count_if(rtts.begin(), rtts.end(), [](double val) { return val >= 0; });

        HopInfo hop;
        hop.hop = ttl;
        hop.ip_address = hop_ip;
        hop.rtt = (count > 0) ? avg_rtt / count : -1;
        hop_info.push_back(hop);
    }

    if (destination_reached) {
        std::cout << "Destination reached!" << std::endl;
    } else {
        std::cout << "Destination not reached within " << max_hops << " hops." << std::endl;
    }

    return hop_info;
}

std::string calculate_network_stats(const std::vector<HopInfo> &hops) {
    std::ostringstream stats;

    stats << "Total Hops: " << hops.size() << "\n";
    double total_rtt = 0;
    double min_bandwidth = std::numeric_limits<double>::max();

    for (const auto &hop : hops) {
        if (hop.rtt > 0)
            total_rtt += hop.rtt;
    }

    if (!hops.empty()) {
        stats << "Average RTT: " << (total_rtt / hops.size()) << " ms\n";
    } else {
        stats << "No hops recorded.\n";
    }

    return stats.str();
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [-4|-6] <destination> [max_hops] [timeout] [probes]" << std::endl;
        return 1;
    }

    int address_family = AF_UNSPEC;
    int arg_index = 1;

    // Handle -4 or -6 flag
    if (strcmp(argv[1], "-4") == 0) {
        address_family = AF_INET;
        arg_index++;
    } else if (strcmp(argv[1], "-6") == 0) {
        address_family = AF_INET6;
        arg_index++;
    }

    if (argc <= arg_index) {
        std::cerr << "Usage: " << argv[0] << " [-4|-6] <destination> [max_hops] [timeout] [probes]" << std::endl;
        return 1;
    }

    const char *destination = argv[arg_index++];
    int max_hops = (argc > arg_index) ? atoi(argv[arg_index++]) : DEFAULT_MAX_HOPS;
    int timeout  = (argc > arg_index) ? atoi(argv[arg_index++]) : DEFAULT_TIMEOUT;
    int probes   = (argc > arg_index) ? atoi(argv[arg_index++]) : DEFAULT_PROBES;

    std::ofstream file("traceroute_output.txt");
    std::ofstream stat_file("stats.txt");

    if (!file || !stat_file) {
        std::cerr << "Error opening output files." << std::endl;
        return 1;
    }

    // Call traceroute with address family
    std::vector<HopInfo> hops = traceroute(destination, max_hops, timeout, probes, address_family);

    for (const auto &hop : hops) {
        file << hop.hop << "\t" << hop.ip_address << "\t\t" << hop.rtt << " ms\n";
    }

    stat_file << calculate_network_stats(hops);

    file.close();
    stat_file.close();

    return 0;
}
