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

// Structure to store hop information


struct UnexpectedHop {
    int hop_number;
    std::string expected_ip;
    std::string actual_ip;
    int probe_number;
};

// Global vector to store all unexpected hops
std::vector<UnexpectedHop> unexpected_hops;

// Improved bandwidth estimation using packet pair technique
std::pair<double, int> estimate_bandwidth(const char *dest_addr, const char *from_addr, int ttl) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (udp_sock < 0 || icmp_sock < 0) {
        std::cerr << "Socket creation failed. Root privileges needed for raw socket." << std::endl;
        return {-1, 0};
    }

    // Set TTL on UDP socket
    if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        std::cerr << "Failed to set TTL." << std::endl;
        close(udp_sock);
        close(icmp_sock);
        return {-1, 0};
    }

    // Set receive timeout on ICMP socket
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(33434); // Unused port
    inet_pton(AF_INET, dest_addr, &dest.sin_addr);

    int large_size = 1400;
    int valid_probes = 0;
    std::vector<double> bandwidths;

    for (int i = 0; i < 10; ++i) {
        char buffer1[large_size], buffer2[large_size];
        memset(buffer1, 'x', large_size);
        memset(buffer2, 'y', large_size);

        auto t1 = std::chrono::high_resolution_clock::now();
        sendto(udp_sock, buffer1, large_size, 0, (sockaddr*)&dest, sizeof(dest));
        auto t2 = std::chrono::high_resolution_clock::now();
        sendto(udp_sock, buffer2, large_size, 0, (sockaddr*)&dest, sizeof(dest));

        char recv_buf[MAX_PACKET_SIZE];
        sockaddr_in from;
        socklen_t from_len = sizeof(from);

        int recv_count = 0;
        std::chrono::high_resolution_clock::time_point icmp_time1, icmp_time2;

        while (recv_count < 2) {
            int bytes = recvfrom(icmp_sock, recv_buf, sizeof(recv_buf), 0, (sockaddr*)&from, &from_len);
            if (bytes > 0) {
                if (recv_count == 0) {
                    icmp_time1 = std::chrono::high_resolution_clock::now();
                } else {
                    icmp_time2 = std::chrono::high_resolution_clock::now();
                }
                recv_count++;
            } else {
                break;
            }
        }

        if (recv_count == 2) {
            auto interval_us = std::chrono::duration_cast<std::chrono::microseconds>(icmp_time2 - icmp_time1).count();
            if (interval_us > 0) {
                double bw_mbps = (large_size * 8.0) / interval_us;
                bandwidths.push_back(bw_mbps);
                valid_probes++;
            }
        }
    }

    close(udp_sock);
    close(icmp_sock);

    double final_bw = -1;
    if (bandwidths.size() >= 3) {
        std::sort(bandwidths.begin(), bandwidths.end());
        size_t n = bandwidths.size();
        final_bw = (n % 2 == 0) ? (bandwidths[n/2 - 1] + bandwidths[n/2]) / 2.0 : bandwidths[n/2];
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
            int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (udp_sock < 0 || icmp_sock < 0) {
                std::cerr << "Socket creation failed." << std::endl;
                continue;
            }

            setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            struct timeval tv = {timeout, 0};
            setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(33434 + ttl);  // Unique port per hop
            inet_pton(AF_INET, dest_addr, &dest.sin_addr);

            char send_buffer[] = "traceroute_probe";
            auto start = std::chrono::high_resolution_clock::now();
            sendto(udp_sock, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&dest, sizeof(dest));

            char recv_buffer[MAX_PACKET_SIZE];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            int bytes = recvfrom(icmp_sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&from, &from_len);
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

                outfile << "  Probe " << (probe + 1) << ": " << from_addr
                          << " | RTT: " << rtt << " ms"
                          << " | BW: " << (bw.first > 0 ? std::to_string(bw.first) + " Mbps" : "N/A")
                          << " | Successful probes(/10): " << bw.second;

                if (reply.is_bottleneck)
                outfile << "  [!] Bottleneck";
                outfile << std::endl;

                if (strcmp(from_addr, dest_addr) == 0) {
                    outfile << "Destination reached at hop " << ttl << std::endl;
                    all_hops.push_back(hop);
                    close(udp_sock);
                    close(icmp_sock);
                    return all_hops;
                }

            } else {
                outfile << "  Probe " << (probe + 1) << ": * Request timed out" << std::endl;
            }

            close(udp_sock);
            close(icmp_sock);
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
    outfile.close();
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