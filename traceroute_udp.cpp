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


struct UnexpectedHop {
    int hop_number;
    std::string expected_ip;
    std::string actual_ip;
    int probe_number;
};

// Global vector to store all unexpected hops
std::vector<UnexpectedHop> unexpected_hops;

//function to get time stamp
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
//function to load and update usage count
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



std::tuple<double, int, double,double> estimate_bandwidth(const char *dest_addr, const char *from_addr, int ttl) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    // Ensure sockets are created successfully
    if (udp_sock < 0 || icmp_sock < 0) {
        std::cerr << "Socket creation failed. Root privileges needed for raw socket." << std::endl;
        return {-1, 0, -1,-1};
    }

    // Set TTL
    if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        std::cerr << "Failed to set TTL." << std::endl;
        close(udp_sock);
        close(icmp_sock);
        return {-1, 0, -1,-1};
    }

    // Set a 1-second receive timeout on the ICMP socket
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Destination setup
    sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(33434); 
    inet_pton(AF_INET, dest_addr, &dest.sin_addr);

    int large_size = 1400;
    int num_probes = 10;
   std::vector<double> bandwidths;
    std::vector<double> intervals;
    std::vector<double> rtts;

    int valid_probes = 0;
    std::string expected_reply_ip = from_addr;

    for (int i = 0; i < num_probes; i++) {
        char packet1[large_size] = {0};
        char packet2[large_size] = {0};

        if (sendto(udp_sock, packet1, large_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) continue;
        if (sendto(udp_sock, packet2, large_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) continue;

        char recv_buffer1[MAX_PACKET_SIZE], recv_buffer2[MAX_PACKET_SIZE];
        struct sockaddr_in from1, from2;
        socklen_t from_len1 = sizeof(from1), from_len2 = sizeof(from2);

        fd_set read_set;
        FD_ZERO(&read_set );
        FD_SET(icmp_sock, &read_set);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        auto start_time = std::chrono::high_resolution_clock::now();

        if (select(icmp_sock + 1, &read_set, NULL, NULL, &timeout) <= 0) continue;
        if (recvfrom(icmp_sock, recv_buffer1, sizeof(recv_buffer1), 0, (struct sockaddr *)&from1, &from_len1) < 0) continue;

        auto first_arrival = std::chrono::high_resolution_clock::now();

        FD_ZERO(&read_set);
        FD_SET(icmp_sock, &read_set);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        if (select(icmp_sock + 1, &read_set, NULL, NULL, &timeout) <= 0) continue;
        if (recvfrom(icmp_sock, recv_buffer2, sizeof(recv_buffer2), 0, (struct sockaddr *)&from2, &from_len2) < 0) continue;

        auto second_arrival = std::chrono::high_resolution_clock::now();

        // Check if both replies came from expected address
        char buffer1[INET_ADDRSTRLEN], buffer2[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from1.sin_addr, buffer1, sizeof(buffer1));
        inet_ntop(AF_INET, &from2.sin_addr, buffer2, sizeof(buffer2));

        std::string reply_ip1 = buffer1;
        std::string reply_ip2 = buffer2;

        if (reply_ip1 != expected_reply_ip || reply_ip2 != expected_reply_ip) {
            if (reply_ip1 != expected_reply_ip) {
                unexpected_hops.push_back({
                    ttl, expected_reply_ip, reply_ip1, i * 2 + 1
                });
            }
            if (reply_ip2 != expected_reply_ip) {
                unexpected_hops.push_back({
                    ttl, expected_reply_ip, reply_ip2, i * 2 + 2
                });
            }
            continue;
        }

        auto interval = std::chrono::duration_cast<std::chrono::microseconds>(
            second_arrival - first_arrival).count();

        auto rtt = std::chrono::duration_cast<std::chrono::microseconds>(
            first_arrival - start_time).count();
        
        if (interval <= 0) continue;

        rtts.push_back(rtt);
        intervals.push_back(interval);

        double bw = (large_size * 8.0) / interval;
        bandwidths.push_back(bw);
        valid_probes++;
    }

    close(udp_sock);
    close(icmp_sock);

    double jitter = -1;

    if (intervals.size() >= 2) {
        double sum_diff_squared = 0.0;
        for (size_t i = 1; i < intervals.size(); ++i) {
            sum_diff_squared += std::pow(intervals[i] - intervals[i - 1], 2);  // Squaring the difference
        }
        jitter = std::sqrt(sum_diff_squared / (intervals.size() - 1));  // Taking the square root for standard deviation

    }

    jitter /= 1000.0; // in milliseconds

    double avg_rtt = std::accumulate(rtts.begin(), rtts.end(), 0.0) / rtts.size();
    avg_rtt /= 1000.0; // in milliseconds

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

    return {final_bw, valid_probes, jitter,avg_rtt};
}

struct ProbeReply {
    std::string ip_address;
    double rtt;
    double bandwidth;
    int num_probes;
    double jitter;
    double avg_rtt;
};

struct HopProbes {
    int ttl;
    std::vector<ProbeReply> replies;
};

std::vector<HopProbes> traceroute(const char *destination, int max_hops, int timeout, int probes_per_hop = DEFAULT_PROBES) {
    std::vector<HopProbes> all_hops;

    struct hostent *host = gethostbyname(destination);
    if (!host) {
        std::cerr << "Unknown host: " << destination << std::endl;
        return all_hops;
    }
    char dest_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, host->h_addr, dest_addr, sizeof(dest_addr));


    bool reached = false;
    for (int ttl = 1; ttl <= max_hops; ttl++) {
        HopProbes hop;
        hop.ttl = ttl;

        for (int probe = 0; probe < probes_per_hop; probe++) {
            // Create a UDP socket for sending
            int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (send_sock < 0) {
                perror("send socket");
                continue;
            }

            // Create raw socket to receive ICMP
            int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (recv_sock < 0) {
                perror("recv socket");
                close(send_sock);
                continue;
            }

            // Set TTL for outgoing UDP packet
            setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

            struct timeval tv = {timeout, 0};
            setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            // Setup destination
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = inet_addr(dest_addr);
            dest.sin_port = htons(33434 + ttl + probe);  // unique high port

            // Send UDP packet
            auto start = std::chrono::high_resolution_clock::now();
            sendto(send_sock, "Hello", 5, 0, (struct sockaddr *)&dest, sizeof(dest));

            // Wait for ICMP reply
            char recv_buffer[MAX_PACKET_SIZE];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);

            int bytes = recvfrom(recv_sock, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&from, &from_len);
            auto end = std::chrono::high_resolution_clock::now();

            if (bytes > 0) {
                char from_addr[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, &from.sin_addr, from_addr, sizeof(from_addr))) {
                    perror("inet_ntop");
                    continue;
                }

                inet_ntop(AF_INET, &from.sin_addr, from_addr, sizeof(from_addr));

                double rtt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
                std::tuple<double, int, double,double> bw = estimate_bandwidth(dest_addr, from_addr, ttl);

                ProbeReply reply = {
                    .ip_address = from_addr,
                    .rtt = rtt,
                    .bandwidth = std::get<0>(bw),
                    .num_probes = std::get<1>(bw),
                    .jitter = std::get<2>(bw),
                    .avg_rtt = std::get<3>(bw)
                };

                hop.replies.push_back(reply);

                if (std::string(from_addr) == std::string(dest_addr)) {
                    reached = true;
                }
            }

            close(send_sock);
            close(recv_sock);
        }

        all_hops.push_back(hop);
        if (reached) break;
    }

    return all_hops;
}



void calculate_network_stats(const std::vector<HopProbes>& hops) {
    std::ofstream stats("stats.txt");
    if (!stats) {
        std::cerr << "Error: Could not open stats file." << std::endl;
        return;
    }

    stats << "Total Hops: " << hops.size() << "\n";

    std::vector<double> all_rtts;
    std::vector<double> all_bandwidths;
    std::vector<double> all_jitter;
    double min_bandwidth = std::numeric_limits<double>::max();
    int bottleneck_hop_num = -1;
    std::string bottleneck_hop_ip = "N/A";

    for (const auto& hop : hops) {
        for (const auto& reply : hop.replies) {
            if (reply.rtt > 0)
                all_rtts.push_back(reply.rtt);
            if (reply.bandwidth > 0){
                all_bandwidths.push_back(reply.bandwidth);
                if(reply.bandwidth < min_bandwidth) {
                    min_bandwidth = reply.bandwidth;
                    bottleneck_hop_num = hop.ttl;
                    bottleneck_hop_ip = reply.ip_address;
                }
            }
            if(reply.jitter > 0)
                all_jitter.push_back(reply.jitter);
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
        if (min_bandwidth != std::numeric_limits<double>::max()) {
            stats << "Instantaneous Bottleneck Link: Hop " << bottleneck_hop_num << " (" << bottleneck_hop_ip 
                      << ") with Effective Bandwidth: " << min_bandwidth << " Mbps" << std::endl;
        }
    } else {
        stats << "No valid Bandwidth data.\n";
    }
    if(!all_jitter.empty()) {
        double total_jitter = std::accumulate(all_jitter.begin(), all_jitter.end(), 0.0);
        double avg_jitter = total_jitter / all_jitter.size();
        stats << "Average Jitter: " << avg_jitter << " ms\n";
    } else {
        stats << "No valid Jitter data.\n";
    }

    stats.close();
}

void print_unexpected_hops() {

    std::ofstream out("unexpected_hops.txt");
    if (!out) {
        std::cerr << "Error: Could not open output file." << std::endl;
        return;
    }

    if (unexpected_hops.empty()) {
        return;
    }

    out << "Unexpected IPs encountered during bandwidth estimation:" << std::endl;
    out << std::string(60, '-') << std::endl;
    out << "Hop\tExpected IP\t\tActual IP\t\tProbe" << std::endl;
    out << std::string(60, '-') << std::endl;

    for (const auto& hop : unexpected_hops) {
        out << hop.hop_number << "\t"
            << hop.expected_ip << "\t\t"
            << hop.actual_ip << "\t\t"
            << hop.probe_number << std::endl;
    }
    out.close();
    return;
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
    
    // Resolve hostname and IP address
    struct hostent *host = gethostbyname(destination);
    if (!host) {
        std::cerr << "Unknown host: " << destination << std::endl;
        return 1;
    }
    
    std::string hostname = destination;
    std::string dest_ip = inet_ntoa(*(struct in_addr *)host->h_addr);
    
    int usage_count = get_and_update_usage_count(hostname);
    std::string timestamp = get_timestamp();
    
    std::vector<HopProbes> hops = traceroute(destination, max_hops, timeout, probes);
    
    std::ofstream output("traceroute_output.txt");
    std::ofstream csv_file("traceroute_icmp.csv", std::ios::app); 
    
    if (!output || !csv_file) {
        std::cerr << "Error: Could not open output files." << std::endl;
        return 1;
    }
    
    // Write CSV header if file is empty
    csv_file.seekp(0, std::ios::end);
    if (csv_file.tellp() == 0) {
        csv_file << "usage_count,destination_ip,hostname,timestamp,hop,hop_ip,rtt_ms,bandwidth_mbps" << std::endl;
    }
    
    
    std::string bottleneck_hop_ip;
    int bottleneck_hop_num = 0;
    bool destination_reached = false;
    int final_hop = 0;
    std::vector<std::tuple<int, std::string, double>> hop_avg_bw;
    
    output << "Traceroute to " << destination << " (" << dest_ip << "), " << max_hops << " hops max" << "\n";
    output << std::string(70, '-') << "\n";
    
    // Process each hop, write once to the text and CSV file
    for (const auto& hop : hops) {
        output << "Hop " << hop.ttl << ":" << "\n";
        final_hop = hop.ttl;
    
        std::vector<double> hop_rtts;
        std::vector<double> hop_bws;
        std::string hop_ip;
    
        int probe_count = 0;
        for (const auto& reply : hop.replies) {
            probe_count++;
            // If no response for this probe, print timeout message
            if (reply.ip_address.empty()) {
                output << "  Probe " << probe_count << ": * Request timed out" << "\n";
                continue;
            }
    
            // Use the first valid IP address for the hop // CHANGE THIS 
            if (hop_ip.empty())
                hop_ip = reply.ip_address;
    
            if (reply.rtt > 0) {
                hop_rtts.push_back(reply.rtt);
            }
    
    
            output << "  Probe " << probe_count << ": " << reply.ip_address 
                   << " | RTT: " << reply.rtt << " ms"
                   << " | BW: " << (reply.bandwidth > 0 ? std::to_string(reply.bandwidth) + " Mbps" : "N/A")
                   << " | Jitter: " << (reply.jitter > 0 ? std::to_string(reply.jitter) + " ms" : "N/A")
                   << " | Average RTT:" << (reply.avg_rtt > 0 ? std::to_string(reply.avg_rtt) + " ms" : "N/A") << "\n"
                   << " | Successful probes(/10):" << reply.num_probes << "\n";
    
            // Check if the destination is reached
            if (reply.ip_address == dest_ip)
                destination_reached = true;
        }

        for (int i = probe_count + 1; i <= 3; ++i) {
            output << "  Probe " << i << ": * Request timed out" << "\n";
        }
        
        // Write hop data to CSV if valid IP exists
        if (!hop_ip.empty()) {
            double avg_rtt = hop_rtts.empty() ? 0.0 : std::accumulate(hop_rtts.begin(), hop_rtts.end(), 0.0) / hop_rtts.size();
            double avg_bw = hop_bws.empty() ? 0.0 : std::accumulate(hop_bws.begin(), hop_bws.end(), 0.0) / hop_bws.size();
            csv_file << usage_count << ","
                     << dest_ip << ","
                     << hostname << ","
                     << timestamp << ","
                     << hop.ttl << ","
                     << hop_ip << ","
                     << (!hop_rtts.empty() ? std::to_string(avg_rtt) : "N/A") << ","
                     << (!hop_bws.empty() ? std::to_string(avg_bw) : "N/A") << std::endl;
        }
    
        output << std::string(70, '-') << "\n";
    }
    
    if (destination_reached) {
        output << "Destination reached at hop " << final_hop << "." << "\n";
    } else {
        output << "Traceroute completed with " << hops.size() << " hops." << "\n";
    }
    
    

    output.close();
    csv_file.close();

    calculate_network_stats(hops);
    print_unexpected_hops();
    
    std::cout << "Results saved to traceroute_output.txt, traceroute_icmp.csv, and stats.txt" << std::endl;
    
    return 0;
}

