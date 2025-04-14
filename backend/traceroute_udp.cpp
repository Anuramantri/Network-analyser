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
#include <map>


#define MAX_PACKET_SIZE 1028
#define DEFAULT_MAX_HOPS 30
#define DEFAULT_TIMEOUT 3
#define DEFAULT_PROBES 3

// Structure to store hop information
struct HopInfo {
    int hop;
    std::string ip_address;
    double rtt;
    double bandwidth;
    bool is_bottleneck;
};

// To store mismatched IP hops (planned vs. actual).
struct UnexpectedHop {
    int hop_number;
    std::string expected_ip;
    std::string actual_ip;
    int probe_number;
};

// Represents the result of a single probe sent to a specific TTL (hop)
struct ProbeReply {
    std::string ip_address;
    double rtt;
    std::pair<double, int> bandwidth;
    bool is_bottleneck;
};

// Represents all probe replies collected for a given TTL (hop)
struct HopProbes {
    int ttl;
    std::vector<ProbeReply> replies;
};

// Global vector to store all unexpected hops
std::vector<UnexpectedHop> unexpected_hops;

// Function to get current timestamp in a readable format
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

// Function to track and update usage count for destinations
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

// Estimates the available bandwidth between source and destination at a specific TTL
// Returns a pair: <estimated bandwidth in Mbps, number of valid samples>
std::pair<double, int> estimate_bandwidth(const char *dest_addr, const char *from_addr, int ttl) {

    // Create UDP and ICMP sockets
    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    // Ensure sockets are created successfully
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

    // Set a 1-second receive timeout on the ICMP socket
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Prepare destination address structure
    sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(33434); // Arbitrary high-numbered unused port
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

// Traceroute function that sends UDP packets with increasing TTL values to map the path to the destination.
// It also estimates bandwidth and detects bottlenecks at each hop.
std::vector<HopProbes> traceroute(const char *destination, int max_hops, int timeout, int probes_per_hop = DEFAULT_PROBES) {
    std::vector<HopProbes> all_hops;

    // Resolve destination hostname to IP address
    struct hostent *host = gethostbyname(destination);
    if (!host) {
        std::cerr << "Unknown host: " << destination << std::endl;
        return all_hops;
    }
    // Convert IP to string
    char *temp_addr = inet_ntoa(*(struct in_addr *)host->h_addr);
    char dest_addr[INET_ADDRSTRLEN];
    strcpy(dest_addr, temp_addr);

    std::cout << "Traceroute to " << destination << " (" << dest_addr << "), " << max_hops << " hops max" << std::endl;
    std::cout << std::string(70, '-') << std::endl;

    // Iterate over TTL values from 1 to max_hops
    for (int ttl = 1; ttl <= max_hops; ttl++) {
        HopProbes hop;
        hop.ttl = ttl;
        std::vector<double> rtts;
        std::vector<double> bws;

        std::cout << "Hop " << ttl << ":" << std::endl;

        // Send multiple probes per hop
        for (int probe = 0; probe < probes_per_hop; probe++) {
            int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (udp_sock < 0 || icmp_sock < 0) {
                std::cerr << "Socket creation failed." << std::endl;
                continue;
            }

            // Set TTL on UDP socket
            setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

            // Set timeout on ICMP socket
            struct timeval tv = {timeout, 0};
            setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            // Set up destination address
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(33434 + ttl);  // Unique port per hop
            inet_pton(AF_INET, dest_addr, &dest.sin_addr);

            // Send UDP packet
            char send_buffer[] = "traceroute_probe";
            auto start = std::chrono::high_resolution_clock::now();
            sendto(udp_sock, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&dest, sizeof(dest));

            // Receive ICMP reply
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

                std::cout << "  Probe " << (probe + 1) << ": " << from_addr
                          << " | RTT: " << rtt << " ms"
                          << " | BW: " << (bw.first > 0 ? std::to_string(bw.first) + " Mbps" : "N/A")
                          << " | Successful probes(/10): " << bw.second;

                if (reply.is_bottleneck)
                    std::cout << "  [!] Bottleneck";
                std::cout << std::endl;

                // Stop if we reached the destination
                if (strcmp(from_addr, dest_addr) == 0) {
                    std::cout << "Destination reached at hop " << ttl << std::endl;
                    all_hops.push_back(hop);
                    close(udp_sock);
                    close(icmp_sock);
                    return all_hops;
                }

            } else {
                std::cout << "  Probe " << (probe + 1) << ": * Request timed out" << std::endl;
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

            std::cout << "  [Stats] Avg RTT: " << rtt_avg << " ms | Jitter: " << rtt_jitter << " ms"
                      << " | Avg BW: " << (bw_avg > 0 ? std::to_string(bw_avg) + " Mbps" : "N/A") << std::endl;
        }

        all_hops.push_back(hop);
        std::cout << std::string(70, '-') << std::endl;
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

void print_unexpected_hops(std::ostream& out) {
    if (unexpected_hops.empty()) {
        out << "No unexpected hops detected." << std::endl;
        return;
    }

    out << "Unexpected IPs encountered during traceroute:" << std::endl;
    out << std::string(60, '-') << std::endl;
    out << "Hop\tExpected IP\t\tActual IP\t\tProbe" << std::endl;
    out << std::string(60, '-') << std::endl;

    for (const auto& hop : unexpected_hops) {
        out << hop.hop_number << "\t"
            << hop.expected_ip << "\t\t"
            << hop.actual_ip << "\t\t"
            << hop.probe_number << std::endl;
    }
}


// Assume the following symbols are declared elsewhere:
// - DEFAULT_MAX_HOPS, DEFAULT_TIMEOUT, DEFAULT_PROBES
// - struct Reply { std::string ip_address; double rtt; std::pair<double,int> bandwidth; };
// - struct HopProbes { int ttl; std::vector<Reply> replies; };
// - Functions: get_and_update_usage_count(), get_timestamp(), traceroute(), print_unexpected_hops()

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
    
    // Get usage count and current timestamp
    int usage_count = get_and_update_usage_count(hostname);
    std::string timestamp = get_timestamp();
    
    // Run the traceroute and get hops information
    std::vector<HopProbes> hops = traceroute(destination, max_hops, timeout, probes);
    
    // Open the output files
    std::ofstream text_file("traceroute_output.txt");
    std::ofstream csv_file("traceroute_udp.csv", std::ios::app); // Append mode
    
    if (!text_file || !csv_file) {
        std::cerr << "Error: Could not open output files." << std::endl;
        return 1;
    }
    
    // Write CSV header if file is empty
    csv_file.seekp(0, std::ios::end);
    if (csv_file.tellp() == 0) {
        csv_file << "usage_count,destination_ip,hostname,timestamp,hop,hop_ip,rtt_ms,bandwidth_mbps" << std::endl;
    }
    
    // Variables for overall statistics
    std::vector<double> all_rtts;
    std::vector<double> all_bandwidths;
    double min_bandwidth = std::numeric_limits<double>::max();
    std::string bottleneck_hop_ip;
    int bottleneck_hop_num = 0;
    bool destination_reached = false;
    int final_hop = 0;
    
    // Build consolidated output in an output stream
    std::ostringstream output;
    output << "Traceroute to " << destination << " (" << dest_ip << "), " << max_hops << " hops max" << std::endl;
    output << std::string(70, '-') << std::endl;
    
    // Process each hop, write once to the ostringstream and CSV file
    for (const auto& hop : hops) {
        output << "Hop " << hop.ttl << ":" << std::endl;
        final_hop = hop.ttl;
    
        std::vector<double> hop_rtts;
        std::vector<double> hop_bws;
        std::string hop_ip;
    
        int probe_count = 0;
        for (const auto& reply : hop.replies) {
            probe_count++;
            // If no response for this probe, print timeout message
            if (reply.ip_address.empty()) {
                output << "  Probe " << probe_count << ": * Request timed out" << std::endl;
                continue;
            }
    
            // Use the first valid IP address for the hop
            if (hop_ip.empty())
                hop_ip = reply.ip_address;
    
            if (reply.rtt > 0) {
                hop_rtts.push_back(reply.rtt);
                all_rtts.push_back(reply.rtt);
            }
    
            if (reply.bandwidth.first > 0) {
                hop_bws.push_back(reply.bandwidth.first);
                all_bandwidths.push_back(reply.bandwidth.first);
    
                // Check for possible bottleneck
                if (reply.bandwidth.first < min_bandwidth) {
                    min_bandwidth = reply.bandwidth.first;
                    bottleneck_hop_ip = reply.ip_address;
                    bottleneck_hop_num = hop.ttl;
                }
            }
    
            output << "  Probe " << probe_count << ": " << reply.ip_address 
                   << " | RTT: " << reply.rtt << " ms"
                   << " | BW: " << (reply.bandwidth.first > 0 ? std::to_string(reply.bandwidth.first) + " Mbps" : "N/A")
                   << " | Successful probes(/10):" << reply.bandwidth.second << std::endl;
    
            // Check if the destination is reached
            if (reply.ip_address == dest_ip)
                destination_reached = true;
        }
    
        // Print hop statistics if RTT data exists
        if (!hop_rtts.empty()) {
            double avg_rtt = std::accumulate(hop_rtts.begin(), hop_rtts.end(), 0.0) / hop_rtts.size();
            double sum_squared_diff = 0.0;
            for (const auto& rtt : hop_rtts) {
                double diff = rtt - avg_rtt;
                sum_squared_diff += diff * diff;
            }
            double jitter = std::sqrt(sum_squared_diff / hop_rtts.size());
            double avg_bw = hop_bws.empty() ? 0.0 : std::accumulate(hop_bws.begin(), hop_bws.end(), 0.0) / hop_bws.size();
            output << "  [Stats] Avg RTT: " << avg_rtt << " ms | Jitter: " << jitter 
                   << " ms | Avg BW: " << (hop_bws.empty() ? "N/A" : std::to_string(avg_bw) + " Mbps") << std::endl;
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
    
        output << std::string(70, '-') << std::endl;
    }
    
    if (destination_reached) {
        output << "Destination reached at hop " << final_hop << "." << std::endl;
    } else {
        output << "Traceroute completed with " << hops.size() << " hops." << std::endl;
    }
    
    // Write the consolidated output once to the text file and to the console
    std::string consolidated_output = output.str();
    text_file << consolidated_output;
    
   
    csv_file.close();
    
    // Calculate overall statistics
    double overall_avg_rtt = all_rtts.empty() ? 0.0 : std::accumulate(all_rtts.begin(), all_rtts.end(), 0.0) / all_rtts.size();
    double overall_avg_bw = all_bandwidths.empty() ? 0.0 : std::accumulate(all_bandwidths.begin(), all_bandwidths.end(), 0.0) / all_bandwidths.size();
    
    std::ofstream stat_file("stats.txt");
    if (stat_file) {
        stat_file << "Total Hops: " << hops.size() << std::endl;
        if (!all_rtts.empty()) {
            stat_file << "Average RTT: " << overall_avg_rtt << " ms" << std::endl;
        }
        if (!all_bandwidths.empty()) {
            stat_file << "Average Bandwidth: " << overall_avg_bw << " Mbps" << std::endl;
        }
        if (min_bandwidth != std::numeric_limits<double>::max()) {
            stat_file << "Effective Bandwidth (Bottleneck): " << min_bandwidth << " Mbps" << std::endl;
        }
        stat_file.close();
    }
    
    // If print_unexpected_hops() prints additional hop details that duplicate
    // information, consider removing or modifying it.
    // Write unexpected hops info to the same file
    print_unexpected_hops(text_file);

    // Also optionally print to the console
    print_unexpected_hops(std::cout);
    text_file.close();
    
    std::cout << "Results saved to traceroute_output.txt, traceroute_udp.csv, and stats.txt" << std::endl;
    
    return 0;
}


