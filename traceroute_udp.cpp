#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <chrono>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <cmath>
#include <iomanip>
#include <ctime>
#include <map>
#include <vector>
#include <numeric>
#include <limits>
#include <algorithm>

#define MAX_HOPS 30
#define PORT 33434
#define TIMEOUT_SEC 3
#define PACKET_SIZE 60  // bytes
#define NUM_PAIRS 5     // number of UDP packet pairs (probes) per hop

// Calculate RTT in milliseconds
double calculateRTT(auto start, auto end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

// Load usage history from CSV
std::map<std::string, int> loadUsageHistory(const std::string &csv_path) {
    std::map<std::string, int> usage;
    std::ifstream infile(csv_path);
    std::string line;
    std::getline(infile, line); // Skip header
    while (std::getline(infile, line)) {
        std::stringstream ss(line);
        std::string count_str, ip, hostname, timestamp;
        std::getline(ss, count_str, ',');
        std::getline(ss, ip, ',');
        std::getline(ss, hostname, ',');
        std::getline(ss, timestamp, ',');
        if (!ip.empty() && !count_str.empty()) {
            usage[ip] = std::stoi(count_str);
        }
    }
    return usage;
}

bool isFileEmptyOrMissing(const std::string& path) {
    std::ifstream infile(path);
    return !infile.good() || infile.peek() == std::ifstream::traits_type::eof();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <hostname or IP>\n";
        return 1;
    }

    const char *target = argv[1];
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int status = getaddrinfo(target, nullptr, &hints, &res);
    if (status != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << "\n";
        return 1;
    }

    // Resolve destination to IPv4 string.
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, sizeof(ip_str));
    std::string destination_ip(ip_str);

    std::string csv_path = "traceroute_history.csv";
    auto usage_map = loadUsageHistory(csv_path);
    int current_usage = ++usage_map[destination_ip];

    // Get current timestamp.
    std::time_t now = std::time(nullptr);
    char timestamp[64];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    std::cout << "Traceroute to " << target << ", 30 hops max\n\n";
    std::cout << "Hop\tIP Address\t\tRTT (ms)\tJitter (ms)\tBandwidth (Mbps)\n";
    std::cout << "----------------------------------------------------------------------\n";

    std::ofstream outfile("traceroute_output.txt");
    outfile << "Traceroute to " << target << ", 30 hops max\n\n";
    outfile << "Hop\tIP Address\t\tRTT (ms)\tJitter (ms)\tBandwidth (Mbps)\n";
    outfile << "----------------------------------------------------------------------\n";

    bool write_headers = isFileEmptyOrMissing(csv_path);
    std::ofstream csvout(csv_path, std::ios::app);
    if (write_headers) {
        csvout << "usage_count,destination_ip,hostname,timestamp,hop,hop_ip,rtt_ms,jitter_ms,bandwidth_mbps\n";
    }

    double total_rtt = 0;
    int successful_hops = 0;
    double overall_bottleneck = std::numeric_limits<double>::max();
    bool destinationReached = false;

    // Iterate through hops via TTL values.
    for (int ttl = 1; ttl <= MAX_HOPS && !destinationReached; ++ttl) {
        std::vector<double> rtt_measurements;
        std::vector<double> bw_measurements;
        std::string hop_ip = "";

        // Implement improved packet pair technique using NUM_PAIRS UDP pairs.
        for (int pair = 0; pair < NUM_PAIRS; pair++) {
            int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (send_sock < 0 || recv_sock < 0) {
                std::cerr << "Socket creation failed: " << strerror(errno) << "\n";
                return 1;
            }

            // Set TTL for the send socket.
            setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

            // Set timeout for the receive socket.
            struct timeval timeout{};
            timeout.tv_sec = TIMEOUT_SEC;
            timeout.tv_usec = 0;
            setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

            // Set up destination address.
            sockaddr_in dest{};
            dest.sin_family = AF_INET;
            dest.sin_port = htons(PORT);
            inet_pton(AF_INET, destination_ip.c_str(), &(dest.sin_addr));

            char msg[PACKET_SIZE] = "Hello UDP";
            sockaddr_in sender{};
            socklen_t sender_len = sizeof(sender);

            // Send first UDP packet.
            auto send_time1 = std::chrono::steady_clock::now();
            sendto(send_sock, msg, sizeof(msg), 0, (sockaddr*)&dest, sizeof(dest));
            // Send second UDP packet back-to-back.
            usleep(1000); // 1ms delay
            auto send_time2 = std::chrono::steady_clock::now();
            sendto(send_sock, msg, sizeof(msg), 0, (sockaddr*)&dest, sizeof(dest));

            // Receive two ICMP responses.
            auto recv_time1 = send_time1, recv_time2 = send_time2;
            int recv_count = 0;
            while (recv_count < 2) {
                char temp_buf[512];
                sockaddr_in temp_sender{};
                socklen_t temp_len = sizeof(temp_sender);
                int bytes = recvfrom(recv_sock, temp_buf, sizeof(temp_buf), 0, (sockaddr*)&temp_sender, &temp_len);
                if (bytes > 0) {
                    if (recv_count == 0) {
                        recv_time1 = std::chrono::steady_clock::now();
                        sender = temp_sender;
                    } else {
                        recv_time2 = std::chrono::steady_clock::now();
                    }
                    recv_count++;
                } else {
                    break;
                }
            }

            close(send_sock);
            close(recv_sock);

            if (recv_count == 2) {
                double rtt = calculateRTT(send_time1, recv_time1);
                auto gap_us = std::chrono::duration_cast<std::chrono::microseconds>(recv_time2 - recv_time1).count();
                if (gap_us > 0) {
                    // Calculate bandwidth in Mbps:
                    double bandwidth_mbps = (PACKET_SIZE * 8.0) / static_cast<double>(gap_us);
                    rtt_measurements.push_back(rtt);
                    bw_measurements.push_back(bandwidth_mbps);
                }
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(sender.sin_addr), sender_ip, sizeof(sender_ip));
                hop_ip = sender_ip;
                if (destination_ip == hop_ip)
                    destinationReached = true;
            }
        } // End of NUM_PAIRS loop

        // If at least one valid probe measurement was obtained for this TTL.
        if (!rtt_measurements.empty()) {
            double avg_rtt = std::accumulate(rtt_measurements.begin(), rtt_measurements.end(), 0.0) / rtt_measurements.size();

            // Compute jitter as the standard deviation of the RTT values.
            double sum_sq_diff = 0.0;
            for (double r : rtt_measurements) {
                sum_sq_diff += (r - avg_rtt) * (r - avg_rtt);
            }
            double jitter = std::sqrt(sum_sq_diff / rtt_measurements.size());

            double median_bw = 0;
            if (!bw_measurements.empty()) {
                std::sort(bw_measurements.begin(), bw_measurements.end());
                size_t count = bw_measurements.size();
                if (count % 2 == 0)
                    median_bw = (bw_measurements[count/2 - 1] + bw_measurements[count/2]) / 2.0;
                else
                    median_bw = bw_measurements[count/2];
            }

            total_rtt += avg_rtt;
            ++successful_hops;
            if (median_bw < overall_bottleneck) overall_bottleneck = median_bw;

            std::cout << ttl << "\t" << hop_ip << "\t\t" 
                      << std::fixed << std::setprecision(3) << avg_rtt << "\t\t" 
                      << std::setprecision(3) << jitter << "\t\t" 
                      << std::setprecision(5) << median_bw << "\n";

            outfile << ttl << "\t" << hop_ip << "\t\t" 
                    << std::fixed << std::setprecision(3) << avg_rtt << "\t\t" 
                    << std::setprecision(3) << jitter << "\t\t" 
                    << std::setprecision(5) << median_bw << "\n";

            csvout << current_usage << "," << destination_ip << "," << target << "," << timestamp << ","
                   << ttl << "," << hop_ip << "," 
                   << std::fixed << std::setprecision(3) << avg_rtt << ","
                   << std::setprecision(3) << jitter << ","
                   << std::setprecision(5) << median_bw << "\n";

            if (destinationReached) break;
        } else {
            std::cout << ttl << "\t*\tTimeout\n";
            outfile << ttl << "\t*\tTimeout\n";
            csvout << current_usage << "," << destination_ip << "," << target << "," << timestamp
                   << "," << ttl << ",*,Timeout,Timeout,Timeout\n";
        }
    } // End TTL loop

    outfile << "\n--- Network Statistics ---\n";
    outfile << "Total Hops: " << successful_hops << "\n";
    if (successful_hops > 0) {
        outfile << "Average RTT: " << std::fixed << std::setprecision(3) 
                << (total_rtt / successful_hops) << " ms\n";
        outfile << "Bottleneck Bandwidth: " << std::setprecision(5) 
                << overall_bottleneck << " Mbps\n";
    } else {
        outfile << "Average RTT: N/A\n";
        outfile << "Bottleneck Bandwidth: N/A\n";
    }

    outfile.close();
    csvout.close();
    freeaddrinfo(res);
    std::cout << "\nResults saved in 'traceroute_output.txt' and 'traceroute_history.csv'\n";
    return 0;
}
