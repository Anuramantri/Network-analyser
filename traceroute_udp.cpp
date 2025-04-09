// #include <iostream>
// #include <fstream>
// #include <cstring>
// #include <chrono>
// #include <netinet/ip_icmp.h>
// #include <netinet/icmp6.h>
// #include <netinet/in.h>
// #include <netdb.h>
// #include <sys/socket.h>
// #include <arpa/inet.h>
// #include <unistd.h>
// #include <errno.h>
// #include <cmath>
// #include <iomanip>

// #define MAX_HOPS 30
// #define PORT 33434
// #define TIMEOUT_SEC 3
// #define PACKET_SIZE 60  // bytes

// double calculateRTT(auto start, auto end) {
//     return std::chrono::duration<double, std::milli>(end - start).count();
// }

// int main(int argc, char *argv[]) {
//     if (argc != 2) {
//         std::cerr << "Usage: " << argv[0] << " <hostname or IP>\n";
//         return 1;
//     }

//     const char *target = argv[1];
//     struct addrinfo hints{}, *res;

//     memset(&hints, 0, sizeof(hints));
//     hints.ai_socktype = SOCK_DGRAM;
//     hints.ai_family = AF_UNSPEC;  // Support both IPv4 and IPv6

//     int status = getaddrinfo(target, nullptr, &hints, &res);
//     if (status != 0 || !res) {
//         std::cerr << "getaddrinfo error: " << gai_strerror(status) << "\n";
//         return 1;
//     }

//     char ip_str[INET6_ADDRSTRLEN];
//     void *addr_ptr = nullptr;
//     int family = res->ai_family;

//     if (family == AF_INET) {
//         addr_ptr = &((sockaddr_in*)res->ai_addr)->sin_addr;
//     } else if (family == AF_INET6) {
//         addr_ptr = &((sockaddr_in6*)res->ai_addr)->sin6_addr;
//     } else {
//         std::cerr << "Unsupported address family.\n";
//         return 1;
//     }

//     inet_ntop(family, addr_ptr, ip_str, sizeof(ip_str));
//     std::string destination_ip(ip_str);

//     std::cout << "Traceroute to " << target << " [" << destination_ip << "], 30 hops max\n\n";
//     std::cout << "Hop\tIP Address\t\tRTT (ms)\t\tBandwidth (Mbps)\n";
//     std::cout << "----------------------------------------------------------------------\n";

//     std::ofstream outfile("traceroute_output.txt");
//     outfile << "Traceroute to " << target << " [" << destination_ip << "], 30 hops max\n\n";
//     outfile << "Hop\tIP Address\t\tRTT (ms)\t\tBandwidth (Mbps)\n";
//     outfile << "----------------------------------------------------------------------\n";

//     double total_rtt = 0;
//     int successful_hops = 0;
//     double bottleneck = std::numeric_limits<double>::max();

//     for (int ttl = 1; ttl <= MAX_HOPS; ++ttl) {
//         int send_sock, recv_sock;

//         if (family == AF_INET) {
//             send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
//             recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
//         } else {
//             send_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
//             recv_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
//         }

//         if (send_sock < 0 || recv_sock < 0) {
//             std::cerr << "Socket creation failed: " << strerror(errno) << "\n";
//             return 1;
//         }

//         if (family == AF_INET)
//             setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
//         else
//             setsockopt(send_sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));

//         struct timeval timeout{};
//         timeout.tv_sec = TIMEOUT_SEC;
//         timeout.tv_usec = 0;
//         setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

//         char msg[PACKET_SIZE] = "Hello UDP";
//         char buffer1[512], buffer2[512];
//         char sender_ip[INET6_ADDRSTRLEN];

//         sockaddr_storage dest_addr{};
//         socklen_t addr_len;

//         if (family == AF_INET) {
//             sockaddr_in *dest = (sockaddr_in *)&dest_addr;
//             dest->sin_family = AF_INET;
//             dest->sin_port = htons(PORT);
//             inet_pton(AF_INET, destination_ip.c_str(), &(dest->sin_addr));
//             addr_len = sizeof(sockaddr_in);
//         } else {
//             sockaddr_in6 *dest6 = (sockaddr_in6 *)&dest_addr;
//             dest6->sin6_family = AF_INET6;
//             dest6->sin6_port = htons(PORT);
//             inet_pton(AF_INET6, destination_ip.c_str(), &(dest6->sin6_addr));
//             addr_len = sizeof(sockaddr_in6);
//         }

//         // Send first packet
//         auto send_time1 = std::chrono::steady_clock::now();
//         sendto(send_sock, msg, sizeof(msg), 0, (sockaddr *)&dest_addr, addr_len);

//         // Slight delay
//         usleep(1000);

//         // Send second packet
//         auto send_time2 = std::chrono::steady_clock::now();
//         sendto(send_sock, msg, sizeof(msg), 0, (sockaddr *)&dest_addr, addr_len);

//         sockaddr_storage sender{};
//         socklen_t sender_len = sizeof(sender);
//         auto recv_time1 = send_time1, recv_time2 = send_time2;
//         int recv_count = 0;

//         while (recv_count < 2) {
//             char temp_buf[512];
//             sockaddr_storage temp_sender{};
//             socklen_t temp_len = sizeof(temp_sender);

//             int bytes = recvfrom(recv_sock, temp_buf, sizeof(temp_buf), 0, (sockaddr*)&temp_sender, &temp_len);
//             if (bytes > 0) {
//                 if (recv_count == 0) {
//                     recv_time1 = std::chrono::steady_clock::now();
//                     sender = temp_sender;
//                 } else {
//                     recv_time2 = std::chrono::steady_clock::now();
//                 }
//                 recv_count++;
//             } else {
//                 break;
//             }
//         }

//         close(send_sock);
//         close(recv_sock);

//         if (recv_count == 2) {
//             if (family == AF_INET) {
//                 inet_ntop(AF_INET, &(((sockaddr_in*)&sender)->sin_addr), sender_ip, sizeof(sender_ip));
//             } else {
//                 inet_ntop(AF_INET6, &(((sockaddr_in6*)&sender)->sin6_addr), sender_ip, sizeof(sender_ip));
//             }

//             double rtt = calculateRTT(send_time1, recv_time1);
//             double reply_gap_ms = calculateRTT(recv_time1, recv_time2);
//             double bandwidth_mbps = reply_gap_ms > 0 ? (PACKET_SIZE * 8) / (reply_gap_ms / 1000.0) / 1e6 : 0;

//             total_rtt += rtt;
//             ++successful_hops;
//             if (bandwidth_mbps < bottleneck) bottleneck = bandwidth_mbps;

//             std::cout << ttl << "\t" << sender_ip << "\t\t" << std::fixed << std::setprecision(3) << rtt
//                       << "\t\t" << std::setprecision(5) << bandwidth_mbps << "\n";

//             outfile << ttl << "\t" << sender_ip << "\t\t" << std::fixed << std::setprecision(3) << rtt
//                     << "\t\t" << std::setprecision(5) << bandwidth_mbps << "\n";

//             if (destination_ip == sender_ip) break;
//         } else {
//             std::cout << ttl << "\t*\tTimeout\n";
//             outfile << ttl << "\t*\tTimeout\n";
//         }
//     }

//     outfile << "\n--- Network Statistics ---\n";
//     outfile << "Total Hops: " << successful_hops << "\n";
//     if (successful_hops > 0) {
//         outfile << "Average RTT: " << std::fixed << std::setprecision(3) << (total_rtt / successful_hops) << " ms\n";
//         outfile << "Bottleneck Bandwidth: " << std::setprecision(5) << bottleneck << " Mbps\n";
//     } else {
//         outfile << "Average RTT: N/A\n";
//         outfile << "Bottleneck Bandwidth: N/A\n";
//     }

//     outfile.close();
//     freeaddrinfo(res);
//     std::cout << "\nResults saved in 'traceroute_output.txt'\n";
//     return 0;
// }





#include <iostream>
#include <fstream>
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

#define MAX_HOPS 30
#define PORT 33434
#define TIMEOUT_SEC 3
#define PACKET_SIZE 60  // bytes

// Calculate RTT in milliseconds
double calculateRTT(auto start, auto end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
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

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, sizeof(ip_str));
    std::string destination_ip(ip_str);

    std::cout << "Traceroute to " << target << ", 30 hops max\n\n";
    std::cout << "Hop\tIP Address\t\tRTT (ms)\t\tBandwidth (Mbps)\n";
    std::cout << "----------------------------------------------------------------------\n";

    std::ofstream outfile("traceroute_output.txt");
    outfile << "Traceroute to " << target << ", 30 hops max\n\n";
    outfile << "Hop\tIP Address\t\tRTT (ms)\t\tBandwidth (Mbps)\n";
    outfile << "----------------------------------------------------------------------\n";

    double total_rtt = 0;
    int successful_hops = 0;
    double bottleneck = std::numeric_limits<double>::max();

    for (int ttl = 1; ttl <= MAX_HOPS; ++ttl) {
        int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (send_sock < 0 || recv_sock < 0) {
            std::cerr << "Socket creation failed: " << strerror(errno) << "\n";
            return 1;
        }

        setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        struct timeval timeout{};
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = 0;
        setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port = htons(PORT);
        inet_pton(AF_INET, destination_ip.c_str(), &(dest.sin_addr));

        char msg[PACKET_SIZE] = "Hello UDP";
        char buffer1[512], buffer2[512];
        sockaddr_in sender{};
        socklen_t sender_len = sizeof(sender);

        // Send first packet
        auto send_time1 = std::chrono::steady_clock::now();
        sendto(send_sock, msg, sizeof(msg), 0, (sockaddr*)&dest, sizeof(dest));

        // Slight delay
        usleep(1000);

        // Send second packet
        auto send_time2 = std::chrono::steady_clock::now();
        sendto(send_sock, msg, sizeof(msg), 0, (sockaddr*)&dest, sizeof(dest));

        // Receive ICMP responses
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

        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sender.sin_addr), sender_ip, sizeof(sender_ip));

        if (recv_count == 2) {
            double rtt = calculateRTT(send_time1, recv_time1);
            double reply_gap_ms = calculateRTT(recv_time1, recv_time2);
            double bandwidth_mbps = reply_gap_ms > 0 ? (PACKET_SIZE * 8) / (reply_gap_ms / 1000.0) / 1e6 : 0;

            total_rtt += rtt;
            ++successful_hops;
            if (bandwidth_mbps < bottleneck) bottleneck = bandwidth_mbps;

            std::cout << ttl << "\t" << sender_ip << "\t\t" << std::fixed << std::setprecision(3) << rtt
                      << "\t\t" << std::setprecision(5) << bandwidth_mbps << "\n";

            outfile << ttl << "\t" << sender_ip << "\t\t" << std::fixed << std::setprecision(3) << rtt
                    << "\t\t" << std::setprecision(5) << bandwidth_mbps << "\n";

            if (destination_ip == sender_ip) break;
        } else {
            std::cout << ttl << "\t*\tTimeout\n";
            outfile << ttl << "\t*\tTimeout\n";
        }
    }

    outfile << "\n--- Network Statistics ---\n";
    outfile << "Total Hops: " << successful_hops << "\n";
    if (successful_hops > 0) {
        outfile << "Average RTT: " << std::fixed << std::setprecision(3) << (total_rtt / successful_hops) << " ms\n";
        outfile << "Bottleneck Bandwidth: " << std::setprecision(5) << bottleneck << " Mbps\n";
    } else {
        outfile << "Average RTT: N/A\n";
        outfile << "Bottleneck Bandwidth: N/A\n";
    }

    outfile.close();
    freeaddrinfo(res);
    std::cout << "\nResults saved in 'traceroute_output.txt'\n";
    return 0;
}
