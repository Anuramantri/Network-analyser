#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int resolve_hostname(const char *hostname, char *dest_addr, int &address_family, size_t addr_size, bool force_ipv4 = false, bool force_ipv6 = false) {
    struct addrinfo hints, *res, *res0;
    
    // Initialize hints structure
    memset(&hints, 0, sizeof(hints));
    
    // Set address family based on flags
    if (force_ipv4) {
        hints.ai_family = AF_INET;     // IPv4 only
    } else if (force_ipv6) {
        hints.ai_family = AF_INET6;    // IPv6 only
    } else {
        hints.ai_family = AF_UNSPEC;   // Allow both IPv4 and IPv6
    }
    
    hints.ai_socktype = SOCK_RAW;      // For traceroute/ping applications
    
    // Get address info
    int error = getaddrinfo(hostname, NULL, &hints, &res0);
    if (error) {
        std::cerr << "Error resolving hostname: " << gai_strerror(error) << std::endl;
        return -1;
    }
    
    // Loop through all results and get the first one that matches our criteria
    for (res = res0; res; res = res->ai_next) {
        if (res->ai_family == AF_INET && (force_ipv4 || !force_ipv6)) {
            // IPv4 address
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), dest_addr, addr_size);
            address_family = AF_INET;
            freeaddrinfo(res0);
            return 0;
        } else if (res->ai_family == AF_INET6 && (force_ipv6 || !force_ipv4)) {
            // IPv6 address
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), dest_addr, addr_size);
            address_family = AF_INET6;
            freeaddrinfo(res0);
            return 0;
        }
    }
    
    // Free the linked list
    freeaddrinfo(res0);
    return -1;  // No suitable address found
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [-4|-6] <hostname>" << std::endl;
        return 1;
    }
    
    char dest_addr[INET6_ADDRSTRLEN];  // Large enough for both IPv4 and IPv6
    int address_family = AF_UNSPEC;
    const char* hostname = argv[1];
    bool force_ipv4 = false;
    bool force_ipv6 = false;
    
    // Check for IPv4/IPv6 flags
    if (argc >= 3 && strcmp(argv[1], "-4") == 0) {
        force_ipv4 = true;
        hostname = argv[2];
    } else if (argc >= 3 && strcmp(argv[1], "-6") == 0) {
        force_ipv6 = true;
        hostname = argv[2];
    }
    
    if (resolve_hostname(hostname, dest_addr, address_family, INET6_ADDRSTRLEN, force_ipv4, force_ipv6) == 0) {
        std::cout << "Resolved address: " << dest_addr << std::endl;
        std::cout << "Address family: " << (address_family == AF_INET ? "IPv4" : "IPv6") << std::endl;
    } else {
        std::cerr << "Failed to resolve hostname: " << hostname << std::endl;
        return 1;
    }
    
    return 0;
}