#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>

#include <linux/if.h>
#include <linux/if_tun.h>

// Define VPN_MODE as 1 for SERVER or 0 for CLIENT
// Can be overridden at compile time: -DVPN_MODE=1 (server) or -DVPN_MODE=0 (client)
#ifndef VPN_MODE
#define VPN_MODE 1  // Default to SERVER mode
#endif

#define SERVER_MODE 1
#define CLIENT_MODE 0

// Configuration
#define SERVER_PORT 5555
#define SERVER_IP "127.0.0.1"  // For client mode
#define BUFFER_SIZE 2048
#define TUN_NAME "mock-vpn"

// VPN packet header (simple encapsulation)
typedef struct {
    uint16_t length;  // Packet length (network byte order)
    uint8_t reserved[2];
} vpn_header_t;

static int tun_fd = -1;
static int sock_fd = -1;
static volatile int running = 1;
static struct sockaddr_in peer_addr;
static socklen_t peer_addr_len = 0;
static int has_peer = 0;

void signal_handler(int sig) {
    running = 0;
}

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev)
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }

    snprintf(dev, IFNAMSIZ, "%s", ifr.ifr_name);
    return fd;
}

int setup_tun_interface(const char *dev_name) {
    char cmd[256];
    char if_name[IFNAMSIZ];
    
    strncpy(if_name, dev_name, IFNAMSIZ);
    tun_fd = tun_alloc(if_name);
    if (tun_fd < 0) {
        return -1;
    }

    printf("Created TUN interface: %s\n", if_name);

    // Configure TUN interface (requires root)
    snprintf(cmd, sizeof(cmd), "ip link set %s up", if_name);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Failed to bring up interface (run as root)\n");
    }

#if VPN_MODE == SERVER_MODE
    snprintf(cmd, sizeof(cmd), "ip addr add 10.0.0.1/24 dev %s", if_name);
#else
    snprintf(cmd, sizeof(cmd), "ip addr add 10.0.0.2/24 dev %s", if_name);
#endif
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Failed to set IP address (run as root)\n");
    }

    return 0;
}

int setup_server_socket(void) {
    struct sockaddr_in addr;
    int fd;
    int opt = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVER_PORT);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    printf("Server listening on port %d\n", SERVER_PORT);
    return fd;
}

int setup_client_socket(void) {
    struct sockaddr_in addr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    if (inet_aton(SERVER_IP, &addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid server IP: %s\n", SERVER_IP);
        close(fd);
        return -1;
    }

    // Connect UDP socket (optional, but helps with error detection)
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    printf("Client connected to %s:%d\n", SERVER_IP, SERVER_PORT);
    return fd;
}

void forward_tun_to_socket(void) {
    uint8_t buffer[BUFFER_SIZE];
    vpn_header_t *header = (vpn_header_t *)buffer;
    ssize_t nread, nwrite;

    nread = read(tun_fd, buffer + sizeof(vpn_header_t), BUFFER_SIZE - sizeof(vpn_header_t));
    if (nread < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read from TUN");
        }
        return;
    }

    if (nread == 0) {
        return;
    }

    // Add VPN header
    header->length = htons((uint16_t)nread);
    header->reserved[0] = 0;
    header->reserved[1] = 0;

#if VPN_MODE == SERVER_MODE
    // Server: send to last known peer
    if (has_peer) {
        nwrite = sendto(sock_fd, buffer, nread + sizeof(vpn_header_t), 0,
                       (struct sockaddr *)&peer_addr, peer_addr_len);
    } else {
        // No peer yet, drop packet
        return;
    }
#else
    // Client: send to server
    nwrite = send(sock_fd, buffer, nread + sizeof(vpn_header_t), 0);
#endif

    if (nwrite < 0) {
        perror("send");
    } else if (nwrite != nread + (ssize_t)sizeof(vpn_header_t)) {
        fprintf(stderr, "Partial send: %zd/%zd bytes\n", nwrite, nread + sizeof(vpn_header_t));
    }
}

void forward_socket_to_tun(void) {
    uint8_t buffer[BUFFER_SIZE];
    vpn_header_t *header = (vpn_header_t *)buffer;
    ssize_t nread, nwrite;
    socklen_t addr_len = sizeof(peer_addr);

#if VPN_MODE == SERVER_MODE
    nread = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0,
                    (struct sockaddr *)&peer_addr, &addr_len);
    // Store peer address for sending packets back
    if (nread > 0 && !has_peer) {
        peer_addr_len = addr_len;
        has_peer = 1;
        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, INET_ADDRSTRLEN);
        printf("Peer connected from %s:%d\n", peer_ip, ntohs(peer_addr.sin_port));
    }
#else
    nread = recv(sock_fd, buffer, BUFFER_SIZE, 0);
#endif

    if (nread < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv");
        }
        return;
    }

    if (nread < (ssize_t)sizeof(vpn_header_t)) {
        fprintf(stderr, "Received packet too small\n");
        return;
    }

    // Extract VPN header
    uint16_t payload_len = ntohs(header->length);
    if (payload_len > BUFFER_SIZE - sizeof(vpn_header_t)) {
        fprintf(stderr, "Invalid packet length: %d\n", payload_len);
        return;
    }

    // Write payload to TUN interface
    nwrite = write(tun_fd, buffer + sizeof(vpn_header_t), payload_len);
    if (nwrite < 0) {
        perror("write to TUN");
    } else if (nwrite != payload_len) {
        fprintf(stderr, "Partial write: %zd/%d bytes\n", nwrite, payload_len);
    }
}

int main(void) {
    fd_set read_fds;
    int max_fd;
    struct timeval timeout;

    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Setup TUN interface
    if (setup_tun_interface(TUN_NAME) < 0) {
        fprintf(stderr, "Failed to setup TUN interface\n");
        return 1;
    }

    // Setup network socket
#if VPN_MODE == SERVER_MODE
    sock_fd = setup_server_socket();
    printf("Running in SERVER mode\n");
#else
    sock_fd = setup_client_socket();
    printf("Running in CLIENT mode\n");
#endif

    if (sock_fd < 0) {
        fprintf(stderr, "Failed to setup network socket\n");
        close(tun_fd);
        return 1;
    }

    // Set non-blocking mode
    int flags = fcntl(tun_fd, F_GETFL, 0);
    fcntl(tun_fd, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sock_fd, F_GETFL, 0);
    fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);

    printf("VPN started. Press Ctrl+C to stop.\n");
    printf("Note: Run as root to configure network interface\n");

    // Main loop: forward packets between TUN and socket
    while (running) {
        FD_ZERO(&read_fds);
        FD_SET(tun_fd, &read_fds);
        FD_SET(sock_fd, &read_fds);
        max_fd = (tun_fd > sock_fd) ? tun_fd : sock_fd;

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ret = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }

        if (ret == 0) {
            // Timeout
            continue;
        }

        if (FD_ISSET(tun_fd, &read_fds)) {
            forward_tun_to_socket();
        }

        if (FD_ISSET(sock_fd, &read_fds)) {
            forward_socket_to_tun();
        }
    }

    printf("\nShutting down...\n");

    // Cleanup
    if (tun_fd >= 0) {
        close(tun_fd);
    }
    if (sock_fd >= 0) {
        close(sock_fd);
    }

    return 0;
}