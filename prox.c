#include "prox.h"

Req *request(const char *dstip, const int dstport) {
    Req *req = malloc(sizeof(Req));
    if (req == NULL) {
        perror("malloc failed");
        return NULL;
    }
    
    req->vn = 4;
    req->cd = 1;
    req->dstport = htons(dstport);
    req->dstip = inet_addr(dstip);
    strncpy(req->userid, USERNAME, sizeof(req->userid) - 1);
    req->userid[sizeof(req->userid) - 1] = '\0';
    
    return req;
}

int connect_to_proxy(const char *proxy, int port) {
    struct sockaddr_in sock;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }
    
    sock.sin_family = AF_INET;
    sock.sin_port = htons(port);
    sock.sin_addr.s_addr = inet_addr(proxy);
    
    if (connect(s, (struct sockaddr *)&sock, sizeof(sock))) {
        perror("connect");
        close(s);
        return -1;
    }
    
    return s;
}

int socks4_connect(int sockfd, const char *dest_host, int dest_port, const char *userid) {
    Req *req = request(dest_host, dest_port);
    if (req == NULL) {
        return -1;
    }
    
    if (send(sockfd, req, sizeof(Req), 0) != sizeof(Req)) {
        perror("send failed");
        free(req);
        return -1;
    }
    
    free(req);
    
    Res res;
    if (recv(sockfd, &res, sizeof(Res), 0) != sizeof(Res)) {
        perror("recv failed");
        return -1;
    }
    
    if (res.cd != 90) {
        fprintf(stderr, "SOCKS4 request failed with status %d\n", res.cd);
        return -1;
    }
    
    return 0;
}

int socks4_connect_with_dns(int sockfd, const char *dest_host, int dest_port, const char *userid) {
    char resolved_ip[INET6_ADDRSTRLEN];
    if (resolve_hostname(dest_host, resolved_ip, sizeof(resolved_ip)) < 0) {
        fprintf(stderr, "Failed to resolve hostname: %s\n", dest_host);
        return -1;
    }

    return socks4_connect(sockfd, resolved_ip, dest_port, userid);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <port> [use_ssl]\n", argv[0]);
        return 1;
    }

    Config config;
    if (load_config("proxy.conf", &config) < 0) {
        fprintf(stderr, "Failed to load configuration. Using defaults.\n");
        strcpy(config.proxy_host, PROXY);
        config.proxy_port = PROXYPORT;
        strcpy(config.username, USERNAME);
    }

    char *host = argv[1];
    int port = atoi(argv[2]);
    int use_ssl = (argc > 3 && strcmp(argv[3], "ssl") == 0);

    initialize_ssl();

    int s = connect_to_proxy(config.proxy_host, config.proxy_port);
    if (s < 0) {
        cleanup_ssl();
        return 1;
    }

    printf("Connected to proxy\n");

    if (socks4_connect_with_dns(s, host, port, config.username) < 0) {
        close(s);
        cleanup_ssl();
        return 1;
    }

    printf("Successfully connected through the proxy to %s:%d\n", host, port);

    if (use_ssl) {
        SSLConnection ssl_conn;
        if (ssl_connect(&ssl_conn, s) < 0) {
            fprintf(stderr, "Failed to establish SSL connection\n");
            close(s);
            cleanup_ssl();
            return 1;
        }

        printf("SSL connection established\n");

        // Example of using SSL read/write
        const char *message = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        ssl_write(&ssl_conn, message, strlen(message));

        char buffer[4096];
        int bytes = ssl_read(&ssl_conn, buffer, sizeof(buffer));
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Received: %s\n", buffer);
        }

        ssl_disconnect(&ssl_conn);
    } else {
        // Non-SSL communication
        // For example:
        const char *message = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        send(s, message, strlen(message), 0);
        
        char buffer[4096];
        int bytes = recv(s, buffer, sizeof(buffer), 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Received: %s\n", buffer);
        }
    }

    close(s);
    cleanup_ssl();
    return 0;
}