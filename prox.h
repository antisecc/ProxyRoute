#ifndef PROX_H
#define PROX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PROXY "127.0.0.1"
#define PROXYPORT 9050
#define USERNAME "someone"

typedef struct {
    uint8_t vn;
    uint8_t cd;
    uint16_t dstport;
    uint32_t dstip;
    char userid[8];
} Req;

typedef struct {
    uint8_t vn;
    uint8_t cd;
    uint16_t dstport;
    uint32_t dstip;
} Res;

typedef struct {
    char proxy_host[256];
    int proxy_port;
    char username[64];
} Config;

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
} SSLConnection;

Req *request(const char *dstip, const int dstport);
int connect_to_proxy(const char *proxy, int port);
int socks4_connect(int sockfd, const char *dest_host, int dest_port, const char *userid);

int load_config(const char *filename, Config *config);

int resolve_hostname(const char *hostname, char *ip_str, size_t ip_str_size);

int initialize_ssl();
int ssl_connect(SSLConnection *conn, int socket);
int ssl_write(SSLConnection *conn, const void *buf, int num);
int ssl_read(SSLConnection *conn, void *buf, int num);
void ssl_disconnect(SSLConnection *conn);
void cleanup_ssl();


inline int load_config(const char *filename, Config *config) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening config file");
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "\n");
        
        if (key && value) {
            if (strcmp(key, "proxy_host") == 0) {
                strncpy(config->proxy_host, value, sizeof(config->proxy_host) - 1);
            } else if (strcmp(key, "proxy_port") == 0) {
                config->proxy_port = atoi(value);
            } else if (strcmp(key, "username") == 0) {
                strncpy(config->username, value, sizeof(config->username) - 1);
            }
        }
    }

    fclose(file);
    return 0;
}

inline int resolve_hostname(const char *hostname, char *ip_str, size_t ip_str_size) {
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    for(p = res; p != NULL; p = p->ai_next) {
        void *addr;
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        break; // Use the first IP address
    }

    strncpy(ip_str, ipstr, ip_str_size);
    ip_str[ip_str_size - 1] = '\0'; // Ensure null-termination

    freeaddrinfo(res); 
    return 0;
}

inline int initialize_ssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    return 0;
}

inline int ssl_connect(SSLConnection *conn, int socket) {
    conn->ctx = SSL_CTX_new(TLS_client_method());
    if (conn->ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    conn->ssl = SSL_new(conn->ctx);
    SSL_set_fd(conn->ssl, socket);

    if (SSL_connect(conn->ssl) == -1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

inline int ssl_write(SSLConnection *conn, const void *buf, int num) {
    return SSL_write(conn->ssl, buf, num);
}

inline int ssl_read(SSLConnection *conn, void *buf, int num) {
    return SSL_read(conn->ssl, buf, num);
}

inline void ssl_disconnect(SSLConnection *conn) {
    SSL_free(conn->ssl);
    SSL_CTX_free(conn->ctx);
}

inline void cleanup_ssl() {
    EVP_cleanup();
}

#endif /* PROX_H */