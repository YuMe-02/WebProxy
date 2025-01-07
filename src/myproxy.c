#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>   // Include time.h for time functions
#include <sys/time.h> // Include sys/time.h for gettimeofday function

#define BUFFER_SIZE 4096
#define MAX_THREADS 10

void print_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
}

void trimWhitespace(char *str) {
    char *end;
    while (isspace(*str)) {
        str++;
    }
    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) {
        end--;
    }
    *(end + 1) = '\0';
}

void resolveAndWriteToFile(const char *line, FILE *input_file) {
    struct sockaddr_in sa;
    char ipstr[INET_ADDRSTRLEN];
    int result = inet_pton(AF_INET, line, &(sa.sin_addr));
    if (result == 1) {
        fprintf(input_file, "%s\n", line);
    } else {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int status = getaddrinfo(line, NULL, &hints, &res);
        if (status != 0) {
            fprintf(stderr, "getaddrinfo error for %s: %s\n", line, gai_strerror(status));
            return;
        }
        struct sockaddr_in *ipv4;
        for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
            ipv4 = (struct sockaddr_in *)p->ai_addr;
            inet_ntop(p->ai_family, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
            fprintf(input_file, "%s\n", ipstr);
        }
        freeaddrinfo(res);
    }
}

int is_banned(const char *url_or_ip, const char *forbidden_sites_file) {
    FILE *file = fopen(forbidden_sites_file, "r");
    if (file == NULL) {
        print_error("Failed to open forbidden sites file");
        return 0;
    }
    char line[BUFFER_SIZE];
    while (fgets(line, BUFFER_SIZE, file) != NULL) {
        line[strcspn(line, "\n")] = 0;
        if (strcmp(line, url_or_ip) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

char *https_request(const char *request, const char* HOST, const char *PORT) {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct addrinfo hints, *res;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "Error creating SSL context\n");
        return NULL;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx); // Set default verify paths

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(HOST, PORT, &hints, &res) != 0) {
        fprintf(stderr, "Error getting address info\n");
        return NULL;
    }
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        fprintf(stderr, "Error creating socket\n");
        return NULL;
    }
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
        fprintf(stderr, "Error connecting to server\n");
        return NULL;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "Error creating SSL structure\n");
        return NULL;
    }
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "Error establishing SSL connection\n");

        // Print SSL error messages
        unsigned long ssl_err;
        while ((ssl_err = ERR_get_error()) != 0) {
            fprintf(stderr, "SSL error: %s\n", ERR_error_string(ssl_err, NULL));
        }
        
        return NULL;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        fprintf(stderr, "Error retrieving server certificate\n");
        return NULL;
    }

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification error: %s\n", X509_verify_cert_error_string(verify_result));
        return NULL;
    }

    if (SSL_write(ssl, request, strlen(request)) <= 0) {
        fprintf(stderr, "Error sending request\n");
        return NULL;
    }

    char response[BUFFER_SIZE];
    int bytes_received;
    char *full_response = NULL;
    size_t full_response_size = 0;
    while ((bytes_received = SSL_read(ssl, response, sizeof(response) - 1)) > 0) {
        response[bytes_received] = '\0';
        printf("Received from server: %s\n", response); // Print what the proxy receives from the requested site
        full_response = realloc(full_response, full_response_size + bytes_received + 1);
        if (full_response == NULL) {
            fprintf(stderr, "Memory allocation error\n");
            return NULL;
        }
        memcpy(full_response + full_response_size, response, bytes_received);
        full_response_size += bytes_received;
    }
    full_response[full_response_size] = '\0';

    SSL_shutdown(ssl);
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    freeaddrinfo(res);

    return full_response;
}

void handle_client(int client_socket, struct sockaddr_in client_addr, const char *forbidden_sites_file, const char *access_log_file) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("Error receiving data from client");
        close(client_socket);
        return;
    }
    buffer[bytes_received] = '\0';

    char request[BUFFER_SIZE];
    char method[BUFFER_SIZE];
    char url[BUFFER_SIZE];
    char host[BUFFER_SIZE];
    char port[6] = "443"; // Default port is 443

    if (sscanf(buffer, "%s %s", method, url) != 2) {
        fprintf(stderr, "Error parsing method and URL from request\n");
        close(client_socket);
        return;
    }

    // Check if the URL starts with "http://"
    if (strncasecmp(url, "http://", 7) == 0) {
        char *host_start = url + 7; // Skip "http://"
        char *path_start = strchr(host_start, '/');
        if (path_start != NULL) {
            *path_start = '\0'; // Null-terminate the host string
        }
        char *port_start = strchr(host_start, ':'); // Find port separator
        if (port_start != NULL) {
            *port_start = '\0'; // Null-terminate the host string
            sscanf(port_start + 1, "%5s", port); // Extract port
        }
        sscanf(host_start, "%[^:/]", host); // Extract host
    } else {
        fprintf(stderr, "Unsupported URL format\n");
        close(client_socket);
        return;
    }

    // Extract the path and query from the URL
    char *path_and_query = strchr(url + 7, '/');
    if (path_and_query == NULL) {
        path_and_query = "/";
    }

    // Concatenate the URL and path_and_query to form the complete request URL
    char complete_url[BUFFER_SIZE];
    snprintf(complete_url, BUFFER_SIZE, "%s%s", url, path_and_query);

    // Prepare the request using the complete URL
    snprintf(request, BUFFER_SIZE, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, complete_url, host);

    // Print the parsed request
    printf("Parsed Request:\n");
    printf("Method: %s\n", method);
    printf("URL: %s\n", url);
    printf("Host: %s\n", host);
    printf("Port: %s\n", port);
    printf("Complete URL: %s\n", complete_url);
    printf("Request: %s\n", request);

    if (is_banned(host, forbidden_sites_file)) {
        // Log the banned request
        FILE *log_file = fopen(access_log_file, "a");
        if (log_file != NULL) {
            time_t raw_time;
            struct tm *time_info;
            char time_str[50]; // Buffer for time string
            time(&raw_time);
            time_info = localtime(&raw_time);
            strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", time_info);

            // Write log entry for the banned request
            fprintf(log_file, "%s.852Z %s \"%s %s HTTP/1.1\" 403 0\n", time_str, inet_ntoa(client_addr.sin_addr), method, url);
            fclose(log_file);
        }

        // Send forbidden response to the client
        const char *forbidden_response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        printf("Sending Forbidden Response:\n%s\n", forbidden_response);
        send(client_socket, forbidden_response, strlen(forbidden_response), 0);
        close(client_socket);
        return;
    }

    // Forward the request to the destination server
    printf("Request sent to HTTPS server:\n%s\n", request); // Print the request sent to the HTTPS server
    char *response = https_request(request, host, port);
    if (response == NULL) {
        // Log the internal server error
        FILE *log_file = fopen(access_log_file, "a");
        if (log_file != NULL) {
            time_t raw_time;
            struct tm *time_info;
            char time_str[50]; // Buffer for time string
            time(&raw_time);
            time_info = localtime(&raw_time);
            strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", time_info);

            // Write log entry for the internal server error
            fprintf(log_file, "%s.852Z %s \"%s %s HTTP/1.1\" 500 0\n", time_str, inet_ntoa(client_addr.sin_addr), method, url);
            fclose(log_file);
        }

        // Send internal server error response to the client
        const char *error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
        printf("Sending Internal Server Error Response:\n%s\n", error_response);
        send(client_socket, error_response, strlen(error_response), 0);
        close(client_socket);
        return;
        
    } else {
        // Log the response being sent
        FILE *log_file = fopen(access_log_file, "a");
        if (log_file != NULL) {
            time_t raw_time;
            struct tm *time_info;
            char time_str[50]; // Buffer for time string
            time(&raw_time);
            time_info = localtime(&raw_time);
            strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", time_info);

            // Write log entry for the response
            if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
                fprintf(log_file, "%s.852Z %s \"%s %s HTTP/1.1\" 200 %zu\n", time_str, inet_ntoa(client_addr.sin_addr), method, url, strlen(response));
            } else {
                fprintf(log_file, "%s.852Z %s \"%s %s HTTP/1.1\" 501 36\n", time_str, inet_ntoa(client_addr.sin_addr), method, url);
            }
            fclose(log_file);
        }
    }
    // Print the response received from the HTTPS server
    printf("Received response from HTTPS server:\n%s\n", response);
    printf("Sending response to client:\n%s\n", response); // Print the response being sent to the client
    send(client_socket, response, strlen(response), 0);

    close(client_socket);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <listen_port> <forbidden_sites_file> <access_log_file>\n", argv[0]);
        return 1;
    }

    int listen_port = atoi(argv[1]);
    char *forbidden_sites_file = argv[2];
    char *access_log_file = argv[3];

    FILE *input_file = fopen(forbidden_sites_file, "r");
    if (input_file == NULL) {
        print_error("Failed to open forbidden sites file");
        return 1;
    }
    fclose(input_file);

    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error creating socket");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(listen_port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        close(server_socket);
        return 1;
    }

    if (listen(server_socket, 50) < 0) {
        perror("Error listening for connections");
        close(server_socket);
        return 1;
    }

    printf("Proxy server listening on port %d...\n", listen_port);

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Error accepting connection");
            continue;
        }
        
        pid_t pid = fork();
        if (pid < 0) {
            perror("Error forking process");
            close(client_socket);
            continue;
        } else if (pid == 0) { // Child process
            close(server_socket); // Close the server socket in the child process
            handle_client(client_socket, client_addr, forbidden_sites_file, access_log_file);
            close(client_socket);
            exit(0); // Terminate the child process after handling the client request
        } else { // Parent process
            close(client_socket); // Close the client socket in the parent process
        }
    }

    close(server_socket);

    return 0;
}
