#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wait.h>

#include <malloc.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1

#define BUF_SIZE 1024

#define READ  0
#define WRITE 1

#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define CREATE_PIPE_ERROR -8
#define BROKEN_PIPE_ERROR -9

typedef enum {TRUE = 1, FALSE = 0} bool;

int create_socket(int port);
void sigchld_handler(int signal);
void sigterm_handler(int signal);
void server_loop();
void handle_client(int client_sock, struct sockaddr_in client_addr);
void forward_data_up(int source_sock, int destination_sock);
void forward_data_down(int source_sock, int destination_sock);
int parse_options(int argc, char *argv[]);
void ShowCerts(SSL* ssl);
SSL_CTX* InitCTX(void);
void init_clinet_ssl(int server);
int create_connection();

int server_sock, client_sock, remote_sock, remote_port;
char *remote_host;
bool opt_in = FALSE, opt_out = FALSE;

SSL_CTX *ctx;
SSL *ssl;

/* Program start */
int main(int argc, char *argv[])
{
    int local_port;
    pid_t pid;

    local_port = parse_options(argc, argv);

    if (local_port < 0) {
        printf("Syntax: %s -l local_port -h remote_host -p remote_port \n", argv[0]);
        return 0;
    }

    if ((server_sock = create_socket(local_port)) < 0) { // start server
        perror("Cannot run server");
        return server_sock;
    }

    signal(SIGCHLD, sigchld_handler); // prevent ended children from becoming zombies
    signal(SIGTERM, sigterm_handler); // handle KILL signal

    switch(pid = fork()) {
    case 0:
        server_loop(); // daemonized child
        break;
    case -1:
        perror("Cannot daemonize");
        return pid;
    default:
        close(server_sock);
    }

    return 0;
}

/* Parse command line options */
int parse_options(int argc, char *argv[])
{
    bool l, h, p;
    int c, local_port;

    l = h = p = FALSE;

    while ((c = getopt(argc, argv, "l:h:p:")) != -1) {
        switch(c) {
        case 'l':
            local_port = atoi(optarg);
            l = TRUE;
            break;
        case 'h':
            remote_host = optarg;
            h = TRUE;
            break;
        case 'p':
            remote_port = atoi(optarg);
            p = TRUE;
            break;
        }
    }

    if (l && h && p) {
        return local_port;
    } else {
        return -1;
    }
}

/* Create server socket */
int create_socket(int port)
{
    int server_sock, optval;
    struct sockaddr_in server_addr;

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return SERVER_SOCKET_ERROR;
    }

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        return SERVER_SETSOCKOPT_ERROR;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        return SERVER_BIND_ERROR;
    }

    if (listen(server_sock, 20) < 0) {
        return SERVER_LISTEN_ERROR;
    }

    return server_sock;
}

/* Handle finished child process */
void sigchld_handler(int signal)
{
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* Handle term signal */
void sigterm_handler(int signal)
{
    close(client_sock);
    close(server_sock);
    exit(0);
}

/* Main server loop */
void server_loop()
{
    struct sockaddr_in client_addr;
    int addrlen = sizeof(client_addr);

    while (TRUE) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, (socklen_t *)&addrlen);
        if (fork() == 0) { // handle client connection in a separate process
            close(server_sock);
            handle_client(client_sock, client_addr);
            exit(0);
        }
        close(client_sock);
    }

}

/* Handle client connection */
void handle_client(int client_sock, struct sockaddr_in client_addr)
{
    if ((remote_sock = create_connection()) < 0) {
        perror("Cannot connect to host");
        return;
    }

    init_clinet_ssl(remote_sock);//get ssl

    if (fork() == 0) { // a process forwarding data from client to remote socket

        forward_data_up(client_sock, remote_sock);

        exit(0);
    }

    if (fork() == 0) { // a process forwarding data from remote socket to client

        forward_data_down(remote_sock, client_sock);

        exit(0);
    }

    close(remote_sock);
    close(client_sock);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

/* Forward data between sockets */
void forward_data_up(int source_sock, int destination_sock)
{
    char buffer[BUF_SIZE]={'\0'};
    int n;

    while ((n = recv(source_sock, buffer, BUF_SIZE, 0)) > 0) { // read data from input socket
        //send(destination_sock, buffer, n, 0); // send data to output socket
        SSL_write(ssl, buffer, n);
    }

    shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
    close(destination_sock);

    shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
    close(source_sock);
}

/* Forward data between sockets */
void forward_data_down(int source_sock, int destination_sock)
{
    char buffer[BUF_SIZE]={'\0'};
    int n=0;

    while ((n = SSL_read(ssl, buffer, sizeof(buffer))) > 0) { // read data from input socket
    printf("vpn client rec vpn server:%s\nlen:%d\n",buffer,n);
    //char msg[] = "send...";
    //send(destination_sock, msg, strlen(msg), 0);
    send(destination_sock, buffer, n, 0); // send data to output socket
    memset(buffer,0,BUF_SIZE);
    }

    shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
    close(destination_sock);

    shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
    close(source_sock);
}


/* Create client connection */
int create_connection()
{
    struct sockaddr_in server_addr;
    struct hostent *server;
    int sock;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return CLIENT_SOCKET_ERROR;
    }

    if ((server = gethostbyname(remote_host)) == NULL) {
        errno = EFAULT;
        return CLIENT_RESOLVE_ERROR;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(remote_port);

    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        return CLIENT_CONNECT_ERROR;
    }

    return sock;
}

void init_clinet_ssl(int server)
{
    SSL_library_init();
    ctx = InitCTX();
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
    }

}
SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL ) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    } else
        printf("No certificates.\n");
}
