#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h> // Добавлен для работы с X509

#define PORT 4433
#define SERVER_CERT "/home/mnemo/ssl_certs/server/server.crt"
#define SERVER_KEY "/home/mnemo/ssl_certs/server/server.key"
#define CA_CERT "/home/mnemo/ssl_certs/ca.crt"

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

int check_certificate_validity(X509 *cert)
{
    if (!cert)
    {
        printf("No certificate provided\n");
        return 0;
    }

    ASN1_TIME *notBefore = X509_get_notBefore(cert);
    ASN1_TIME *notAfter = X509_get_notAfter(cert);

    time_t now = time(NULL);
    int days, seconds;

    if (X509_cmp_time(notBefore, &now) > 0)
    {
        printf("Certificate is not yet valid\n");
        return 0;
    }

    if (X509_cmp_time(notAfter, &now) < 0)
    {
        printf("Certificate has expired\n");
        return 0;
    }

    printf("Certificate is valid\n");
    return 1;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != 1)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    if (!preverify_ok)
    {
        fprintf(stderr, "Certificate verification failed\n");
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    int sock, client;
    struct sockaddr_in addr;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    { // Добавлено < 0
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        SSL *ssl;
        const char reply[] = "Hello from SSL server!\n";
        X509 *cert;

        client = accept(sock, (struct sockaddr *)&client_addr, &len);
        if (client < 0)
        {
            perror("Unable to accept");
            continue;
        }

        printf("Client connected: %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
            continue;
        }
        cert = SSL_get_peer_certificate(ssl);
        if (cert)
        {
            char *subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
            char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

            printf("Client certificate:\nSubject: %s\nIssuer: %s\n", subject, issuer);

            check_certificate_validity(cert);

            OPENSSL_free(subject);
            OPENSSL_free(issuer);
            X509_free(cert);
        }
        else
        {
            printf("No client certificate provided\n");
        }

        SSL_write(ssl, reply, strlen(reply));

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}