#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#define PORT 4433
#define SERVER "127.0.0.1"
#define CA_CERT "/home/mnemo/ssl_certs/ca.crt"  // Сертификат удостоверяющего центра для проверки сервера
#define CLIENT_CERT "/home/mnemo/ssl_certs/client/client.crt"  // Клиентский сертификат
#define CLIENT_KEY "/home/mnemo/ssl_certs/client/client.key"   // Клиентский приватный ключ

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    /* Загружаем CA сертификат для проверки сервера */
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Устанавливаем уровень проверки */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    /* Если используется клиентский сертификат */
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(EXIT_FAILURE);
    }
}

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    if (!preverify_ok) {
        fprintf(stderr, "Certificate verification failed\n");
        return 0;
    }

    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    
    printf("Certificate verification depth: %d\n", depth);
    
    if (depth == 0) {  // Это сертификат конечного объекта (сервера)
        char *subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Server certificate subject: %s\n", subject);
        OPENSSL_free(subject);
    }

    return 1;
}

int main(int argc, char **argv) {
    SSL_CTX *ctx;
    int sock;
    struct sockaddr_in addr;
    SSL *ssl;
    char buf[1024];
    int bytes;
    X509 *cert;

    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

    /* Проверяем сертификат сервера */
    cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char *subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        
        printf("Server certificate:\nSubject: %s\nIssuer: %s\n", subject, issuer);
        
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK) {
            printf("Certificate verification error: %s\n", X509_verify_cert_error_string(verify_result));
        } else {
            printf("Certificate verified successfully\n");
        }
        
        OPENSSL_free(subject);
        OPENSSL_free(issuer);
        X509_free(cert);
    } else {
        printf("No server certificate provided\n");
    }

    bytes = SSL_read(ssl, buf, sizeof(buf));
    buf[bytes] = 0;
    printf("Received: %s", buf);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}