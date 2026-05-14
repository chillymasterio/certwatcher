/*
 * certwatcher - SSL/TLS certificate monitoring tool
 * Check expiry dates, chain issues, and certificate details.
 *
 * License: MIT
 */

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ocsp.h>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "libssl.lib")
  #pragma comment(lib, "libcrypto.lib")
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <arpa/inet.h>
  #define closesocket close
  typedef int SOCKET;
  #define INVALID_SOCKET (-1)
#endif

#define CW_VERSION "1.0.0"
#define MAX_HOSTS 256
#define DEFAULT_PORT "443"
#define DEFAULT_WARN_DAYS 30

/* ── Color output ── */

static int use_color = 1;

#define C_RED     (use_color ? "\033[31m" : "")
#define C_GREEN   (use_color ? "\033[32m" : "")
#define C_YELLOW  (use_color ? "\033[33m" : "")
#define C_BLUE    (use_color ? "\033[34m" : "")
#define C_CYAN    (use_color ? "\033[36m" : "")
#define C_BOLD    (use_color ? "\033[1m" : "")
#define C_DIM     (use_color ? "\033[2m" : "")
#define C_RESET   (use_color ? "\033[0m" : "")

static void detect_color(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    use_color = 0;
    if (GetConsoleMode(h, &mode)) {
        if (SetConsoleMode(h, mode | 0x0004))
            use_color = 1;
    }
#else
    if (!isatty(1)) use_color = 0;
#endif
}

/* ── Network init ── */

static int net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    return 0;
#endif
}

static void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* ── Time helpers ── */

static time_t asn1_to_time(const ASN1_TIME *t) {
    struct tm tm_result;
    memset(&tm_result, 0, sizeof(tm_result));
    if (ASN1_TIME_to_tm(t, &tm_result) != 1)
        return 0;
    return mktime(&tm_result);
}

static int days_until(time_t target) {
    time_t now = time(NULL);
    double diff = difftime(target, now);
    return (int)(diff / 86400.0);
}

static void format_time(time_t t, char *buf, size_t len) {
    struct tm *tm = gmtime(&t);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S UTC", tm);
}

static void format_relative(int days, char *buf, size_t len) {
    if (days < 0) {
        int d = -days;
        if (d == 1) snprintf(buf, len, "yesterday");
        else if (d < 7) snprintf(buf, len, "%d days ago", d);
        else if (d < 30) snprintf(buf, len, "%d weeks ago", d / 7);
        else if (d < 365) snprintf(buf, len, "%d months ago", d / 30);
        else snprintf(buf, len, "%d years ago", d / 365);
    } else if (days == 0) {
        snprintf(buf, len, "today");
    } else if (days == 1) {
        snprintf(buf, len, "tomorrow");
    } else if (days < 7) {
        snprintf(buf, len, "in %d days", days);
    } else if (days < 30) {
        snprintf(buf, len, "in %d weeks", days / 7);
    } else if (days < 365) {
        snprintf(buf, len, "in %d months", days / 30);
    } else {
        snprintf(buf, len, "in %d years", days / 365);
    }
}

/* ── Certificate info struct ── */

typedef struct {
    char host[256];
    char port[16];
    int connected;
    int ssl_ok;
    char ip_addr[64];

    /* Subject */
    char subject[512];
    char issuer[512];
    char common_name[256];
    char serial[128];

    /* SANs */
    char sans[2048];
    int san_count;

    /* Validity */
    time_t not_before;
    time_t not_after;
    int days_left;

    /* Details */
    char sig_algo[64];
    int key_bits;
    char key_type[32];
    char fingerprint_sha256[128];
    int version;

    /* Chain */
    int chain_depth;
    char chain_subjects[10][256];
    int chain_valid;
    long verify_result;
    char verify_error[256];

    /* TLS info */
    char tls_version[32];
    char cipher[128];
    int cipher_bits;

    /* PEM data */
    char pem[8192];

    /* Timing */
    double connect_ms;
    double tls_ms;
    double total_ms;
} cert_info_t;

/* ── STARTTLS helpers ── */

enum starttls_proto { STARTTLS_NONE = 0, STARTTLS_SMTP, STARTTLS_IMAP, STARTTLS_FTP };

static int do_starttls(SOCKET sock, enum starttls_proto proto) {
    char buf[1024];
    int n;

    switch (proto) {
    case STARTTLS_SMTP:
        /* Read greeting */
        n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return -1;
        buf[n] = '\0';
        /* Send EHLO */
        send(sock, "EHLO certwatcher\r\n", 18, 0);
        n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return -1;
        buf[n] = '\0';
        /* Send STARTTLS */
        send(sock, "STARTTLS\r\n", 10, 0);
        n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return -1;
        buf[n] = '\0';
        if (strncmp(buf, "220", 3) != 0) return -1;
        break;

    case STARTTLS_IMAP:
        n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return -1;
        send(sock, "a001 STARTTLS\r\n", 15, 0);
        n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return -1;
        buf[n] = '\0';
        if (strstr(buf, "OK") == NULL) return -1;
        break;

    case STARTTLS_FTP:
        n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return -1;
        send(sock, "AUTH TLS\r\n", 10, 0);
        n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return -1;
        buf[n] = '\0';
        if (strncmp(buf, "234", 3) != 0) return -1;
        break;

    case STARTTLS_NONE:
    default:
        break;
    }
    return 0;
}

/* ── Get certificate from host ── */

static int fetch_cert(const char *host, const char *port, int timeout_sec,
                      const char *sni_name, enum starttls_proto starttls,
                      cert_info_t *info) {
    struct addrinfo hints, *res;
    SOCKET sock;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    X509 *cert = NULL;
    int ret = -1;

    memset(info, 0, sizeof(*info));
    strncpy(info->host, host, sizeof(info->host) - 1);
    strncpy(info->port, port, sizeof(info->port) - 1);

    struct timespec ts_start, ts_conn, ts_tls;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    /* Resolve */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;

    /* Extract resolved IP address */
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, info->ip_addr, sizeof(info->ip_addr));
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &sa6->sin6_addr, info->ip_addr, sizeof(info->ip_addr));
    }

    /* Connect */
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return -1;
    }

    /* Non-blocking connect with timeout */
    {
#ifdef _WIN32
        unsigned long nb = 1;
        ioctlsocket(sock, FIONBIO, &nb);
#else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
        int rc = connect(sock, res->ai_addr, (int)res->ai_addrlen);
        if (rc != 0) {
#ifdef _WIN32
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
#else
            if (errno != EINPROGRESS) {
#endif
                closesocket(sock);
                freeaddrinfo(res);
                return -1;
            }
            fd_set wfds;
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            if (select((int)sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
                closesocket(sock);
                freeaddrinfo(res);
                return -1;
            }
            int serr = 0;
            socklen_t slen = sizeof(serr);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&serr, &slen);
            if (serr != 0) {
                closesocket(sock);
                freeaddrinfo(res);
                return -1;
            }
        }
        /* Back to blocking */
#ifdef _WIN32
        nb = 0;
        ioctlsocket(sock, FIONBIO, &nb);
#else
        fcntl(sock, F_SETFL, flags);
#endif
    }
    freeaddrinfo(res);
    info->connected = 1;
    clock_gettime(CLOCK_MONOTONIC, &ts_conn);
    info->connect_ms = (ts_conn.tv_sec - ts_start.tv_sec) * 1000.0
                     + (ts_conn.tv_nsec - ts_start.tv_nsec) / 1e6;

    /* Set read/write timeouts */
    {
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
    }

    /* STARTTLS negotiation if needed */
    if (starttls != STARTTLS_NONE) {
        if (do_starttls(sock, starttls) != 0) {
            closesocket(sock);
            return -1;
        }
    }

    /* SSL handshake */
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { closesocket(sock); return -1; }

    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); closesocket(sock); return -1; }

    SSL_set_fd(ssl, (int)sock);
    SSL_set_tlsext_host_name(ssl, (char *)(sni_name ? sni_name : host));

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sock);
        return -1;
    }
    info->ssl_ok = 1;
    clock_gettime(CLOCK_MONOTONIC, &ts_tls);
    info->tls_ms = (ts_tls.tv_sec - ts_conn.tv_sec) * 1000.0
                 + (ts_tls.tv_nsec - ts_conn.tv_nsec) / 1e6;
    info->total_ms = (ts_tls.tv_sec - ts_start.tv_sec) * 1000.0
                   + (ts_tls.tv_nsec - ts_start.tv_nsec) / 1e6;

    /* TLS info */
    strncpy(info->tls_version, SSL_get_version(ssl), sizeof(info->tls_version) - 1);
    strncpy(info->cipher, SSL_get_cipher_name(ssl), sizeof(info->cipher) - 1);
    info->cipher_bits = SSL_get_cipher_bits(ssl, NULL);

    /* Verify */
    info->verify_result = SSL_get_verify_result(ssl);
    if (info->verify_result == X509_V_OK) {
        info->chain_valid = 1;
    } else {
        strncpy(info->verify_error,
                X509_verify_cert_error_string(info->verify_result),
                sizeof(info->verify_error) - 1);
    }

    /* Get certificate */
    cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sock);
        return -1;
    }

    /* Subject & Issuer */
    X509_NAME_oneline(X509_get_subject_name(cert), info->subject, sizeof(info->subject));
    X509_NAME_oneline(X509_get_issuer_name(cert), info->issuer, sizeof(info->issuer));

    /* Common Name */
    X509_NAME *subj = X509_get_subject_name(cert);
    int cn_idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
    if (cn_idx >= 0) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, cn_idx);
        ASN1_STRING *asn1 = X509_NAME_ENTRY_get_data(e);
        const char *cn = (const char *)ASN1_STRING_get0_data(asn1);
        strncpy(info->common_name, cn, sizeof(info->common_name) - 1);
    }

    /* Serial */
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn) {
        char *hex = BN_bn2hex(bn);
        if (hex) {
            strncpy(info->serial, hex, sizeof(info->serial) - 1);
            OPENSSL_free(hex);
        }
        BN_free(bn);
    }

    /* Version */
    info->version = (int)X509_get_version(cert) + 1;

    /* Validity */
    info->not_before = asn1_to_time(X509_get0_notBefore(cert));
    info->not_after = asn1_to_time(X509_get0_notAfter(cert));
    info->days_left = days_until(info->not_after);

    /* SANs */
    GENERAL_NAMES *sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans) {
        int n = sk_GENERAL_NAME_num(sans);
        info->san_count = n;
        info->sans[0] = '\0';
        int i;
        for (i = 0; i < n && strlen(info->sans) < sizeof(info->sans) - 100; i++) {
            GENERAL_NAME *gen = sk_GENERAL_NAME_value(sans, i);
            if (gen->type == GEN_DNS) {
                const char *dns = (const char *)ASN1_STRING_get0_data(gen->d.dNSName);
                if (i > 0) strncat(info->sans, ", ", sizeof(info->sans) - strlen(info->sans) - 1);
                strncat(info->sans, dns, sizeof(info->sans) - strlen(info->sans) - 1);
            }
        }
        GENERAL_NAMES_free(sans);
    }

    /* Key info */
    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    if (pkey) {
        info->key_bits = EVP_PKEY_bits(pkey);
        int pkey_id = EVP_PKEY_id(pkey);
        switch (pkey_id) {
        case EVP_PKEY_RSA: strncpy(info->key_type, "RSA", sizeof(info->key_type)); break;
        case EVP_PKEY_EC: strncpy(info->key_type, "EC", sizeof(info->key_type)); break;
        case EVP_PKEY_ED25519: strncpy(info->key_type, "Ed25519", sizeof(info->key_type)); break;
        default: snprintf(info->key_type, sizeof(info->key_type), "type-%d", pkey_id); break;
        }
    }

    /* Signature algorithm */
    int sig_nid = X509_get_signature_nid(cert);
    const char *sig_name = OBJ_nid2ln(sig_nid);
    if (sig_name)
        strncpy(info->sig_algo, sig_name, sizeof(info->sig_algo) - 1);

    /* SHA256 fingerprint */
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (X509_digest(cert, EVP_sha256(), md, &md_len)) {
        char *p = info->fingerprint_sha256;
        unsigned int i;
        for (i = 0; i < md_len; i++) {
            if (i > 0) *p++ = ':';
            p += sprintf(p, "%02X", md[i]);
        }
    }

    /* Chain */
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    if (chain) {
        info->chain_depth = sk_X509_num(chain);
        int i;
        for (i = 0; i < info->chain_depth && i < 10; i++) {
            X509 *c = sk_X509_value(chain, i);
            X509_NAME_oneline(X509_get_subject_name(c),
                              info->chain_subjects[i],
                              sizeof(info->chain_subjects[i]));
        }
    }

    /* Extract PEM */
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            if (PEM_write_bio_X509(bio, cert)) {
                BUF_MEM *bptr;
                BIO_get_mem_ptr(bio, &bptr);
                if (bptr && bptr->length > 0 && bptr->length < sizeof(info->pem)) {
                    memcpy(info->pem, bptr->data, bptr->length);
                    info->pem[bptr->length] = '\0';
                }
            }
            BIO_free(bio);
        }
    }

    ret = 0;

    X509_free(cert);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(sock);

    return ret;
}

/* ── Output formatters ── */

static void print_cert_normal(const cert_info_t *info, int warn_days, int verbose) {
    const char *status_color;
    const char *status_text;

    if (info->days_left < 0) {
        status_color = C_RED;
        status_text = "EXPIRED";
    } else if (info->days_left <= warn_days) {
        status_color = C_YELLOW;
        status_text = "EXPIRING SOON";
    } else {
        status_color = C_GREEN;
        status_text = "VALID";
    }

    printf("\n%s%s:%s%s\n", C_BOLD, info->host, info->port, C_RESET);
    char rel[64];
    format_relative(info->days_left, rel, sizeof(rel));
    printf("  Status:      %s%s%s", status_color, status_text, C_RESET);
    if (info->days_left >= 0)
        printf(" (%d days remaining, expires %s)", info->days_left, rel);
    else
        printf(" (expired %d days ago, %s)", -info->days_left, rel);
    printf("\n");

    printf("  Subject:     %s\n", info->common_name);
    printf("  Issuer:      %s\n", info->issuer);

    char buf[64];
    format_time(info->not_before, buf, sizeof(buf));
    printf("  Valid from:  %s\n", buf);
    format_time(info->not_after, buf, sizeof(buf));
    printf("  Valid until: %s\n", buf);

    printf("  Key:         %s %d bits\n", info->key_type, info->key_bits);
    printf("  Signature:   %s\n", info->sig_algo);
    printf("  TLS:         %s (%s, %d bits)\n",
           info->tls_version, info->cipher, info->cipher_bits);

    if (!info->chain_valid) {
        printf("  Chain:       %s%s%s\n", C_RED, info->verify_error, C_RESET);
    } else {
        printf("  Chain:       %s%d certificates, valid%s\n",
               C_GREEN, info->chain_depth, C_RESET);
    }

    printf("  Timing:      %.0f ms connect, %.0f ms TLS, %.0f ms total\n",
           info->connect_ms, info->tls_ms, info->total_ms);

    if (verbose) {
        if (info->ip_addr[0])
            printf("  IP:          %s\n", info->ip_addr);
        printf("  Version:     X.509v%d\n", info->version);
        printf("  Serial:      %s\n", info->serial);
        printf("  SHA-256:     %s\n", info->fingerprint_sha256);

        if (info->san_count > 0) {
            printf("  SANs (%d):   %s\n", info->san_count, info->sans);
        }

        if (info->chain_depth > 0) {
            int i;
            printf("  Chain detail:\n");
            for (i = 0; i < info->chain_depth && i < 10; i++) {
                printf("    [%d] %s\n", i, info->chain_subjects[i]);
            }
        }
    }
}

static void print_cert_oneline(const cert_info_t *info, int warn_days) {
    const char *status_color;
    const char *status_icon;

    if (info->days_left < 0) {
        status_color = C_RED;
        status_icon = "EXPIRED";
    } else if (info->days_left <= warn_days) {
        status_color = C_YELLOW;
        status_icon = "WARNING";
    } else {
        status_color = C_GREEN;
        status_icon = "OK";
    }

    printf("%s%-8s%s %-40s %4d days  %s  %s %d  %s\n",
           status_color, status_icon, C_RESET,
           info->host,
           info->days_left,
           info->tls_version,
           info->key_type, info->key_bits,
           info->issuer);
}

static void print_cert_json(const cert_info_t *info) {
    char nb[64], na[64];
    format_time(info->not_before, nb, sizeof(nb));
    format_time(info->not_after, na, sizeof(na));

    printf("  {\n");
    printf("    \"host\": \"%s\",\n", info->host);
    printf("    \"port\": \"%s\",\n", info->port);
    printf("    \"common_name\": \"%s\",\n", info->common_name);
    printf("    \"issuer\": \"%s\",\n", info->issuer);
    printf("    \"not_before\": \"%s\",\n", nb);
    printf("    \"not_after\": \"%s\",\n", na);
    printf("    \"days_left\": %d,\n", info->days_left);
    printf("    \"key_type\": \"%s\",\n", info->key_type);
    printf("    \"key_bits\": %d,\n", info->key_bits);
    printf("    \"sig_algo\": \"%s\",\n", info->sig_algo);
    printf("    \"tls_version\": \"%s\",\n", info->tls_version);
    printf("    \"cipher\": \"%s\",\n", info->cipher);
    printf("    \"cipher_bits\": %d,\n", info->cipher_bits);
    printf("    \"chain_valid\": %s,\n", info->chain_valid ? "true" : "false");
    printf("    \"chain_depth\": %d,\n", info->chain_depth);
    printf("    \"serial\": \"%s\",\n", info->serial);
    printf("    \"fingerprint_sha256\": \"%s\",\n", info->fingerprint_sha256);
    printf("    \"san_count\": %d,\n", info->san_count);
    printf("    \"version\": %d\n", info->version);
    printf("  }");
}

static void print_cert_csv(const cert_info_t *info) {
    char na[64];
    format_time(info->not_after, na, sizeof(na));
    printf("%s,%s,%s,%s,%d,%s,%s,%d,%s,%d\n",
           info->host, info->port, info->common_name, info->issuer,
           info->days_left, na, info->key_type, info->key_bits,
           info->tls_version, info->chain_valid);
}

/* ── Usage ── */

static void usage(const char *prog) {
    fprintf(stderr,
        "certwatcher %s - SSL/TLS certificate monitoring tool\n"
        "\n"
        "Usage: %s [options] <host> [host2 ...]\n"
        "       %s [options] -f <hostfile>\n"
        "\n"
        "Options:\n"
        "  -p <port>       Port (default: 443)\n"
        "  -t <sec>        Connection timeout (default: 10)\n"
        "  -w <days>       Warning threshold for expiry (default: 30)\n"
        "  -f <file>       Read hosts from file (one per line)\n"
        "  -s <name>       Override SNI hostname\n"
        "  -v              Verbose output (SANs, chain, serial, fingerprint)\n"
        "  -1              One-line output per host\n"
        "  --csv           CSV output\n"
        "  --json          JSON output\n"
        "  --no-color      Disable colors\n"
        "  --expired-only  Only show expired or expiring certs\n"
        "  --exit-warn     Exit 1 if any cert expiring within threshold\n"
        "  -V, --version   Show version\n"
        "  -h, --help      Show this help\n"
        "\n"
        "Examples:\n"
        "  %s google.com github.com\n"
        "  %s -w 14 -1 example.com\n"
        "  %s --json -f hosts.txt\n"
        "  %s -v -w 60 prod-api.example.com\n"
        "\n", CW_VERSION, prog, prog, prog, prog, prog, prog);
}

/* ── Main ── */

int main(int argc, char **argv) {
    const char *hosts[MAX_HOSTS];
    int nhost = 0;
    const char *port = DEFAULT_PORT;
    int timeout_sec = 10;
    int warn_days = DEFAULT_WARN_DAYS;
    const char *hostfile = NULL;
    const char *sni = NULL;
    int verbose = 0;
    int oneline = 0;
    int csv = 0;
    int json = 0;
    int expired_only = 0;
    int exit_warn = 0;
    int quiet = 0;
    int sort_by_expiry = 0;
    int pem_output = 0;
    const char *output_file = NULL;
    enum starttls_proto starttls = STARTTLS_NONE;
    int i;

    /* Parse args */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("certwatcher %s\n", CW_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            timeout_sec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            warn_days = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            hostfile = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            sni = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            quiet = 1;
        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--sort") == 0) {
            sort_by_expiry = 1;
        } else if (strcmp(argv[i], "--pem") == 0) {
            pem_output = 1;
        } else if (strcmp(argv[i], "-1") == 0) {
            oneline = 1;
        } else if (strcmp(argv[i], "--csv") == 0) {
            csv = 1;
        } else if (strcmp(argv[i], "--json") == 0) {
            json = 1;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            use_color = 0;
        } else if (strcmp(argv[i], "--expired-only") == 0) {
            expired_only = 1;
        } else if (strcmp(argv[i], "--exit-warn") == 0) {
            exit_warn = 1;
        } else if (strcmp(argv[i], "--starttls") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "smtp") == 0) starttls = STARTTLS_SMTP;
            else if (strcmp(argv[i], "imap") == 0) starttls = STARTTLS_IMAP;
            else if (strcmp(argv[i], "ftp") == 0) starttls = STARTTLS_FTP;
            else {
                fprintf(stderr, "Unknown STARTTLS protocol: %s (use smtp, imap, ftp)\n", argv[i]);
                return 1;
            }
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        } else if (nhost < MAX_HOSTS) {
            hosts[nhost++] = argv[i];
        }
    }

    /* Read hosts from file */
    if (hostfile) {
        FILE *f = fopen(hostfile, "r");
        if (!f) {
            fprintf(stderr, "Cannot open host file: %s\n", hostfile);
            return 1;
        }
        static char line_bufs[MAX_HOSTS][256];
        char line[256];
        while (fgets(line, sizeof(line), f) && nhost < MAX_HOSTS) {
            /* Strip newline and comments */
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            char *comment = strchr(line, '#');
            if (comment) *comment = '\0';
            /* Trim whitespace */
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '\0') continue;
            strncpy(line_bufs[nhost], p, sizeof(line_bufs[nhost]) - 1);
            hosts[nhost] = line_bufs[nhost];
            nhost++;
        }
        fclose(f);
    }

    if (nhost == 0) {
        usage(argv[0]);
        return 1;
    }

    /* Redirect output to file if requested */
    if (output_file) {
        FILE *of = freopen(output_file, "w", stdout);
        if (!of) {
            fprintf(stderr, "Cannot open output file: %s\n", output_file);
            return 1;
        }
        use_color = 0;
    }

    /* Init */
    detect_color();
    net_init();
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    int any_warn = 0;
    int any_error = 0;
    int count_ok = 0, count_warn = 0, count_err = 0;

    /* Collect all results */
    static cert_info_t results[MAX_HOSTS];
    int nresults = 0;

    for (i = 0; i < nhost; i++) {
        /* Parse host:port */
        char host_buf[256];
        const char *h = hosts[i];
        const char *p = port;
        const char *colon = strrchr(h, ':');
        if (colon && colon != h) {
            size_t hlen = colon - h;
            if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
            memcpy(host_buf, h, hlen);
            host_buf[hlen] = '\0';
            h = host_buf;
            p = colon + 1;
        }

        cert_info_t info;
        int rc = fetch_cert(h, p, timeout_sec, sni, starttls, &info);

        if (rc != 0) {
            if (!quiet && !json && !csv) {
                if (oneline)
                    printf("%sERROR%s   %-40s  connection failed\n", C_RED, C_RESET, h);
                else
                    printf("\n%s%s:%s%s\n  %sConnection failed%s\n", C_BOLD, h, p, C_RESET, C_RED, C_RESET);
            }
            any_error = 1;
            count_err++;
            continue;
        }

        if (info.days_left <= warn_days) {
            any_warn = 1;
            count_warn++;
        } else {
            count_ok++;
        }

        if (expired_only && info.days_left > warn_days)
            continue;

        results[nresults++] = info;
    }

    /* Sort by days remaining if requested */
    if (sort_by_expiry && nresults > 1) {
        int j;
        for (i = 0; i < nresults - 1; i++) {
            for (j = i + 1; j < nresults; j++) {
                if (results[j].days_left < results[i].days_left) {
                    cert_info_t tmp = results[i];
                    results[i] = results[j];
                    results[j] = tmp;
                }
            }
        }
    }

    /* Print results */
    if (csv)
        printf("host,port,cn,issuer,days_left,expires,key_type,key_bits,tls,chain_valid\n");
    if (json)
        printf("[\n");

    for (i = 0; i < nresults; i++) {
        if (!quiet) {
            if (pem_output) {
                printf("# %s:%s\n%s", results[i].host, results[i].port, results[i].pem);
            } else if (json) {
                if (i > 0) printf(",\n");
                print_cert_json(&results[i]);
            } else if (csv) {
                print_cert_csv(&results[i]);
            } else if (oneline) {
                print_cert_oneline(&results[i], warn_days);
            } else {
                print_cert_normal(&results[i], warn_days, verbose);
            }
        }
    }

    if (json)
        printf("\n]\n");

    /* Summary line */
    if (!quiet && !json && !csv && !oneline && nhost > 1) {
        printf("\n%s--- Summary: %d hosts checked: ", C_DIM, nhost);
        if (count_ok > 0) printf("%s%d valid%s", C_GREEN, count_ok, C_DIM);
        if (count_warn > 0) printf("%s%s%d expiring%s", count_ok ? ", " : "", C_YELLOW, count_warn, C_DIM);
        if (count_err > 0) printf("%s%s%d errors%s", (count_ok || count_warn) ? ", " : "", C_RED, count_err, C_DIM);
        printf(" ---%s\n", C_RESET);
    }

    net_cleanup();

    if (exit_warn && any_warn) return 1;
    if (any_error) return 2;
    return 0;
}
