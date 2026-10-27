#define _POSIX_C_SOURCE 200809L
#include "aes.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_LINE 512


static int hex_val(char c);

static int valid_key(const char *s)
{
    size_t n = strlen(s);
    if (n != 16 && n != 24 && n != 32) return 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 33 || (unsigned char)s[i] > 126 || s[i] == '|')
            return 0;
    return 1;
}

static void trim_newline(char *s)
{
    s[strcspn(s, "\r\n")] = '\0';
}

static void ask_key(const char *name, char *key)
{
    char line[128];
    for (;;) {
        printf("Master key %s (16/24/32 karakter): ", name);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) exit(1);
        trim_newline(line);
        if (valid_key(line)) {
            strcpy(key, line);
            return;
        }
        puts("Key harus 16, 24, atau 32 karakter tanpa spasi");
    }
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int read_line(int fd, char *out, size_t cap)
{
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) return 0;
        if (c == '\n') {
            if (n && out[n - 1] == '\r') n--;
            out[n] = '\0';
            return 1;
        }
        out[n++] = c;
    }
    return 0;
}

static int random_bytes(unsigned char *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;

    int ok = fread(out, 1, len, f) == len;
    fclose(f);
    return ok;
}

static int encrypt_hex(const char *key, const char *plain,
                       char *hex, size_t hex_size)
{
    size_t len = strlen(plain);
    size_t blocks = len / AES_BLOCK_SIZE + 1;
    size_t padded = blocks * AES_BLOCK_SIZE;

    if (padded > 256 || hex_size < 32 + padded * 2 + 1)
        return 0;

    unsigned char input[256], output[256];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char prev[AES_BLOCK_SIZE];
    unsigned char block[AES_BLOCK_SIZE];

    if (!random_bytes(iv, sizeof(iv)))
        return 0;

    memcpy(input, plain, len);
    memset(input + len, (int)(padded - len), padded - len);

    AesContext ctx;
    if (aesInit(&ctx, (const uint8_t *)key, strlen(key)) != AES_OK)
        return 0;

    memcpy(prev, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < padded; i += AES_BLOCK_SIZE) {
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            block[j] = input[i + j] ^ prev[j];

        aesEncryptBlock(&ctx, block, output + i);
        memcpy(prev, output + i, AES_BLOCK_SIZE);
    }

    aesDeinit(&ctx);

    static const char digits[] = "0123456789ABCDEF";
    size_t total = AES_BLOCK_SIZE + padded;

    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
        hex[2 * i] = digits[iv[i] >> 4];
        hex[2 * i + 1] = digits[iv[i] & 15];
    }

    for (size_t i = 0; i < padded; i++) {
        hex[2 * (AES_BLOCK_SIZE + i)] = digits[output[i] >> 4];
        hex[2 * (AES_BLOCK_SIZE + i) + 1] = digits[output[i] & 15];
    }

    hex[total * 2] = '\0';
    return 1;
}

static int decrypt_hex(const char *key, const char *hex,
                       char *plain, size_t cap)
{
    size_t hl = strlen(hex);

    if (hl < 64 || hl % 32 != 0 || hl / 2 > 272)
        return 0;

    size_t total = hl / 2;
    size_t n = total - AES_BLOCK_SIZE;

    if (n > 256)
        return 0;

    unsigned char in[272], out[256];
    unsigned char prev[AES_BLOCK_SIZE];
    unsigned char cipher_block[AES_BLOCK_SIZE];

    for (size_t i = 0; i < total; i++) {
        int hi = hex_val(hex[2 * i]);
        int lo = hex_val(hex[2 * i + 1]);

        if (hi < 0 || lo < 0)
            return 0;

        in[i] = (unsigned char)((hi << 4) | lo);
    }

    memcpy(prev, in, AES_BLOCK_SIZE);

    AesContext ctx;
    if (aesInit(&ctx, (const uint8_t *)key, strlen(key)) != AES_OK)
        return 0;

    for (size_t i = 0; i < n; i += AES_BLOCK_SIZE) {
        memcpy(cipher_block, in + AES_BLOCK_SIZE + i, AES_BLOCK_SIZE);
        aesDecryptBlock(&ctx, in + AES_BLOCK_SIZE + i, out + i);
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++)
            out[i + j] ^= prev[j];
        memcpy(prev, cipher_block, AES_BLOCK_SIZE);
    }

    aesDeinit(&ctx);

    unsigned pad = out[n - 1];
    if (pad < 1 || pad > AES_BLOCK_SIZE || pad > n)
        return 0;

    for (unsigned i = 0; i < pad; i++) {
        if (out[n - 1 - i] != pad)
            return 0;
    }

    size_t len = n - pad;
    if (len + 1 > cap)
        return 0;

    memcpy(plain, out, len);
    plain[len] = '\0';
    return 1;
}

static int split(char *s, char **part, int max)
{
    int n = 0;
    part[n++] = s;
    while (n < max && (s = strchr(s, '|'))) {
        *s++ = '\0';
        part[n++] = s;
    }
    return n;
}


static int connect_to(const char *ip, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        fprintf(stderr, "IP tidak valid: %s\n", ip);
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }
    return fd;
}

static int listen_on(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) || listen(fd, 1)) {
        perror("bind/listen");
        close(fd);
        return -1;
    }
    return fd;
}


static void chat(int fd, const char *ks)
{
    printf("\nKomunikasi AES aktif. Session key: %s\n", ks);
    printf("/quit untuk keluar.\n");

    for (;;) {
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(STDIN_FILENO, &rs);
        FD_SET(fd, &rs);
        int mx = fd > STDIN_FILENO ? fd : STDIN_FILENO;
        if (select(mx + 1, &rs, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (FD_ISSET(fd, &rs)) {
            char line[MAX_LINE], plain[256];
            if (!read_line(fd, line, sizeof(line))) {
                puts("Disconnected");
                break;
            }
            printf("[ciphertext in] %s\n", line);
            if (!strncmp(line, "MSG|", 4) && decrypt_hex(ks, line + 4, plain, sizeof(plain)))
                printf("[plaintext in] %s\n", plain);
            else
                puts("message invalid");
        }

        if (FD_ISSET(STDIN_FILENO, &rs)) {
            char text[200], hex[513];
            if (!fgets(text, sizeof(text), stdin)) break;
            trim_newline(text);
            if (!strcmp(text, "/quit")) break;
            if (!text[0]) continue;
            if (!encrypt_hex(ks, text, hex, sizeof(hex))) continue;
            dprintf(fd, "MSG|%s\n", hex);
            printf("[ciphertext out] MSG|%s\n", hex);
        }
    }
}

static int run_alice(const char *kdc_ip, int kdc_port, const char *bob_ip, int bob_port)
{
    char ka[33], line[MAX_LINE], plain[256], ks[17], *p[4], *q[5];
    ask_key("Alice", ka);

    uint32_t n1 = (uint32_t)rand();
    int kfd = connect_to(kdc_ip, kdc_port);
    if (kfd < 0) return 1;
    dprintf(kfd, "1|alice|bob|%u\n", n1);
    printf("[1] Alice -> KDC: 1|alice|bob|%u\n", n1);

    if (!read_line(kfd, line, sizeof(line))) {
        puts("KDC tidak membalas.");
        close(kfd);
        return 1;
    }
    close(kfd);
    printf("[2] KDC -> Alice: %s\n", line);

    if (split(line, p, 3) != 3 || strcmp(p[0], "2")) {
        puts("Balasan KDC tidak valid (lihat pesan di atas).");
        return 1;
    }
    const char *ticket = p[2];
    if (!decrypt_hex(ka, p[1], plain, sizeof(plain))) {
        puts("Gagal dekripsi balasan KDC (master key Alice salah?).");
        return 1;
    }
    char want[16];
    snprintf(want, sizeof(want), "%u", n1);
    if (split(plain, q, 4) != 4 || strlen(q[0]) != 16 || strcmp(q[1], "alice") ||
        strcmp(q[2], "bob") || strcmp(q[3], want)) {
        puts("Isi balasan KDC tidak cocok (ID atau nonce N1 salah).");
        return 1;
    }
    strcpy(ks, q[0]);
    printf("    Session key Ks = %s (N1 cocok)\n", ks);

    int fd = connect_to(bob_ip, bob_port);
    if (fd < 0) return 1;
    dprintf(fd, "3|%s\n", ticket);
    printf("[3] Alice -> Bob: 3|%s\n", ticket);

    char line2[MAX_LINE];
    if (!read_line(fd, line2, sizeof(line2))) {
        puts("Bob tidak membalas (ticket ditolak?).");
        close(fd);
        return 1;
    }
    printf("[4] Bob -> Alice: %s\n", line2);
    if (split(line2, p, 2) != 2 || strcmp(p[0], "4") ||
        !decrypt_hex(ks, p[1], plain, sizeof(plain))) {
        puts("Pesan langkah 4 tidak valid.");
        close(fd);
        return 1;
    }
    unsigned long n2 = strtoul(plain, NULL, 10);
    printf("    N2 = %lu\n", n2);

    char buf[32], hex[128];
    snprintf(buf, sizeof(buf), "%lu", n2 - 1);
    if (!encrypt_hex(ks, buf, hex, sizeof(hex))) { close(fd); return 1; }
    dprintf(fd, "5|%s\n", hex);
    printf("[5] Alice -> Bob: 5|%s  (f(N2) = %s)\n", hex, buf);

    chat(fd, ks);
    close(fd);
    return 0;
}

static int run_bob(int port)
{
    char kb[33], line[MAX_LINE], plain[256], ks[17], *p[3], *q[3];
    ask_key("Bob", kb);

    int srv = listen_on(port);
    if (srv < 0) return 1;
    printf("Bob menunggu Alice di port %d ...\n", port);
    int fd = accept(srv, NULL, NULL);
    close(srv);
    if (fd < 0) { perror("accept"); return 1; }

    if (!read_line(fd, line, sizeof(line))) { close(fd); return 1; }
    printf("[3] Alice -> Bob: %s\n", line);
    if (split(line, p, 2) != 2 || strcmp(p[0], "3") ||
        !decrypt_hex(kb, p[1], plain, sizeof(plain))) {
        puts("Ticket tidak valid (master key Bob salah?).");
        close(fd);
        return 1;
    }
    if (split(plain, q, 2) != 2 || strlen(q[0]) != 16 || strcmp(q[1], "alice")) {
        puts("Isi ticket tidak valid.");
        close(fd);
        return 1;
    }
    strcpy(ks, q[0]);
    printf("    Session key Ks = %s (dari: %s)\n", ks, q[1]);

    unsigned long n2 = 1 + (unsigned long)rand() % 1000000000UL;
    char buf[32], hex[128];
    snprintf(buf, sizeof(buf), "%lu", n2);
    if (!encrypt_hex(ks, buf, hex, sizeof(hex))) { close(fd); return 1; }
    dprintf(fd, "4|%s\n", hex);
    printf("[4] Bob -> Alice: 4|%s  (N2 = %lu)\n", hex, n2);

    if (!read_line(fd, line, sizeof(line))) { close(fd); return 1; }
    printf("[5] Alice -> Bob: %s\n", line);
    snprintf(buf, sizeof(buf), "%lu", n2 - 1);
    if (split(line, p, 2) != 2 || strcmp(p[0], "5") ||
        !decrypt_hex(ks, p[1], plain, sizeof(plain)) || strcmp(plain, buf)) {
        puts("Langkah 5 gagal: f(N2) tidak cocok.");
        close(fd);
        return 1;
    }
    puts("    f(N2) cocok. Alice terautentikasi.");

    chat(fd, ks);
    close(fd);
    return 0;
}


static void usage(const char *prog)
{
    fprintf(stderr,
            " How to run:\n"
            "  %s bob   <port_listen>\n"
            "  %s alice <kdc_ip> <kdc_port> <bob_ip> <bob_port>\n",
            prog, prog);
}

static int parse_port(const char *s)
{
    char *end;
    long p = strtol(s, &end, 10);
    return (*end || p < 1 || p > 65535) ? -1 : (int)p;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    if (argc == 3 && !strcmp(argv[1], "bob")) {
        int port = parse_port(argv[2]);
        if (port < 0) { usage(argv[0]); return 1; }
        return run_bob(port);
    }
    if (argc == 6 && !strcmp(argv[1], "alice")) {
        int kp = parse_port(argv[3]), bp = parse_port(argv[5]);
        if (kp < 0 || bp < 0) { usage(argv[0]); return 1; }
        return run_alice(argv[2], kp, argv[4], bp);
    }
    usage(argv[0]);
    return 1;
}