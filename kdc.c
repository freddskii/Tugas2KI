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
#include <sys/time.h>
#include <unistd.h>

#define MAX_LINE 512

static char key_alice[33];
static char key_bob[33];
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
        printf("Master key %s (16/24/32 karakter ASCII): ", name);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) exit(1);
        trim_newline(line);
        if (valid_key(line)) {
            strcpy(key, line);
            return;
        }
        puts("Key harus 16, 24, atau 32 karakter ASCII tanpa spasi dan '|'.");
    }
}

static int session_key(char out[17])
{
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    unsigned char random[16];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    int ok = fread(random, 1, sizeof(random), f) == sizeof(random);
    fclose(f);
    if (!ok) return 0;
    for (int i = 0; i < 16; i++) out[i] = chars[random[i] % (sizeof(chars) - 1)];
    out[16] = '\0';
    return 1;
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
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

static int valid_nonce(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 10) return 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9') return 0;
    return strtoull(s, NULL, 10) <= UINT32_MAX;
}

static void handle_client(int fd)
{
    char line[MAX_LINE], ticket[257], response[257], plain[256], ks[17];
    char *part[4], *cursor;
    if (!read_line(fd, line, sizeof(line))) return;
    printf("Request: %s\n", line);

    cursor = line;
    for (int i = 0; i < 3; i++) {
        part[i] = cursor;
        cursor = strchr(cursor, '|');
        if (!cursor) {
            dprintf(fd, "ERR|format request salah\n");
            return;
        }
        *cursor++ = '\0';
    }
    part[3] = cursor;
    if (strchr(part[3], '|') || strcmp(part[0], "1") || !valid_nonce(part[3]) ||
        !((!strcmp(part[1], "alice") && !strcmp(part[2], "bob")) ||
          (!strcmp(part[1], "bob") && !strcmp(part[2], "alice")))) {
        dprintf(fd, "ERR|format request salah\n");
        return;
    }

    const char *sender_key = !strcmp(part[1], "alice") ? key_alice : key_bob;
    const char *target_key = !strcmp(part[2], "alice") ? key_alice : key_bob;
    if (!session_key(ks)) {
        dprintf(fd, "ERR|gagal membuat session key\n");
        return;
    }

    snprintf(plain, sizeof(plain), "%s|%s", ks, part[1]);
    if (!encrypt_hex(target_key, plain, ticket, sizeof(ticket))) return;
    snprintf(plain, sizeof(plain), "%s|%s|%s|%s", ks, part[1], part[2], part[3]);
    if (!encrypt_hex(sender_key, plain, response, sizeof(response))) return;

    dprintf(fd, "2|%s|%s\n", response, ticket);
    printf("Balasan: 2|%s|%s\n", response, ticket);
}

int main(int argc, char **argv)
{
    int port = 5000;
    if (argc > 2) {
        fprintf(stderr, "Pemakaian: %s [port]\n", argv[0]);
        return 1;
    }
    if (argc == 2) {
        char *end;
        long p = strtol(argv[1], &end, 10);
        if (*end || p < 1 || p > 65535) {
            fprintf(stderr, "Port harus 1..65535\n");
            return 1;
        }
        port = (int)p;
    }

    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    ask_key("Alice", key_alice);
    ask_key("Bob", key_bob);

    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) { perror("socket"); return 1; }
    int reuse = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) || listen(server, 5)) {
        perror("bind/listen");
        close(server);
        return 1;
    }

    printf("KDC berjalan di port %d. Perintah: /key alice|bob KEY, /quit\n", port);
    int watch_stdin = 1;
    for (;;) {
        fd_set ready;
        FD_ZERO(&ready);
        FD_SET(server, &ready);
        if (watch_stdin) FD_SET(STDIN_FILENO, &ready);
        if (select(server + 1, &ready, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (FD_ISSET(server, &ready)) {
            int client = accept(server, NULL, NULL);
            if (client >= 0) {
                struct timeval timeout = {.tv_sec = 5};
                setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
                handle_client(client);
                close(client);
            }
        }
        if (watch_stdin && FD_ISSET(STDIN_FILENO, &ready)) {
            char command[128], id[32], key[64], extra;
            if (!fgets(command, sizeof(command), stdin)) {
                watch_stdin = 0;
                continue;
            }
            trim_newline(command);
            if (!strcmp(command, "/quit")) break;
            if (sscanf(command, "/key %31s %63s %c", id, key, &extra) == 2 &&
                valid_key(key) && (!strcmp(id, "alice") || !strcmp(id, "bob"))) {
                strcpy(!strcmp(id, "alice") ? key_alice : key_bob, key);
                printf("Master key %s diperbarui.\n", id);
            } else {
                puts("Perintah: /key alice|bob KEY, /quit");
            }
        }
    }
    close(server);
    return 0;
}