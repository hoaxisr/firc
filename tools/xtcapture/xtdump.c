#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "v4") != 0 && strcmp(argv[1], "v6") != 0) || strlen(argv[2]) >= 32) {
        fprintf(stderr, "usage: xtdump v4|v6 TABLE OUT_FILE\n");
        return 2;
    }
    int v6 = strcmp(argv[1], "v6") == 0;
    int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) { perror("socket"); return 1; }
    int level = v6 ? 41 : 0;
    unsigned char info[84];
    memset(info, 0, sizeof(info));
    memcpy(info, argv[2], strlen(argv[2]));
    socklen_t len = sizeof(info);
    if (getsockopt(fd, level, 64, info, &len) != 0) { perror("GET_INFO"); return 1; }
    uint32_t size;
    memcpy(&size, info + 80, sizeof(size));
    unsigned char *ent = calloc(1, 40u + size);
    if (ent == NULL) { return 1; }
    memcpy(ent, argv[2], strlen(argv[2]));
    memcpy(ent + 32, &size, sizeof(size));
    len = (socklen_t)(40u + size);
    if (getsockopt(fd, level, 65, ent, &len) != 0) { perror("GET_ENTRIES"); return 1; }
    FILE *out = fopen(argv[3], "wb");
    if (out == NULL) { perror(argv[3]); return 1; }
    if (fwrite(info, 1, sizeof(info), out) != sizeof(info) || fwrite(ent + 40, 1, size, out) != size) {
        perror("write");
        return 1;
    }
    fclose(out);
    free(ent);
    close(fd);
    printf("%s %s: %u bytes\n", argv[1], argv[2], size);
    return 0;
}
