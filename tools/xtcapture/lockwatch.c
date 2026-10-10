#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static unsigned long held_inode(void) {
    FILE *f = fopen("/proc/net/unix", "r");
    if (f == NULL) { return 0; }
    char line[512];
    unsigned long ino = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, " @xtables\n") == NULL) { continue; }
        if (sscanf(line, "%*s %*s %*s %*s %*s %*s %lu", &ino) != 1) { ino = 0; }
        break;
    }
    fclose(f);
    return ino;
}

static void owner(unsigned long ino, char *out, size_t cap) {
    char want[64];
    snprintf(want, sizeof(want), "socket:[%lu]", ino);
    snprintf(out, cap, "pid=? comm=?");
    DIR *proc = opendir("/proc");
    if (proc == NULL) { return; }
    struct dirent *p;
    while ((p = readdir(proc)) != NULL) {
        if (p->d_name[0] < '0' || p->d_name[0] > '9') { continue; }
        char fdpath[300];
        snprintf(fdpath, sizeof(fdpath), "/proc/%s/fd", p->d_name);
        DIR *fds = opendir(fdpath);
        if (fds == NULL) { continue; }
        struct dirent *fd;
        int found = 0;
        while (!found && (fd = readdir(fds)) != NULL) {
            char link[600], target[128];
            snprintf(link, sizeof(link), "%s/%s", fdpath, fd->d_name);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n <= 0) { continue; }
            target[n] = '\0';
            found = strcmp(target, want) == 0;
        }
        closedir(fds);
        if (found) {
            char comm[64] = "?", cpath[300];
            snprintf(cpath, sizeof(cpath), "/proc/%s/comm", p->d_name);
            FILE *c = fopen(cpath, "r");
            if (c != NULL) {
                if (fgets(comm, sizeof(comm), c) != NULL) { comm[strcspn(comm, "\n")] = '\0'; }
                fclose(c);
            }
            snprintf(out, cap, "pid=%s comm=%s", p->d_name, comm);
            break;
        }
    }
    closedir(proc);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: lockwatch SECONDS\n");
        return 2;
    }
    long end = now_ms() + atol(argv[1]) * 1000L;
    unsigned long last = 0;
    struct timespec pause = {0, 20 * 1000 * 1000};
    while (now_ms() < end) {
        unsigned long ino = held_inode();
        if (ino != 0 && ino != last) {
            char who[128];
            owner(ino, who, sizeof(who));
            printf("%ld held inode=%lu %s\n", now_ms(), ino, who);
            fflush(stdout);
        } else if (ino == 0 && last != 0) {
            printf("%ld released\n", now_ms());
            fflush(stdout);
        }
        last = ino;
        nanosleep(&pause, NULL);
    }
    return 0;
}
