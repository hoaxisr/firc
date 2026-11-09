#define _GNU_SOURCE
#include <alloca.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "unit.h"
#include "tstack.h"

static __thread volatile char g_tls[600 * 1024];

static void *walk(void *a) {
    size_t n = *(size_t *)a;
    g_tls[0] = 1;
    volatile char *p = alloca(n);
    for (size_t i = n; i > 0; i -= i > 4096 ? 4096 : i) p[i - 1] = 1;
    return (void *)(intptr_t)p[0];
}

static int survives(size_t usable) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        pthread_attr_t a;
        pthread_attr_init(&a);
        if (tstack_set(&a, usable)) _exit(3);
        pthread_t t;
        if (pthread_create(&t, &a, walk, &usable)) _exit(2);
        pthread_join(t, NULL);
        _exit(0);
    }
    int st = -1;
    if (pid < 0 || waitpid(pid, &st, 0) != pid) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

int main(void) {
    /* catches: a thread-local block left out of the count */
    check("the TLS counted covers the test's own", 1, tstack_tls() >= sizeof g_tls);
    /* catches: a stack sized as asked, without the TLS glibc carves out of it */
    check("128 KiB usable under 600 KiB of TLS: touched", 0, survives(128 * 1024));
    /* catches: a fixed 1 MiB stack, enough only while the TLS is small */
    check("1 MiB usable under 600 KiB of TLS: touched", 0, survives(1024 * 1024));
    return unit_done("tstackmatch");
}
