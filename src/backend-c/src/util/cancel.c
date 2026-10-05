#include "firc/cancel.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

struct firc_cancel {
    atomic_bool raised;
    pthread_mutex_t mu;
    int rd;
    int wr;
};

static int set_nonblock_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { return -1; }
    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) { return -1; }
    return 0;
}

firc_cancel_t *firc_cancel_new(void) {
    firc_cancel_t *c = calloc(1, sizeof(*c));
    if (!c) { return NULL; }

    int fds[2];
    if (pipe(fds) != 0) {
        free(c);
        return NULL;
    }
    if (set_nonblock_cloexec(fds[0]) != 0 || set_nonblock_cloexec(fds[1]) != 0) {
        close(fds[0]);
        close(fds[1]);
        free(c);
        return NULL;
    }

    c->rd = fds[0];
    c->wr = fds[1];
    atomic_init(&c->raised, false);
    if (pthread_mutex_init(&c->mu, NULL) != 0) {
        close(c->rd);
        close(c->wr);
        free(c);
        return NULL;
    }
    return c;
}

void firc_cancel_free(firc_cancel_t *c) {
    if (!c) { return; }
    pthread_mutex_destroy(&c->mu);
    close(c->rd);
    close(c->wr);
    free(c);
}

void firc_cancel_raise(firc_cancel_t *c) {
    if (!c) { return; }

    pthread_mutex_lock(&c->mu);
    /* Only the false->true transition writes, so the pipe holds at most one byte. */
    bool expected = false;
    if (!atomic_compare_exchange_strong(&c->raised, &expected, true)) {
        pthread_mutex_unlock(&c->mu);
        return;
    }

    const uint8_t byte = 1;
    ssize_t n;
    do {
        n = write(c->wr, &byte, 1);
    } while (n < 0 && errno == EINTR);
    pthread_mutex_unlock(&c->mu);
}

void firc_cancel_clear(firc_cancel_t *c) {
    if (!c) { return; }

    /* The mutex orders the flag change against raise(); without it clear() can eat the byte while raised stays true. */
    pthread_mutex_lock(&c->mu);
    atomic_store(&c->raised, false);

    uint8_t buf[8];
    for (;;) {
        ssize_t n = read(c->rd, buf, sizeof(buf));
        if (n > 0) { continue; }
        if (n < 0 && errno == EINTR) { continue; }
        break;
    }
    pthread_mutex_unlock(&c->mu);
}

bool firc_cancel_raised(const firc_cancel_t *c) {
    if (!c) { return false; }
    return atomic_load(&((firc_cancel_t *)c)->raised);
}

int firc_cancel_fd(const firc_cancel_t *c) {
    return c ? c->rd : -1;
}
