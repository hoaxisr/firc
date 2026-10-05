#include "fake_nflog.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netlink.h>

#include "firc/nlattr_iter.h"

struct fake_nflog {
    int fd;
    pthread_t th;
    pthread_mutex_t mu;
    bool stop;
    bool bound;
    uint16_t group;
    bool has_mode;
    uint8_t copy_mode;
    uint32_t copy_range;
    bool has_qthresh;
    uint32_t qthresh;
    bool has_timeout;
    uint32_t timeout;
    bool saw_pf;
    size_t configs;
    int refuse_next;
    bool stray_first;
    bool swallow_next;
    bool garbage_first;
    bool garbage_short;
};

/* Acks a failed request always and a successful one only when it asked (NLM_F_ACK). */
static void send_ack(int fd, const struct nlmsghdr *req, int err) {
    if (err == 0 && !(req->nlmsg_flags & NLM_F_ACK)) { return; }
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    h->nlmsg_type = NLMSG_ERROR;
    h->nlmsg_len = (uint32_t)(NLMSG_HDRLEN + sizeof(struct nlmsgerr));
    h->nlmsg_seq = req->nlmsg_seq;
    struct nlmsgerr *e = (struct nlmsgerr *)(buf + NLMSG_HDRLEN);
    e->error = err;
    e->msg = *req;
    (void)!send(fd, buf, h->nlmsg_len, 0);
}

/* nfulnl_recv_config, as the shipped kernel has it. */
static void handle(fake_nflog_t *f, const struct nlmsghdr *h) {
    const struct nfgenmsg *g = (const struct nfgenmsg *)((const uint8_t *)h + NLMSG_HDRLEN);
    uint16_t group = ntohs(g->res_id);

    const struct nlattr *cmd_a = NULL, *mode_a = NULL, *qt_a = NULL, *to_a = NULL;
    firc_nlattr_iter_t it;
    const struct nlattr *a = NULL;
    if (firc_nlattr_iter_init_nlmsg(&it, h, sizeof(*g))) {
        while (firc_nlattr_iter_next(&it, &a)) {
            switch (a->nla_type) {
            case NFULA_CFG_CMD: cmd_a = a; break;
            case NFULA_CFG_MODE: mode_a = a; break;
            case NFULA_CFG_QTHRESH: qt_a = a; break;
            case NFULA_CFG_TIMEOUT: to_a = a; break;
            default: break;
            }
        }
    }

    pthread_mutex_lock(&f->mu);
    f->configs++;
    if (f->stray_first) {
        f->stray_first = false;
        pthread_mutex_unlock(&f->mu);
        struct nlmsghdr stray = *h;
        stray.nlmsg_seq = 0;
        send_ack(f->fd, &stray, -EPERM);
        pthread_mutex_lock(&f->mu);
    }
    if (f->garbage_first) {
        f->garbage_first = false;
        pthread_mutex_unlock(&f->mu);
        _Alignas(4) uint8_t buf[64];
        memset(buf, 0, sizeof(buf));
        struct nlmsghdr *bad = (struct nlmsghdr *)buf;
        bad->nlmsg_type = NLMSG_ERROR;
        bad->nlmsg_seq = h->nlmsg_seq;
        bad->nlmsg_len = (f->garbage_short ? (uint32_t)NLMSG_HDRLEN + 2u : 4096u);
        size_t n = f->garbage_short ? (size_t)NLMSG_HDRLEN + 2u : (size_t)NLMSG_HDRLEN;
        (void)!send(f->fd, buf, n, 0);
        return;
    }
    if (f->swallow_next) {
        f->swallow_next = false;
        pthread_mutex_unlock(&f->mu);
        return;
    }
    if (f->refuse_next != 0) {
        int err = f->refuse_next;
        f->refuse_next = 0;
        pthread_mutex_unlock(&f->mu);
        send_ack(f->fd, h, err);
        return;
    }

    uint8_t cmd = 0xff;
    if (cmd_a != NULL) {
        cmd = *((const uint8_t *)cmd_a + 4);
        if (cmd == NFULNL_CFG_CMD_PF_BIND || cmd == NFULNL_CFG_CMD_PF_UNBIND) {
            f->saw_pf = true;
            pthread_mutex_unlock(&f->mu);
            send_ack(f->fd, h, 0);
            return;
        }
        if (cmd == NFULNL_CFG_CMD_BIND) {
            if (f->bound) {
                pthread_mutex_unlock(&f->mu);
                send_ack(f->fd, h, -EBUSY);
                return;
            }
            f->bound = true;
            f->group = group;
        } else if (cmd == NFULNL_CFG_CMD_UNBIND) {
            if (!f->bound) {
                pthread_mutex_unlock(&f->mu);
                send_ack(f->fd, h, -ENODEV);
                return;
            }
            f->bound = false;
            pthread_mutex_unlock(&f->mu);
            send_ack(f->fd, h, 0);
            return;
        } else {
            pthread_mutex_unlock(&f->mu);
            send_ack(f->fd, h, -524);
            return;
        }
    } else if (!f->bound) {
        pthread_mutex_unlock(&f->mu);
        send_ack(f->fd, h, -ENODEV);
        return;
    }

    if (mode_a != NULL) {
        const struct nfulnl_msg_config_mode *m =
            (const struct nfulnl_msg_config_mode *)((const uint8_t *)mode_a + 4);
        f->has_mode = true;
        f->copy_mode = m->copy_mode;
        f->copy_range = ntohl(m->copy_range);
    }
    if (qt_a != NULL) {
        uint32_t v;
        memcpy(&v, (const uint8_t *)qt_a + 4, 4);
        f->has_qthresh = true;
        f->qthresh = ntohl(v);
    }
    if (to_a != NULL) {
        uint32_t v;
        memcpy(&v, (const uint8_t *)to_a + 4, 4);
        f->has_timeout = true;
        f->timeout = ntohl(v);
    }
    pthread_mutex_unlock(&f->mu);
    send_ack(f->fd, h, 0);
}

static void *run(void *ud) {
    fake_nflog_t *f = ud;
    for (;;) {
        uint8_t buf[2048];
        ssize_t r = recv(f->fd, buf, sizeof(buf), 0);
        if (r <= 0) { return NULL; }
        pthread_mutex_lock(&f->mu);
        bool stop = f->stop;
        pthread_mutex_unlock(&f->mu);
        if (stop) { return NULL; }
        if ((size_t)r < NLMSG_HDRLEN) { continue; }
        const struct nlmsghdr *h = (const struct nlmsghdr *)buf;
        if (h->nlmsg_len > (uint32_t)r) { continue; }
        if (!(h->nlmsg_flags & NLM_F_REQUEST)) {
            send_ack(f->fd, h, 0);
            continue;
        }
        if ((h->nlmsg_type >> 8) == NFNL_SUBSYS_ULOG &&
            (h->nlmsg_type & 0xff) == NFULNL_MSG_CONFIG) {
            handle(f, h);
        }
    }
}

fake_nflog_t *fake_nflog_start(int *daemon_fd) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) { return NULL; }
    fake_nflog_t *f = calloc(1, sizeof(*f));
    if (f == NULL) {
        close(sv[0]);
        close(sv[1]);
        return NULL;
    }
    f->fd = sv[1];
    pthread_mutex_init(&f->mu, NULL);
    if (pthread_create(&f->th, NULL, run, f) != 0) {
        close(sv[0]);
        close(sv[1]);
        pthread_mutex_destroy(&f->mu);
        free(f);
        return NULL;
    }
    *daemon_fd = sv[0];
    return f;
}

void fake_nflog_stop(fake_nflog_t *f) {
    if (f == NULL) { return; }
    pthread_mutex_lock(&f->mu);
    f->stop = true;
    pthread_mutex_unlock(&f->mu);
    shutdown(f->fd, SHUT_RDWR);
    pthread_join(f->th, NULL);
    close(f->fd);
    pthread_mutex_destroy(&f->mu);
    free(f);
}

bool fake_nflog_send(fake_nflog_t *f, const void *buf, size_t len) {
    return send(f->fd, buf, len, 0) == (ssize_t)len;
}

bool fake_nflog_is_bound(fake_nflog_t *f, uint16_t *group_out) {
    pthread_mutex_lock(&f->mu);
    bool b = f->bound;
    if (group_out != NULL) { *group_out = f->group; }
    pthread_mutex_unlock(&f->mu);
    return b;
}

bool fake_nflog_mode(fake_nflog_t *f, uint8_t *copy_mode, uint32_t *copy_range) {
    pthread_mutex_lock(&f->mu);
    bool b = f->has_mode;
    if (copy_mode != NULL) { *copy_mode = f->copy_mode; }
    if (copy_range != NULL) { *copy_range = f->copy_range; }
    pthread_mutex_unlock(&f->mu);
    return b;
}

bool fake_nflog_qthresh(fake_nflog_t *f, uint32_t *out) {
    pthread_mutex_lock(&f->mu);
    bool b = f->has_qthresh;
    if (out != NULL) { *out = f->qthresh; }
    pthread_mutex_unlock(&f->mu);
    return b;
}

bool fake_nflog_timeout(fake_nflog_t *f, uint32_t *out) {
    pthread_mutex_lock(&f->mu);
    bool b = f->has_timeout;
    if (out != NULL) { *out = f->timeout; }
    pthread_mutex_unlock(&f->mu);
    return b;
}

bool fake_nflog_saw_a_pf_command(fake_nflog_t *f) {
    pthread_mutex_lock(&f->mu);
    bool b = f->saw_pf;
    pthread_mutex_unlock(&f->mu);
    return b;
}

void fake_nflog_ack_garbage_first(fake_nflog_t *f) {
    pthread_mutex_lock(&f->mu);
    f->garbage_first = true;
    f->garbage_short = false;
    pthread_mutex_unlock(&f->mu);
}

void fake_nflog_ack_too_short_first(fake_nflog_t *f) {
    pthread_mutex_lock(&f->mu);
    f->garbage_first = true;
    f->garbage_short = true;
    pthread_mutex_unlock(&f->mu);
}

void fake_nflog_swallow_next(fake_nflog_t *f) {
    pthread_mutex_lock(&f->mu);
    f->swallow_next = true;
    pthread_mutex_unlock(&f->mu);
}

void fake_nflog_stray_ack_first(fake_nflog_t *f) {
    pthread_mutex_lock(&f->mu);
    f->stray_first = true;
    pthread_mutex_unlock(&f->mu);
}

void fake_nflog_refuse_next(fake_nflog_t *f, int err) {
    pthread_mutex_lock(&f->mu);
    f->refuse_next = err;
    pthread_mutex_unlock(&f->mu);
}

size_t fake_nflog_config_messages(fake_nflog_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->configs;
    pthread_mutex_unlock(&f->mu);
    return n;
}

#define ATTR_HDR ((size_t)4)
static size_t attr_step(size_t n) { return (n + 3u) & ~(size_t)3u; }
size_t fake_nflog_hello(uint8_t *out, const char *sni) {
    uint8_t body[512];
    size_t b = 0;
    body[b++] = 0x03;
    body[b++] = 0x03;
    memset(body + b, 0xab, 32);
    b += 32;
    body[b++] = 0;
    body[b++] = 0;
    body[b++] = 2;
    body[b++] = 0x13;
    body[b++] = 0x01;
    body[b++] = 1;
    body[b++] = 0;

    uint8_t ext[256];
    size_t e = 0;
    size_t n = strlen(sni);
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = (uint8_t)((n + 5) >> 8);
    ext[e++] = (uint8_t)(n + 5);
    ext[e++] = (uint8_t)((n + 3) >> 8);
    ext[e++] = (uint8_t)(n + 3);
    ext[e++] = 0x00;
    ext[e++] = (uint8_t)(n >> 8);
    ext[e++] = (uint8_t)n;
    memcpy(ext + e, sni, n);
    e += n;

    body[b++] = (uint8_t)(e >> 8);
    body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e);
    b += e;

    size_t at = 0;
    out[at++] = 0x16;
    out[at++] = 0x03;
    out[at++] = 0x01;
    out[at++] = (uint8_t)((b + 4) >> 8);
    out[at++] = (uint8_t)(b + 4);
    out[at++] = 0x01;
    out[at++] = 0x00;
    out[at++] = (uint8_t)(b >> 8);
    out[at++] = (uint8_t)b;
    memcpy(out + at, body, b);
    return at + b;
}
size_t fake_nflog_packet(uint8_t *out, const uint8_t *src, const uint8_t *dst, uint16_t port,
                     const uint8_t *payload, size_t payload_len) {
    memset(out, 0, 40);
    out[0] = 0x45;
    size_t total = 20 + 20 + payload_len;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[8] = 64;
    out[9] = 6;
    memcpy(out + 12, src, 4);
    memcpy(out + 16, dst, 4);
    out[20] = 0xc0;
    out[21] = 0x00;
    out[22] = (uint8_t)(port >> 8);
    out[23] = (uint8_t)port;
    out[32] = 0x50;
    out[33] = 0x18;
    memcpy(out + 40, payload, payload_len);
    return total;
}
size_t fake_nflog_msg(uint8_t *out, const uint8_t *pkt, size_t pkt_len) {
    struct nlmsghdr *h = (struct nlmsghdr *)out;
    memset(h, 0, NLMSG_HDRLEN);
    h->nlmsg_type = (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET);
    size_t at = NLMSG_HDRLEN;
    memset(out + at, 0, sizeof(struct nfgenmsg));
    at += sizeof(struct nfgenmsg);
    struct nlattr *a = (struct nlattr *)(out + at);
    a->nla_type = NFULA_PAYLOAD;
    a->nla_len = (uint16_t)(ATTR_HDR + pkt_len);
    memcpy(out + at + ATTR_HDR, pkt, pkt_len);
    at += attr_step(a->nla_len);
    h->nlmsg_len = (uint32_t)at;
    return at;
}
