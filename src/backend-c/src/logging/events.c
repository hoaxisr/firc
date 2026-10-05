#include "firc/events.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "firc/rand.h"

/* One lock, held for a struct copy; nothing inside allocates or logs (a log call there would deadlock). */
typedef struct log_slot {
    uint64_t seq;
    int64_t at;
    firc_log_level_t level;
    char text[FIRC_EVENT_TEXT];
} log_slot_t;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static firc_event_t g_dns[FIRC_EVENTS_RING];
static log_slot_t g_log[FIRC_EVENTS_LOG_RING];
static size_t g_dns_head, g_dns_used;
static size_t g_log_head, g_log_used;
static uint64_t g_next_seq = 1;

void firc_event_put(firc_event_t *e)
{
    pthread_mutex_lock(&g_mu);
    e->seq = g_next_seq++;
    if (e->kind == FIRC_EVENT_LOG) {
        log_slot_t *s = &g_log[g_log_head];
        s->seq = e->seq;
        s->at = e->at;
        s->level = e->u.log.level;
        memcpy(s->text, e->u.log.text, sizeof(s->text));
        g_log_head = (g_log_head + 1) % FIRC_EVENTS_LOG_RING;
        if (g_log_used < FIRC_EVENTS_LOG_RING) { g_log_used++; }
    } else {
        g_dns[g_dns_head] = *e;
        g_dns_head = (g_dns_head + 1) % FIRC_EVENTS_RING;
        if (g_dns_used < FIRC_EVENTS_RING) { g_dns_used++; }
    }
    pthread_mutex_unlock(&g_mu);
}

void firc_event_put_log(firc_log_level_t level, int64_t at, const char *text)
{
    firc_event_t e;
    memset(&e, 0, sizeof(e));
    e.kind = FIRC_EVENT_LOG;
    e.at = at;
    e.u.log.level = level;
    snprintf(e.u.log.text, sizeof(e.u.log.text), "%s", text);
    firc_event_put(&e);
}

static size_t slot(size_t head, size_t used, size_t size, size_t i)
{
    return (head + size - used + i) % size;
}

static uint64_t dns_seq(size_t i)
{
    return g_dns[slot(g_dns_head, g_dns_used, FIRC_EVENTS_RING, i)].seq;
}

static uint64_t log_seq(size_t i)
{
    return g_log[slot(g_log_head, g_log_used, FIRC_EVENTS_LOG_RING, i)].seq;
}

static size_t first_after(uint64_t (*seq_at)(size_t), size_t used, uint64_t since)
{
    size_t lo = 0, hi = used;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (seq_at(mid) <= since) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

size_t firc_event_read(uint64_t since, firc_event_t *out, size_t cap,
                       uint64_t *out_next, uint64_t *out_dropped)
{
    if (out == NULL || cap == 0) { return 0; }
    pthread_mutex_lock(&g_mu);
    uint64_t newest = g_next_seq - 1;
    size_t d = first_after(dns_seq, g_dns_used, since);
    size_t l = first_after(log_seq, g_log_used, since);
    size_t n = 0;
    while (n < cap && (d < g_dns_used || l < g_log_used)) {
        bool take_log = d >= g_dns_used || (l < g_log_used && log_seq(l) < dns_seq(d));
        if (take_log) {
            const log_slot_t *s = &g_log[slot(g_log_head, g_log_used, FIRC_EVENTS_LOG_RING, l++)];
            firc_event_t *e = &out[n++];
            memset(e, 0, sizeof(*e));
            e->seq = s->seq;
            e->at = s->at;
            e->kind = FIRC_EVENT_LOG;
            e->u.log.level = s->level;
            memcpy(e->u.log.text, s->text, sizeof(e->u.log.text));
        } else {
            out[n++] = g_dns[slot(g_dns_head, g_dns_used, FIRC_EVENTS_RING, d++)];
        }
    }
    pthread_mutex_unlock(&g_mu);
    /* A reader at 0 has never asked, so nothing is reported dropped for it. */
    uint64_t dropped = 0;
    if (since != 0) {
        if (n > 0) {
            dropped = out[n - 1].seq - since - n;
        } else if (newest > since) {
            dropped = newest - since;
        }
    }
    if (out_dropped != NULL) { *out_dropped = dropped; }
    if (out_next != NULL && n > 0) { *out_next = out[n - 1].seq; }
    return n;
}

/* The random part tells apart two starts in one second (a crash and the init script's restart). */
static char g_boot[32];
static pthread_once_t g_boot_once = PTHREAD_ONCE_INIT;

static void boot_init(void)
{
    uint8_t r[4] = {0, 0, 0, 0};
    (void)firc_random_bytes(r, sizeof(r));
    snprintf(g_boot, sizeof(g_boot), "%llx-%02x%02x%02x%02x", (unsigned long long)time(NULL), r[0],
             r[1], r[2], r[3]);
}

const char *firc_event_boot(void)
{
    pthread_once(&g_boot_once, boot_init);
    return g_boot;
}

void firc_event_reset_for_test(void)
{
    pthread_mutex_lock(&g_mu);
    g_next_seq = 1;
    g_dns_head = g_dns_used = 0;
    g_log_head = g_log_used = 0;
    pthread_mutex_unlock(&g_mu);
}
