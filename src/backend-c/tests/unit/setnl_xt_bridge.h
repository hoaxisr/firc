#ifndef FIRC_TEST_SETNL_XT_BRIDGE_H
#define FIRC_TEST_SETNL_XT_BRIDGE_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fake_iptables.h"
#include "fake_setnl.h"
#include "fake_xtables.h"

#define SETNL_XT_BRIDGE_EVENTS 1024
#define SETNL_XT_BRIDGE_NAMES 64

typedef struct {
    char what[12];
    char name[FIRC_SET_NAME_MAX];
    uint64_t at;
} setnl_xt_event_t;

typedef struct {
    fake_setnl_t *sets;
    firc_fake_ipt_t *ipt[2];
    pthread_mutex_t mu;
    uint64_t step;
    uint16_t next_index;
    struct {
        char name[FIRC_SET_NAME_MAX];
        uint16_t index;
    } names[SETNL_XT_BRIDGE_NAMES];
    size_t n_names;
    setnl_xt_event_t ev[SETNL_XT_BRIDGE_EVENTS];
    size_t n_ev;
    bool overflow;
    void (*then)(const char *what, const char *name, void *ud);
    void *then_ud;
} setnl_xt_bridge_t;

static inline uint64_t bridge_stamp_locked(setnl_xt_bridge_t *b, const char *what, const char *name) {
    uint64_t at = ++b->step;
    if (b->n_ev < SETNL_XT_BRIDGE_EVENTS) {
        setnl_xt_event_t *e = &b->ev[b->n_ev++];
        snprintf(e->what, sizeof(e->what), "%s", what);
        snprintf(e->name, sizeof(e->name), "%s", name);
        e->at = at;
    } else {
        b->overflow = true;
    }
    return at;
}

static inline firc_fake_xt_t *bridge_xt_of(setnl_xt_bridge_t *b, const char *name) {
    size_t len = strlen(name);
    firc_fake_ipt_t *f = len > 0 && name[len - 1] == '6' ? b->ipt[1] : b->ipt[0];
    return f != NULL ? firc_fake_ipt_xt(f) : NULL;
}

static inline long bridge_find_locked(setnl_xt_bridge_t *b, const char *name) {
    for (size_t i = 0; i < b->n_names; i++) {
        if (strcmp(b->names[i].name, name) == 0) { return (long)i; }
    }
    return -1;
}

static inline void bridge_put_locked(setnl_xt_bridge_t *b, const char *name, uint16_t index) {
    long at = bridge_find_locked(b, name);
    if (at < 0 && b->n_names < SETNL_XT_BRIDGE_NAMES) { at = (long)b->n_names++; }
    if (at < 0) { return; }
    snprintf(b->names[at].name, sizeof(b->names[at].name), "%s", name);
    b->names[at].index = index;
    firc_fake_xt_t *xt = bridge_xt_of(b, name);
    if (xt != NULL) { firc_fake_xt_set(xt, name, index); }
}

static inline void bridge_drop_locked(setnl_xt_bridge_t *b, const char *name) {
    long at = bridge_find_locked(b, name);
    if (at >= 0) { b->names[at] = b->names[--b->n_names]; }
    firc_fake_xt_t *xt = bridge_xt_of(b, name);
    if (xt != NULL) { firc_fake_xt_set_drop(xt, name); }
}

static inline void bridge_on_step(const char *what, const char *name, void *ud) {
    setnl_xt_bridge_t *b = ud;
    fake_setnl_meta_t meta;
    bool busy = strcmp(what, "destroy") == 0 && fake_setnl_meta(b->sets, name, &meta) && meta.referenced;
    pthread_mutex_lock(&b->mu);
    bridge_stamp_locked(b, what, name);
    if (strcmp(what, "create") == 0) {
        bridge_put_locked(b, name, ++b->next_index);
    } else if (strcmp(what, "rename") == 0) {
        long at = bridge_find_locked(b, name);
        size_t len = strlen(name);
        if (at >= 0 && len >= 2 && name[len - 2] == 'T') {
            uint16_t index = b->names[at].index;
            char to[FIRC_SET_NAME_MAX];
            snprintf(to, sizeof(to), "%s", name);
            to[len - 2] = 'S';
            bridge_drop_locked(b, name);
            bridge_put_locked(b, to, index);
        }
    } else if (strcmp(what, "destroy") == 0 && !busy && name[0] != '\0') {
        bridge_drop_locked(b, name);
    }
    void (*then)(const char *, const char *, void *) = b->then;
    void *then_ud = b->then_ud;
    pthread_mutex_unlock(&b->mu);
    if (then != NULL) { then(what, name, then_ud); }
}

static inline void bridge_on_table(void *ud) {
    setnl_xt_bridge_t *b = ud;
    pthread_mutex_lock(&b->mu);
    bridge_stamp_locked(b, "table", "");
    pthread_mutex_unlock(&b->mu);
}

static inline void bridge_attach(setnl_xt_bridge_t *b, fake_setnl_t *sets, firc_fake_ipt_t *ipt4,
                                 firc_fake_ipt_t *ipt6) {
    memset(b, 0, sizeof(*b));
    pthread_mutex_init(&b->mu, NULL);
    b->sets = sets;
    b->ipt[0] = ipt4;
    b->ipt[1] = ipt6;
    fake_setnl_on_step(sets, bridge_on_step, b);
    for (int i = 0; i < 2; i++) {
        if (b->ipt[i] != NULL) { firc_fake_ipt_on_write(b->ipt[i], bridge_on_table, b); }
    }
}

static inline void bridge_detach(setnl_xt_bridge_t *b) {
    if (b->sets == NULL) { return; }
    fake_setnl_on_step(b->sets, NULL, NULL);
    for (int i = 0; i < 2; i++) {
        if (b->ipt[i] != NULL) { firc_fake_ipt_on_write(b->ipt[i], NULL, NULL); }
    }
    pthread_mutex_destroy(&b->mu);
    b->sets = NULL;
}

static inline void bridge_then(setnl_xt_bridge_t *b, void (*fn)(const char *what, const char *name, void *ud),
                               void *ud) {
    pthread_mutex_lock(&b->mu);
    b->then = fn;
    b->then_ud = ud;
    pthread_mutex_unlock(&b->mu);
}

static inline uint64_t bridge_now(setnl_xt_bridge_t *b) {
    pthread_mutex_lock(&b->mu);
    uint64_t at = b->step;
    pthread_mutex_unlock(&b->mu);
    return at;
}

static inline size_t bridge_count_since(setnl_xt_bridge_t *b, uint64_t since, const char *what, const char *name) {
    size_t n = 0;
    pthread_mutex_lock(&b->mu);
    if (b->overflow) {
        pthread_mutex_unlock(&b->mu);
        return SIZE_MAX;
    }
    for (size_t i = 0; i < b->n_ev; i++) {
        const setnl_xt_event_t *e = &b->ev[i];
        if (e->at > since && strcmp(e->what, what) == 0 && (name == NULL || strcmp(e->name, name) == 0)) { n++; }
    }
    pthread_mutex_unlock(&b->mu);
    return n;
}

static inline uint64_t bridge_first_since(setnl_xt_bridge_t *b, uint64_t since, const char *what, const char *name) {
    uint64_t at = 0;
    pthread_mutex_lock(&b->mu);
    if (b->overflow) {
        pthread_mutex_unlock(&b->mu);
        return 0;
    }
    for (size_t i = 0; i < b->n_ev && at == 0; i++) {
        const setnl_xt_event_t *e = &b->ev[i];
        if (e->at > since && strcmp(e->what, what) == 0 && (name == NULL || strcmp(e->name, name) == 0)) {
            at = e->at;
        }
    }
    pthread_mutex_unlock(&b->mu);
    return at;
}

static inline uint64_t bridge_last_since(setnl_xt_bridge_t *b, uint64_t since, const char *what, const char *name) {
    uint64_t at = 0;
    pthread_mutex_lock(&b->mu);
    if (b->overflow) {
        pthread_mutex_unlock(&b->mu);
        return 0;
    }
    for (size_t i = 0; i < b->n_ev; i++) {
        const setnl_xt_event_t *e = &b->ev[i];
        if (e->at > since && strcmp(e->what, what) == 0 && (name == NULL || strcmp(e->name, name) == 0)) {
            at = e->at;
        }
    }
    pthread_mutex_unlock(&b->mu);
    return at;
}

#endif
