#include "xt_golden.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../../src/xtables/abi.h"

const char *const firc_test_xt_fixtures[] = {
    "empty", "firmware", "firmware-firc", "firmware-firc-remove", "sweep",
    "dedupe-seed", "dedupe", "kept-seed", "dnat2000", "tiny",
};
const size_t firc_test_xt_n_fixtures = sizeof(firc_test_xt_fixtures) / sizeof(firc_test_xt_fixtures[0]);

static const char *const k_hooks[XT_NUMHOOKS] = {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"};

static const char *fam_tag(firc_ipt_proto_t fam) { return fam == FIRC_IPT_PROTO_IPV6 ? "v6" : "v4"; }

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return NULL; }
    size_t cap = 1 << 16, n = 0;
    uint8_t *buf = malloc(cap + 1);
    while (buf != NULL) {
        size_t got = fread(buf + n, 1, cap - n, f);
        n += got;
        if (n < cap) { break; }
        cap *= 2;
        uint8_t *grown = realloc(buf, cap + 1);
        if (grown == NULL) { free(buf); buf = NULL; break; }
        buf = grown;
    }
    fclose(f);
    if (buf != NULL) { buf[n] = '\0'; *len = n; }
    return buf;
}

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void host16(uint8_t *p) { uint16_t v = le16(p); memcpy(p, &v, sizeof(v)); }
static void host32(uint8_t *p) { uint32_t v = le32(p); memcpy(p, &v, sizeof(v)); }
static void host64(uint8_t *p) {
    uint64_t v = (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
    memcpy(p, &v, sizeof(v));
}

uint8_t *firc_test_xt_raw(const char *name, firc_ipt_proto_t fam, size_t *len) {
    char path[256];
    snprintf(path, sizeof(path), "tests/unit/fixtures/xt/%s.%s.replace.bin", name, fam_tag(fam));
    return read_file(path, len);
}

static bool host_payload(firc_ipt_proto_t fam, const char *name, uint8_t rev, uint8_t *p, size_t room, bool target) {
    bool v6 = fam == FIRC_IPT_PROTO_IPV6;
    if (target && name[0] == '\0') {
        if (room < 4) { return false; }
        host32(p);
        return true;
    }
    if (target && strcmp(name, "ERROR") == 0) { return true; }
    if (!target && strcmp(name, "mark") == 0 && rev == 1) {
        if (room < 8) { return false; }
        host32(p);
        host32(p + 4);
        return true;
    }
    if (!target && (strcmp(name, "tcp") == 0 || strcmp(name, "udp") == 0) && rev == 0) {
        if (room < 8) { return false; }
        for (int i = 0; i < 4; i++) { host16(p + 2 * i); }
        return true;
    }
    if (target && !v6 && (strcmp(name, "DNAT") == 0 || strcmp(name, "SNAT") == 0 || strcmp(name, "MASQUERADE") == 0) && rev == 0) {
        if (room < 8) { return false; }
        host32(p);
        host32(p + 4);
        return true;
    }
    bool v6_range = strcmp(name, "MASQUERADE") == 0 ? rev == 0 : rev == 1;
    if (target && v6 && (strcmp(name, "DNAT") == 0 || strcmp(name, "SNAT") == 0 || strcmp(name, "MASQUERADE") == 0) && v6_range) {
        if (room < 4) { return false; }
        host32(p);
        return true;
    }
    return false;
}

bool firc_test_xt_to_host(firc_ipt_proto_t fam, uint8_t *blob, uint32_t size) {
    bool v6 = fam == FIRC_IPT_PROTO_IPV6;
    uint32_t eh = v6 ? 168u : 112u, at_t = v6 ? 140u : 88u, at_proto = v6 ? 128u : 80u;
    uint32_t at_nfc = v6 ? 136u : 84u, at_from = v6 ? 144u : 92u, at_cnt = v6 ? 152u : 96u;
    for (uint32_t off = 0; off < size;) {
        if (size - off < eh) { return false; }
        uint8_t *e = blob + off;
        uint16_t toff = le16(e + at_t), next = le16(e + at_t + 2);
        if (next < eh || next > size - off || toff < eh || toff > next) { return false; }
        for (uint32_t m = eh; m < toff;) {
            uint16_t ms = le16(e + m);
            if (ms < 32u || ms > toff - m) { return false; }
            host16(e + m);
            if (!host_payload(fam, (const char *)e + m + 2, e[m + 31], e + m + 32, ms - 32u, false)) { return false; }
            m += ms;
        }
        uint8_t *t = e + toff;
        uint16_t ts = le16(t);
        if (ts < 32u || (uint32_t)toff + ts != next) { return false; }
        host16(t);
        if (!host_payload(fam, (const char *)t + 2, t[31], t + 32, ts - 32u, true)) { return false; }
        host16(e + at_proto);
        host32(e + at_nfc);
        host16(e + at_t);
        host16(e + at_t + 2);
        host32(e + at_from);
        host64(e + at_cnt);
        host64(e + at_cnt + 8);
        off += next;
    }
    return true;
}

bool firc_test_xt_read(const char *name, firc_ipt_proto_t fam, firc_xt_info_t *info, uint8_t **blob) {
    size_t len = 0;
    uint8_t *raw = firc_test_xt_raw(name, fam, &len);
    if (raw == NULL || len < XT_REPLACE_HDR_LEN) { free(raw); return false; }
    memset(info, 0, sizeof(*info));
    info->valid_hooks = le32(raw + 32);
    info->num_entries = le32(raw + 36);
    info->size = le32(raw + 40);
    for (int h = 0; h < XT_NUMHOOKS; h++) {
        info->hook_entry[h] = le32(raw + 44 + 4 * h);
        info->underflow[h] = le32(raw + 64 + 4 * h);
    }
    if (len != XT_REPLACE_HDR_LEN + info->size) { free(raw); return false; }
    *blob = malloc(info->size ? info->size : 1);
    if (*blob == NULL) { free(raw); return false; }
    memcpy(*blob, raw + XT_REPLACE_HDR_LEN, info->size);
    free(raw);
    if (!firc_test_xt_to_host(fam, *blob, info->size)) { free(*blob); *blob = NULL; return false; }
    return true;
}

char *firc_test_xt_read_text(const char *name, firc_ipt_proto_t fam) {
    char path[256];
    snprintf(path, sizeof(path), "tests/unit/fixtures/xt/%s.%s.save.txt", name, fam_tag(fam));
    size_t len = 0;
    return (char *)read_file(path, &len);
}

typedef struct out {
    char *s;
    size_t n, cap;
    bool ok;
} out_t;

static void say(out_t *o, const char *fmt, ...) {
    if (!o->ok) { return; }
    va_list ap;
    va_start(ap, fmt);
    char tmp[512];
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(tmp)) { o->ok = false; return; }
    if (o->n + (size_t)n + 1 > o->cap) {
        size_t cap = o->cap ? o->cap * 2 : 4096;
        while (cap < o->n + (size_t)n + 1) { cap *= 2; }
        char *g = realloc(o->s, cap);
        if (g == NULL) { o->ok = false; return; }
        o->s = g;
        o->cap = cap;
    }
    memcpy(o->s + o->n, tmp, (size_t)n + 1);
    o->n += (size_t)n;
}

typedef struct pchain {
    const char *name;
    int hook;
    uint32_t head;
    uint32_t first;
    uint32_t end;
} pchain_t;

typedef struct view {
    firc_ipt_proto_t fam;
    const uint8_t *blob;
    uint32_t eh, at_t;
    uint32_t *offs;
    uint32_t n;
    pchain_t chains[512];
    size_t nc;
} view_t;

static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static const uint8_t *target_of(const view_t *v, uint32_t off) {
    return v->blob + off + rd16(v->blob + off + v->at_t);
}

static int prefix_len(const uint8_t *mask, size_t bytes) {
    int len = 0;
    bool done = false;
    for (size_t i = 0; i < bytes; i++) {
        for (int b = 7; b >= 0; b--) {
            bool set = (mask[i] >> b) & 1u;
            if (set && done) { return -1; }
            if (set) { len++; } else { done = true; }
        }
    }
    return len;
}

static bool say_addr(out_t *o, bool v6, const char *flag, const uint8_t *addr, const uint8_t *mask) {
    size_t bytes = v6 ? 16 : 4;
    bool any = false;
    for (size_t i = 0; i < bytes; i++) { any = any || mask[i] != 0; }
    if (!any) { return true; }
    int len = prefix_len(mask, bytes);
    char text[INET6_ADDRSTRLEN];
    if (len < 0 || inet_ntop(v6 ? AF_INET6 : AF_INET, addr, text, sizeof(text)) == NULL) { return false; }
    say(o, " %s %s/%d", flag, text, len);
    return true;
}

static bool say_iface(out_t *o, const char *flag, const char *name, const uint8_t *mask) {
    if (name[0] == '\0') { return true; }
    size_t n = strnlen(name, 16);
    for (size_t i = 0; i < 16; i++) {
        if (mask[i] != (i <= n ? 0xff : 0x00)) { return false; }
    }
    say(o, " %s %s", flag, name);
    return true;
}

static void say_ports(out_t *o, const char *flag, uint16_t lo, uint16_t hi) {
    if (lo == 0 && hi == 0xffff) { return; }
    if (lo == hi) { say(o, " %s %u", flag, lo); } else { say(o, " %s %u:%u", flag, lo, hi); }
}

static const pchain_t *chain_starting_at(const view_t *v, uint32_t off) {
    for (size_t i = 0; i < v->nc; i++) {
        if (v->chains[i].first == off) { return &v->chains[i]; }
    }
    return NULL;
}

static bool say_rule(out_t *o, const view_t *v, uint32_t off) {
    bool v6 = v->fam == FIRC_IPT_PROTO_IPV6;
    const uint8_t *e = v->blob + off;
    uint16_t toff = rd16(e + v->at_t);
    bool go = false;
    if (v6) {
        xt_ip6t_ip6_t ip;
        memcpy(&ip, e, sizeof(ip));
        if (ip.invflags != 0 || (ip.flags & ~(XT_IP6T_F_PROTO | XT_IP6T_F_GOTO)) != 0) { return false; }
        go = (ip.flags & XT_IP6T_F_GOTO) != 0;
        if (!say_addr(o, true, "-s", ip.src, ip.smsk) || !say_addr(o, true, "-d", ip.dst, ip.dmsk)) { return false; }
        if (!say_iface(o, "-i", ip.iniface, ip.iniface_mask) || !say_iface(o, "-o", ip.outiface, ip.outiface_mask)) { return false; }
        if (ip.proto == 6) { say(o, " -p tcp"); } else if (ip.proto == 17) { say(o, " -p udp"); } else if (ip.proto != 0) { return false; }
    } else {
        xt_ipt_ip_t ip;
        memcpy(&ip, e, sizeof(ip));
        if (ip.invflags != 0 || (ip.flags & ~XT_IPT_F_GOTO) != 0) { return false; }
        go = (ip.flags & XT_IPT_F_GOTO) != 0;
        if (!say_addr(o, false, "-s", ip.src, ip.smsk) || !say_addr(o, false, "-d", ip.dst, ip.dmsk)) { return false; }
        if (!say_iface(o, "-i", ip.iniface, ip.iniface_mask) || !say_iface(o, "-o", ip.outiface, ip.outiface_mask)) { return false; }
        if (ip.proto == 6) { say(o, " -p tcp"); } else if (ip.proto == 17) { say(o, " -p udp"); } else if (ip.proto != 0) { return false; }
    }
    for (uint32_t m = v->eh; m < toff; m += rd16(e + m)) {
        const char *name = (const char *)e + m + 2;
        uint8_t rev = e[m + 31];
        const uint8_t *p = e + m + 32;
        if (strcmp(name, "mark") == 0 && rev == 1) {
            xt_mark_mtinfo1_t mi;
            memcpy(&mi, p, sizeof(mi));
            if (mi.invert != 0) { return false; }
            say(o, " -m mark --mark 0x%x", mi.mark);
            if (mi.mask != 0xffffffffu) { say(o, "/0x%x", mi.mask); }
        } else if (strcmp(name, "tcp") == 0 && rev == 0) {
            xt_tcp_t t;
            memcpy(&t, p, sizeof(t));
            if (t.option != 0 || t.flg_mask != 0 || t.flg_cmp != 0 || t.invflags != 0) { return false; }
            say(o, " -m tcp");
            say_ports(o, "--sport", t.spts[0], t.spts[1]);
            say_ports(o, "--dport", t.dpts[0], t.dpts[1]);
        } else if (strcmp(name, "udp") == 0 && rev == 0) {
            xt_udp_t u;
            memcpy(&u, p, sizeof(u));
            if (u.invflags != 0) { return false; }
            say(o, " -m udp");
            say_ports(o, "--sport", u.spts[0], u.spts[1]);
            say_ports(o, "--dport", u.dpts[0], u.dpts[1]);
        } else {
            return false;
        }
    }
    const uint8_t *t = e + toff;
    const char *tname = (const char *)t + 2;
    const uint8_t *p = t + 32;
    if (tname[0] == '\0') {
        int32_t verdict = (int32_t)rd32(p);
        if (verdict == XT_VERDICT_ACCEPT) { say(o, " -j ACCEPT"); }
        else if (verdict == XT_VERDICT_DROP) { say(o, " -j DROP"); }
        else if (verdict == XT_VERDICT_RETURN) { say(o, " -j RETURN"); }
        else if (verdict >= 0) {
            const pchain_t *c = chain_starting_at(v, (uint32_t)verdict);
            if (c == NULL) { return false; }
            say(o, " %s %s", go ? "-g" : "-j", c->name);
        } else { return false; }
        return o->ok;
    }
    bool dnat = strcmp(tname, "DNAT") == 0, snat = strcmp(tname, "SNAT") == 0;
    bool masq = strcmp(tname, "MASQUERADE") == 0;
    if (!dnat && !snat && !masq) { return false; }
    uint32_t flags;
    char addr[INET6_ADDRSTRLEN] = "";
    uint16_t port = 0;
    if (v6) {
        xt_nat_range_t r;
        memcpy(&r, p, sizeof(r));
        flags = r.flags;
        if (flags & XT_NAT_MAP_IPS) {
            if (memcmp(r.min_addr, r.max_addr, 16) != 0 || inet_ntop(AF_INET6, r.min_addr, addr, sizeof(addr)) == NULL) { return false; }
        }
        if (flags & XT_NAT_PROTO_SPECIFIED) {
            if (r.min_proto != r.max_proto) { return false; }
            port = ntohs(r.min_proto);
        }
    } else {
        xt_nat_ipv4_compat_t c;
        memcpy(&c, p, sizeof(c));
        if (c.rangesize != 1) { return false; }
        flags = c.range[0].flags;
        if (flags & XT_NAT_MAP_IPS) {
            if (memcmp(c.range[0].min_ip, c.range[0].max_ip, 4) != 0 || inet_ntop(AF_INET, c.range[0].min_ip, addr, sizeof(addr)) == NULL) { return false; }
        }
        if (flags & XT_NAT_PROTO_SPECIFIED) {
            if (c.range[0].min_port != c.range[0].max_port) { return false; }
            port = ntohs(c.range[0].min_port);
        }
    }
    if ((flags & ~(XT_NAT_MAP_IPS | XT_NAT_PROTO_SPECIFIED)) != 0) { return false; }
    if (masq) {
        if (flags != 0) { return false; }
        say(o, " -j MASQUERADE");
        return o->ok;
    }
    say(o, " -j %s %s ", tname, dnat ? "--to-destination" : "--to-source");
    if ((flags & XT_NAT_MAP_IPS) && (flags & XT_NAT_PROTO_SPECIFIED)) {
        say(o, v6 ? "[%s]:%u" : "%s:%u", addr, port);
    } else if (flags & XT_NAT_MAP_IPS) {
        say(o, "%s", addr);
    } else if (flags & XT_NAT_PROTO_SPECIFIED) {
        say(o, ":%u", port);
    } else {
        return false;
    }
    return o->ok;
}

static int chain_cmp(const void *a, const void *b) {
    const pchain_t *x = a, *y = b;
    return (x->head > y->head) - (x->head < y->head);
}

char *firc_test_xt_print(firc_ipt_proto_t fam, const firc_xt_info_t *info, const uint8_t *blob) {
    view_t *v = calloc(1, sizeof(*v));
    if (v == NULL) { return NULL; }
    bool v6 = fam == FIRC_IPT_PROTO_IPV6;
    v->fam = fam;
    v->blob = blob;
    v->eh = v6 ? 168u : 112u;
    v->at_t = v6 ? 140u : 88u;
    v->offs = malloc(((size_t)info->size / v->eh + 2u) * sizeof(uint32_t));
    out_t o = {NULL, 0, 0, v->offs != NULL};
    for (uint32_t off = 0; o.ok && off < info->size;) {
        uint16_t next = rd16(blob + off + v->at_t + 2);
        if (next < v->eh || next > info->size - off) { o.ok = false; break; }
        v->offs[v->n++] = off;
        off += next;
    }
    for (int h = 0; h < XT_NUMHOOKS; h++) {
        if (!(info->valid_hooks & (1u << h))) { continue; }
        pchain_t c = {k_hooks[h], h, info->hook_entry[h], info->hook_entry[h], info->underflow[h]};
        v->chains[v->nc++] = c;
    }
    for (uint32_t i = 0; o.ok && i + 1 < v->n; i++) {
        const uint8_t *t = target_of(v, v->offs[i]);
        if (strcmp((const char *)t + 2, "ERROR") != 0) { continue; }
        uint32_t k = i + 1;
        while (k < v->n && strcmp((const char *)target_of(v, v->offs[k]) + 2, "ERROR") != 0) { k++; }
        pchain_t c = {(const char *)t + 32, -1, v->offs[i], v->offs[i + 1], v->offs[k - 1]};
        v->chains[v->nc++] = c;
        if (v->nc == sizeof(v->chains) / sizeof(v->chains[0])) { o.ok = false; }
    }
    qsort(v->chains, v->nc, sizeof(v->chains[0]), chain_cmp);
    say(&o, "*nat\n");
    for (int h = 0; h < XT_NUMHOOKS; h++) {
        for (size_t i = 0; i < v->nc; i++) {
            if (v->chains[i].hook != h) { continue; }
            int32_t policy = (int32_t)rd32(target_of(v, v->chains[i].end) + 32);
            say(&o, ":%s %s [0:0]\n", v->chains[i].name, policy == XT_VERDICT_DROP ? "DROP" : "ACCEPT");
        }
    }
    for (size_t i = 0; i < v->nc; i++) {
        if (v->chains[i].hook < 0) { say(&o, ":%s - [0:0]\n", v->chains[i].name); }
    }
    for (int pass = 0; pass < 2 && o.ok; pass++) {
        for (int h = 0; h < (pass == 0 ? XT_NUMHOOKS : 1); h++) {
            for (size_t i = 0; i < v->nc && o.ok; i++) {
                const pchain_t *c = &v->chains[i];
                if (pass == 0 ? c->hook != h : c->hook >= 0) { continue; }
                for (uint32_t k = 0; k < v->n && o.ok; k++) {
                    uint32_t off = v->offs[k];
                    if (off < c->first || off >= c->end) { continue; }
                    say(&o, "-A %s", c->name);
                    o.ok = o.ok && say_rule(&o, v, off);
                    say(&o, "\n");
                }
            }
        }
    }
    say(&o, "COMMIT\n");
    free(v->offs);
    free(v);
    if (!o.ok) { free(o.s); return NULL; }
    return o.s;
}

void firc_test_xt_zero_kernel_fields(firc_ipt_proto_t fam, uint8_t *blob, uint32_t size) {
    bool v6 = fam == FIRC_IPT_PROTO_IPV6;
    uint32_t at_t = v6 ? 140u : 88u, at_from = v6 ? 144u : 92u, at_cnt = v6 ? 152u : 96u;
    for (uint32_t off = 0; off < size;) {
        uint16_t next = rd16(blob + off + at_t + 2);
        if (next == 0 || next > size - off) { return; }
        memset(blob + off + at_from, 0, 4);
        memset(blob + off + at_cnt, 0, 16);
        off += next;
    }
}

bool firc_test_xt_same(firc_ipt_proto_t fam, const firc_xt_info_t *ai, const uint8_t *a,
                       const firc_xt_info_t *bi, const uint8_t *b) {
    if (ai->valid_hooks != bi->valid_hooks || ai->num_entries != bi->num_entries || ai->size != bi->size) { return false; }
    for (int h = 0; h < XT_NUMHOOKS; h++) {
        if (!(ai->valid_hooks & (1u << h))) { continue; }
        if (ai->hook_entry[h] != bi->hook_entry[h] || ai->underflow[h] != bi->underflow[h]) { return false; }
    }
    bool v6 = fam == FIRC_IPT_PROTO_IPV6;
    uint32_t at_t = v6 ? 140u : 88u, at_from = v6 ? 144u : 92u, at_cnt = v6 ? 152u : 96u;
    uint8_t *x = malloc(ai->size ? ai->size : 1), *y = malloc(ai->size ? ai->size : 1);
    bool same = x != NULL && y != NULL;
    if (same) {
        memcpy(x, a, ai->size);
        memcpy(y, b, ai->size);
        for (uint32_t off = 0; off < ai->size;) {
            uint16_t nx = rd16(x + off + at_t + 2), ny = rd16(y + off + at_t + 2);
            if (nx != ny || nx == 0) { same = false; break; }
            memset(x + off + at_from, 0, 4);
            memset(y + off + at_from, 0, 4);
            memset(x + off + at_cnt, 0, 16);
            memset(y + off + at_cnt, 0, 16);
            off += nx;
        }
        same = same && memcmp(x, y, ai->size) == 0;
    }
    free(x);
    free(y);
    return same;
}

firc_ipt_rule_t *firc_test_rule(const char *line) {
    char *copy = strdup(line);
    const char *parts[64] = {NULL};
    size_t n = 0;
    for (char *save = NULL, *tok = strtok_r(copy, " ", &save); tok != NULL && n < 64; tok = strtok_r(NULL, " ", &save)) {
        parts[n++] = tok;
    }
    firc_ipt_rule_t *r = firc_ipt_rule_new(parts, n);
    free(copy);
    return r;
}

firc_test_stage_t *firc_test_stage_new(void) {
    firc_test_stage_t *s = calloc(1, sizeof(*s));
    if (s != NULL) { s->stage.chains = s->chains; }
    return s;
}

static firc_xt_stage_chain_t *next_chain(firc_test_stage_t *s, const char *chain, firc_xt_stage_kind_t kind) {
    firc_xt_stage_chain_t *c = &s->chains[s->n_chains++];
    memset(c, 0, sizeof(*c));
    c->name = chain;
    c->kind = kind;
    s->stage.n_chains = s->n_chains;
    return c;
}

void firc_test_stage_override(firc_test_stage_t *s, const char *chain, const char *const *lines, size_t n) {
    firc_xt_stage_chain_t *c = next_chain(s, chain, FIRC_XT_STAGE_OVERRIDE);
    c->rules = &s->rules[s->n_rules];
    c->n_rules = n;
    for (size_t i = 0; i < n; i++) { s->rules[s->n_rules++] = firc_test_rule(lines[i]); }
}

void firc_test_stage_delete(firc_test_stage_t *s, const char *chain) { (void)next_chain(s, chain, FIRC_XT_STAGE_DELETE); }

void firc_test_stage_patch(firc_test_stage_t *s, const char *chain, size_t n, const firc_ipt_option_t *opts,
                           const int *nums, const char *const *lines) {
    firc_xt_stage_chain_t *c = next_chain(s, chain, FIRC_XT_STAGE_PATCH);
    c->ops = &s->ops[s->n_ops];
    c->n_ops = n;
    for (size_t i = 0; i < n; i++) {
        firc_ipt_rule_t *r = firc_test_rule(lines[i]);
        s->rules[s->n_rules++] = r;
        s->ops[s->n_ops++] = (firc_xt_patch_op_t){opts[i], nums[i], r};
    }
}

void firc_test_stage_free(firc_test_stage_t *s) {
    if (s == NULL) { return; }
    for (size_t i = 0; i < s->n_rules; i++) { firc_ipt_rule_free(s->rules[i]); }
    free(s);
}

void firc_test_stage_fixture(firc_test_stage_t *s, const char *fx, firc_ipt_proto_t fam) {
    bool v6 = fam == FIRC_IPT_PROTO_IPV6;
    const char *dnsor[] = {
        v6 ? "-p tcp -d fd00:1::1 --dport 53 -j DNAT --to-destination :3553"
           : "-p tcp -d 192.168.1.1 --dport 53 -j DNAT --to-destination :3553",
        v6 ? "-p udp -d fd00:1::1 --dport 53 -j DNAT --to-destination :3553"
           : "-p udp -d 192.168.1.1 --dport 53 -j DNAT --to-destination :3553",
    };
    const char *dnat[] = {v6 ? "-d fd37:9a00::1/128 -j DNAT --to-destination 2606:2800:220:1:248:1893:25c8:1946"
                             : "-d 198.18.0.1/32 -j DNAT --to-destination 93.184.216.34"};
    const char *masq[] = {"-o nwg1 -m mark --mark 0x10000/0xff0000 -j MASQUERADE"};
    const char *pool_jump = v6 ? "-d fd37:9a00::/48 -j FIRC_DNAT" : "-d 198.18.0.0/15 -j FIRC_DNAT";
    if (strcmp(fx, "firmware-firc") == 0 || strcmp(fx, "full") == 0) {
        if (fx[0] == 'f' && fx[1] == 'u') { s->stage.sweep_prefix = "FIRC_"; }
        firc_test_stage_override(s, "FIRC_DNSOR", dnsor, 2);
        firc_test_stage_override(s, "FIRC_DNAT", dnat, 1);
        firc_test_stage_override(s, "FIRC_g1", masq, 1);
        firc_test_stage_override(s, "FIRC_bh", NULL, 0);
        const firc_ipt_option_t pre_ops[] = {FIRC_IPT_OP_INSERT, FIRC_IPT_OP_APPEND};
        const int pre_nums[] = {1, 0};
        const char *pre[] = {"-j FIRC_DNSOR", pool_jump};
        firc_test_stage_patch(s, "PREROUTING", 2, pre_ops, pre_nums, pre);
        const firc_ipt_option_t post_ops[] = {FIRC_IPT_OP_APPEND, FIRC_IPT_OP_APPEND};
        const int post_nums[] = {0, 0};
        const char *post[] = {"-j FIRC_g1", "-j FIRC_bh"};
        firc_test_stage_patch(s, "POSTROUTING", 2, post_ops, post_nums, post);
    } else if (strcmp(fx, "firmware-firc-remove") == 0) {
        firc_test_stage_delete(s, "FIRC_g1");
        const firc_ipt_option_t ops[] = {FIRC_IPT_OP_DELETE};
        const int nums[] = {0};
        const char *post[] = {"-j FIRC_g1"};
        firc_test_stage_patch(s, "POSTROUTING", 1, ops, nums, post);
    } else if (strcmp(fx, "sweep") == 0) {
        s->stage.sweep_prefix = "FIRC_";
    } else if (strcmp(fx, "dedupe") == 0) {
        firc_test_stage_override(s, "FIRC_g1", masq, 1);
        const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
        const int nums[] = {0};
        const char *post[] = {"-j FIRC_g1"};
        firc_test_stage_patch(s, "POSTROUTING", 1, ops, nums, post);
    } else if (strcmp(fx, "kept") == 0) {
        firc_test_stage_override(s, "FIRC_DNSOR", dnsor, 1);
        const firc_ipt_option_t ops[] = {FIRC_IPT_OP_INSERT};
        const int nums[] = {1};
        const char *pre[] = {"-j FIRC_DNSOR"};
        firc_test_stage_patch(s, "PREROUTING", 1, ops, nums, pre);
    } else if (strcmp(fx, "dnat2000") == 0) {
        firc_xt_stage_chain_t *c = next_chain(s, "FIRC_DNAT", FIRC_XT_STAGE_OVERRIDE);
        c->rules = &s->rules[s->n_rules];
        c->n_rules = 2000;
        for (unsigned i = 0; i < 2000; i++) {
            char line[160];
            if (v6) {
                snprintf(line, sizeof(line), "-d fd37:9a00::%x/128 -j DNAT --to-destination 2001:db8::%x", i + 1, i + 1);
            } else {
                snprintf(line, sizeof(line), "-d 198.18.%u.%u/32 -j DNAT --to-destination 100.64.%u.%u", i / 256, i % 256,
                         i / 256, i % 256);
            }
            s->rules[s->n_rules++] = firc_test_rule(line);
        }
        const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
        const int nums[] = {0};
        const char *pre[] = {pool_jump};
        firc_test_stage_patch(s, "PREROUTING", 1, ops, nums, pre);
    }
}
