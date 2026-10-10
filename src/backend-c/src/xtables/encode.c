#include "xt_internal.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

const firc_xt_ext_desc_t firc_xt_exts[] = {
    {FIRC_XT_EXT_DNAT, "DNAT", true, 0, 1},
    {FIRC_XT_EXT_MASQUERADE, "MASQUERADE", true, 0, 0},
    {FIRC_XT_EXT_MARK, "mark", false, 1, 1},
    {FIRC_XT_EXT_TCP, "tcp", false, 0, 0},
    {FIRC_XT_EXT_UDP, "udp", false, 0, 0},
};
const size_t firc_xt_n_exts = sizeof(firc_xt_exts) / sizeof(firc_xt_exts[0]);

typedef enum { T_NONE = 0, T_VERDICT, T_JUMP, T_DNAT, T_MASQ } target_kind_t;

typedef struct want {
    bool v6;
    bool has_s, has_d;
    uint8_t src[16], smsk[16], dst[16], dmsk[16];
    char in[16], out[16];
    size_t in_len, out_len;
    uint16_t proto;
    bool mark;
    uint32_t mark_v, mark_m;
    uint16_t l4;
    bool dport;
    uint16_t dlo, dhi;
    int first;
    target_kind_t target;
    int32_t verdict;
    char jump[FIRC_XT_NAME_LEN];
    bool to_addr, to_port;
    uint8_t addr[16];
    uint16_t port;
} want_t;

static bool parse_addr(bool v6, const char *s, uint8_t *addr, uint8_t *mask) {
    char buf[64];
    size_t n = strlen(s);
    if (n == 0 || n >= sizeof(buf)) { return false; }
    memcpy(buf, s, n + 1);
    long len = v6 ? 128 : 32;
    char *slash = strchr(buf, '/');
    if (slash != NULL) {
        *slash = '\0';
        char *end = NULL;
        long l = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || l < 0 || l > len) { return false; }
        len = l;
    }
    if (inet_pton(v6 ? AF_INET6 : AF_INET, buf, addr) != 1) { return false; }
    size_t bytes = v6 ? 16 : 4;
    memset(mask, 0, bytes);
    for (long b = 0; b < len; b++) { mask[b / 8] |= (uint8_t)(0x80u >> (b % 8)); }
    for (size_t i = 0; i < bytes; i++) { addr[i] &= mask[i]; }
    return true;
}

static bool parse_iface(const char *s, char *name, size_t *len) {
    size_t n = strlen(s);
    if (n == 0 || n > 15 || strchr(s, '+') != NULL) { return false; }
    memset(name, 0, 16);
    memcpy(name, s, n);
    *len = n;
    return true;
}

static bool parse_u16(const char *s, uint16_t *v) {
    if (s[0] < '0' || s[0] > '9') { return false; }
    char *end = NULL;
    unsigned long x = strtoul(s, &end, 10);
    if (*end != '\0' || x > 65535) { return false; }
    *v = (uint16_t)x;
    return true;
}

static bool parse_ports(const char *s, uint16_t *lo, uint16_t *hi) {
    char buf[16];
    size_t n = strlen(s);
    if (n == 0 || n >= sizeof(buf)) { return false; }
    memcpy(buf, s, n + 1);
    char *colon = strchr(buf, ':');
    if (colon == NULL) {
        if (!parse_u16(buf, lo)) { return false; }
        *hi = *lo;
        return true;
    }
    *colon = '\0';
    return parse_u16(buf, lo) && parse_u16(colon + 1, hi) && *lo <= *hi;
}

static bool parse_u32(const char *s, uint32_t *v) {
    if (s[0] < '0' || s[0] > '9') { return false; }
    char *end = NULL;
    unsigned long long x = strtoull(s, &end, 0);
    if (*end != '\0' || x > 0xffffffffull) { return false; }
    *v = (uint32_t)x;
    return true;
}

static bool parse_mark(const char *s, uint32_t *v, uint32_t *m) {
    char buf[32];
    size_t n = strlen(s);
    if (n == 0 || n >= sizeof(buf)) { return false; }
    memcpy(buf, s, n + 1);
    char *slash = strchr(buf, '/');
    *m = 0xffffffffu;
    if (slash != NULL) {
        *slash = '\0';
        if (!parse_u32(slash + 1, m)) { return false; }
    }
    return parse_u32(buf, v);
}

static bool chain_name_ok(const char *s) {
    size_t n = strlen(s);
    return n > 0 && n <= 28 && s[0] != '-' && s[0] != '!';
}

static bool read_target(want_t *w, char *const *p, size_t n, size_t *i) {
    const char *b = p[*i + 1];
    *i += 2;
    if (strcmp(b, "ACCEPT") == 0) { w->target = T_VERDICT; w->verdict = XT_VERDICT_ACCEPT; return true; }
    if (strcmp(b, "DROP") == 0) { w->target = T_VERDICT; w->verdict = XT_VERDICT_DROP; return true; }
    if (strcmp(b, "RETURN") == 0) { w->target = T_VERDICT; w->verdict = XT_VERDICT_RETURN; return true; }
    if (strcmp(b, "MASQUERADE") == 0) { w->target = T_MASQ; return true; }
    if (strcmp(b, "DNAT") == 0) {
        if (*i + 1 >= n || strcmp(p[*i], "--to-destination") != 0) { return false; }
        const char *to = p[*i + 1];
        *i += 2;
        if (to[0] == ':' && (!w->v6 || strchr(to + 1, ':') == NULL)) {
            if (w->proto == 0 || !parse_u16(to + 1, &w->port) || w->port == 0) { return false; }
            w->to_port = true;
        } else {
            if (inet_pton(w->v6 ? AF_INET6 : AF_INET, to, w->addr) != 1) { return false; }
            w->to_addr = true;
        }
        w->target = T_DNAT;
        return true;
    }
    if (!chain_name_ok(b)) { return false; }
    w->target = T_JUMP;
    snprintf(w->jump, sizeof(w->jump), "%s", b);
    return true;
}

static bool read_rule(firc_ipt_proto_t fam, const firc_ipt_rule_t *rule, want_t *w) {
    memset(w, 0, sizeof(*w));
    w->v6 = fam == FIRC_IPT_PROTO_IPV6;
    char *const *p = rule->parts;
    size_t n = rule->n_parts, i = 0;
    while (i < n) {
        if (w->target != T_NONE) { return false; }
        const char *a = p[i];
        const char *b = i + 1 < n ? p[i + 1] : NULL;
        if (b == NULL) { return false; }
        if (strcmp(a, "-s") == 0) {
            if (w->has_s || !parse_addr(w->v6, b, w->src, w->smsk)) { return false; }
            w->has_s = true;
            i += 2;
        } else if (strcmp(a, "-d") == 0) {
            if (w->has_d || !parse_addr(w->v6, b, w->dst, w->dmsk)) { return false; }
            w->has_d = true;
            i += 2;
        } else if (strcmp(a, "-i") == 0) {
            if (w->in_len != 0 || !parse_iface(b, w->in, &w->in_len)) { return false; }
            i += 2;
        } else if (strcmp(a, "-o") == 0) {
            if (w->out_len != 0 || !parse_iface(b, w->out, &w->out_len)) { return false; }
            i += 2;
        } else if (strcmp(a, "-p") == 0) {
            if (w->proto != 0) { return false; }
            if (strcmp(b, "tcp") == 0) { w->proto = 6; } else if (strcmp(b, "udp") == 0) { w->proto = 17; } else { return false; }
            i += 2;
        } else if (strcmp(a, "-m") == 0 && strcmp(b, "mark") == 0) {
            if (w->mark || i + 3 >= n || strcmp(p[i + 2], "--mark") != 0 || !parse_mark(p[i + 3], &w->mark_v, &w->mark_m)) { return false; }
            w->mark = true;
            if (w->first == 0) { w->first = 1; }
            i += 4;
        } else if (strcmp(a, "-m") == 0 && (strcmp(b, "tcp") == 0 || strcmp(b, "udp") == 0)) {
            uint16_t want_proto = b[0] == 't' ? 6 : 17;
            if (w->proto != want_proto || w->l4 != 0) { return false; }
            w->l4 = want_proto;
            if (w->first == 0) { w->first = 2; }
            i += 2;
        } else if (strcmp(a, "--dport") == 0) {
            if (w->proto == 0 || w->dport || !parse_ports(b, &w->dlo, &w->dhi)) { return false; }
            if (w->l4 == 0) {
                w->l4 = w->proto;
                if (w->first == 0) { w->first = 2; }
            }
            w->dport = true;
            i += 2;
        } else if (strcmp(a, "-j") == 0) {
            if (!read_target(w, p, n, &i)) { return false; }
        } else {
            return false;
        }
    }
    return w->target != T_NONE;
}

static void put_ext(uint8_t *at, uint16_t size, const char *name, uint8_t rev) {
    firc_xt_wr16(at, size);
    memcpy(at + 2, name, strlen(name));
    at[31] = rev;
}

static void put_ip(const want_t *w, uint8_t *e) {
    if (w->v6) {
        xt_ip6t_ip6_t ip;
        memset(&ip, 0, sizeof(ip));
        memcpy(ip.src, w->src, 16);
        memcpy(ip.smsk, w->smsk, 16);
        memcpy(ip.dst, w->dst, 16);
        memcpy(ip.dmsk, w->dmsk, 16);
        memcpy(ip.iniface, w->in, 16);
        memcpy(ip.outiface, w->out, 16);
        memset(ip.iniface_mask, 0xff, w->in_len ? w->in_len + 1 : 0);
        memset(ip.outiface_mask, 0xff, w->out_len ? w->out_len + 1 : 0);
        ip.proto = w->proto;
        ip.flags = w->proto ? XT_IP6T_F_PROTO : 0;
        memcpy(e, &ip, sizeof(ip));
    } else {
        xt_ipt_ip_t ip;
        memset(&ip, 0, sizeof(ip));
        memcpy(ip.src, w->src, 4);
        memcpy(ip.smsk, w->smsk, 4);
        memcpy(ip.dst, w->dst, 4);
        memcpy(ip.dmsk, w->dmsk, 4);
        memcpy(ip.iniface, w->in, 16);
        memcpy(ip.outiface, w->out, 16);
        memset(ip.iniface_mask, 0xff, w->in_len ? w->in_len + 1 : 0);
        memset(ip.outiface_mask, 0xff, w->out_len ? w->out_len + 1 : 0);
        ip.proto = w->proto;
        memcpy(e, &ip, sizeof(ip));
    }
}

static uint8_t *put_mark(const want_t *w, uint8_t *m, uint32_t *exts) {
    put_ext(m, XT_MATCH_HDR_LEN + 16, "mark", 1);
    xt_mark_mtinfo1_t mi;
    memset(&mi, 0, sizeof(mi));
    mi.mark = w->mark_v;
    mi.mask = w->mark_m;
    memcpy(m + XT_MATCH_HDR_LEN, &mi, sizeof(mi));
    *exts |= FIRC_XT_EXT_MARK;
    return m + XT_MATCH_HDR_LEN + 16;
}

static uint8_t *put_l4(const want_t *w, uint8_t *m, uint32_t *exts) {
    put_ext(m, XT_MATCH_HDR_LEN + 16, w->l4 == 6 ? "tcp" : "udp", 0);
    uint16_t ports[4] = {0, 0xffff, w->dport ? w->dlo : 0, w->dport ? w->dhi : 0xffff};
    memcpy(m + XT_MATCH_HDR_LEN, ports, sizeof(ports));
    *exts |= w->l4 == 6 ? FIRC_XT_EXT_TCP : FIRC_XT_EXT_UDP;
    return m + XT_MATCH_HDR_LEN + 16;
}

static void put_target(const want_t *w, uint8_t *t, firc_xt_entry_t *out, uint32_t *exts) {
    if (w->target == T_VERDICT || w->target == T_JUMP) {
        put_ext(t, XT_STANDARD_TARGET_LEN, "", 0);
        if (w->target == T_VERDICT) { firc_xt_wr32(t + XT_MATCH_HDR_LEN, (uint32_t)w->verdict); }
        else { snprintf(out->jump, sizeof(out->jump), "%s", w->jump); }
        return;
    }
    bool dnat = w->target == T_DNAT;
    *exts |= dnat ? FIRC_XT_EXT_DNAT : FIRC_XT_EXT_MASQUERADE;
    if (w->v6) {
        put_ext(t, XT_MATCH_HDR_LEN + 40, dnat ? "DNAT" : "MASQUERADE", dnat ? 1 : 0);
        xt_nat_range_t r;
        memset(&r, 0, sizeof(r));
        if (w->to_addr) {
            r.flags |= XT_NAT_MAP_IPS;
            memcpy(r.min_addr, w->addr, 16);
            memcpy(r.max_addr, w->addr, 16);
        }
        if (w->to_port) {
            r.flags |= XT_NAT_PROTO_SPECIFIED;
            r.min_proto = htons(w->port);
            r.max_proto = htons(w->port);
        }
        memcpy(t + XT_MATCH_HDR_LEN, &r, sizeof(r));
        return;
    }
    put_ext(t, XT_MATCH_HDR_LEN + 24, dnat ? "DNAT" : "MASQUERADE", 0);
    xt_nat_ipv4_compat_t c;
    memset(&c, 0, sizeof(c));
    c.rangesize = 1;
    if (w->to_addr) {
        c.range[0].flags |= XT_NAT_MAP_IPS;
        memcpy(c.range[0].min_ip, w->addr, 4);
        memcpy(c.range[0].max_ip, w->addr, 4);
    }
    if (w->to_port) {
        c.range[0].flags |= XT_NAT_PROTO_SPECIFIED;
        c.range[0].min_port = htons(w->port);
        c.range[0].max_port = htons(w->port);
    }
    memcpy(t + XT_MATCH_HDR_LEN, &c, sizeof(c));
}

firc_err_t firc_xt_encode(firc_ipt_proto_t fam, const firc_ipt_rule_t *rule, firc_xt_entry_t *out, uint32_t *exts) {
    memset(out, 0, sizeof(*out));
    out->old_index = -1;
    out->old_off = FIRC_XT_NONE;
    out->points_at = FIRC_XT_NONE;
    want_t w;
    if (rule == NULL || !read_rule(fam, rule, &w)) { return FIRC_ERR_INVAL; }
    uint32_t eh = firc_xt_ehdr(fam);
    uint32_t msize = (w.mark ? XT_MATCH_HDR_LEN + 16 : 0) + (w.l4 ? XT_MATCH_HDR_LEN + 16 : 0);
    uint32_t tsize = (w.target == T_VERDICT || w.target == T_JUMP) ? XT_STANDARD_TARGET_LEN
                     : XT_MATCH_HDR_LEN + (w.v6 ? 40u : 24u);
    uint32_t len = eh + msize + tsize;
    uint8_t *e = calloc(1, len);
    if (e == NULL) { return FIRC_ERR_NOMEM; }
    put_ip(&w, e);
    firc_xt_wr16(e + firc_xt_at_toff(fam), (uint16_t)(eh + msize));
    firc_xt_wr16(e + firc_xt_at_next(fam), (uint16_t)len);
    uint8_t *m = e + eh;
    if (w.first == 1) {
        m = put_mark(&w, m, exts);
        if (w.l4) { m = put_l4(&w, m, exts); }
    } else if (w.first == 2) {
        m = put_l4(&w, m, exts);
        if (w.mark) { m = put_mark(&w, m, exts); }
    }
    put_target(&w, m, out, exts);
    out->bytes = e;
    out->len = len;
    return FIRC_OK;
}
