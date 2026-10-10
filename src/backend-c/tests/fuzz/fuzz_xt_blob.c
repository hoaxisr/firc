#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/xtables/xt_internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static firc_ipt_rule_t *g_r[2][3];
static firc_xt_stage_chain_t g_ch[2][3];
static firc_xt_patch_op_t g_op[2][2];

static void fuzz_once(void) {
    static const char *const words[2][3][8] = {
        {{"-d", "198.18.0.1/32", "-j", "DNAT", "--to-destination", "1.2.3.4"}, {"-j", "FIRC_DNAT"},
         {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"}},
        {{"-d", "fd37:9a00::1/128", "-j", "DNAT", "--to-destination", "2001:db8::1"}, {"-j", "FIRC_DNAT"},
         {"-d", "fd37:9a00::/48", "-j", "FIRC_DNAT"}},
    };
    for (int f = 0; f < 2; f++) {
        g_r[f][0] = firc_ipt_rule_new(words[f][0], 6);
        g_r[f][1] = firc_ipt_rule_new(words[f][1], 2);
        g_r[f][2] = firc_ipt_rule_new(words[f][2], 4);
        g_op[f][0] = (firc_xt_patch_op_t){FIRC_IPT_OP_APPEND, 0, g_r[f][1]};
        g_op[f][1] = (firc_xt_patch_op_t){FIRC_IPT_OP_INSERT, 1, g_r[f][2]};
        g_ch[f][0] = (firc_xt_stage_chain_t){"FIRC_g1", FIRC_XT_STAGE_DELETE, NULL, 0, NULL, 0};
        g_ch[f][1] = (firc_xt_stage_chain_t){"FIRC_DNAT", FIRC_XT_STAGE_OVERRIDE, &g_r[f][0], 1, NULL, 0};
        g_ch[f][2] = (firc_xt_stage_chain_t){"PREROUTING", FIRC_XT_STAGE_PATCH, NULL, 0, g_op[f], 2};
    }
}

static uint32_t *entry_offsets(firc_ipt_proto_t fam, const uint8_t *b, uint32_t size, uint32_t n) {
    uint32_t *offs = malloc(((size_t)n + 1) * sizeof(*offs));
    if (offs == NULL) { abort(); }
    uint32_t off = 0;
    for (uint32_t k = 0; k < n; k++) {
        if (off >= size) { abort(); }
        offs[k] = off;
        off += firc_xt_rd16(b + off + firc_xt_at_next(fam));
    }
    if (off != size) { abort(); }
    offs[n] = size;
    return offs;
}

static void same_outside_verdict(firc_ipt_proto_t fam, const uint8_t *was, uint32_t was_len, const uint8_t *now,
                                 uint32_t now_len) {
    if (was_len != now_len) { abort(); }
    uint32_t toff = firc_xt_rd16(was + firc_xt_at_toff(fam));
    bool jump = was[toff + 2] == '\0' && (int32_t)firc_xt_rd32(was + toff + 32) >= 0;
    uint32_t skip = jump ? toff + 32 : now_len;
    for (uint32_t i = 0; i < now_len; i++) {
        if (i >= skip && i < skip + 4) { continue; }
        if (was[i] != now[i]) { abort(); }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 + sizeof(firc_xt_info_t)) { return 0; }
    firc_ipt_proto_t fam = (data[0] & 1u) ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4;
    firc_xt_info_t info;
    memcpy(&info, data + 1, sizeof(info));
    size_t bl = size - 1 - sizeof(info);
    info.size = (uint32_t)bl;
    uint8_t *blob = malloc(bl ? bl : 1);
    if (blob == NULL) { return 0; }
    memcpy(blob, data + 1 + sizeof(info), bl);
    firc_xt_table_t t;
    const char *why = NULL;
    if (firc_xt_parse(fam, &info, blob, &t, &why) == FIRC_OK) {
        uint8_t *a = NULL, *b = NULL;
        int32_t *oa = NULL, *ob = NULL;
        firc_xt_info_t ai, bi;
        char w[256];
        firc_xt_table_t u;
        if (firc_xt_serialise(&t, &a, &ai, &oa, w, sizeof(w)) != FIRC_OK) { abort(); }
        if (ai.size != info.size || ai.num_entries != info.num_entries) { abort(); }
        uint32_t n = ai.num_entries;
        uint32_t *old_offs = entry_offsets(fam, blob, info.size, n);
        uint32_t *new_offs = entry_offsets(fam, a, ai.size, n);
        uint8_t *seen = calloc(n ? n : 1, 1);
        if (seen == NULL) { abort(); }
        for (uint32_t k = 0; k < n; k++) {
            if (oa[k] < 0 || (uint32_t)oa[k] >= n || seen[oa[k]]) { abort(); }
            seen[oa[k]] = 1;
            uint32_t o = (uint32_t)oa[k];
            same_outside_verdict(fam, blob + old_offs[o], old_offs[o + 1] - old_offs[o], a + new_offs[k],
                                 new_offs[k + 1] - new_offs[k]);
        }
        free(seen);
        free(old_offs);
        free(new_offs);
        if (firc_xt_parse(fam, &ai, a, &u, &why) != FIRC_OK) { abort(); }
        if (firc_xt_serialise(&u, &b, &bi, &ob, w, sizeof(w)) != FIRC_OK) { abort(); }
        if (bi.size != ai.size || memcmp(a, b, ai.size) != 0) { abort(); }
        firc_xt_table_clear(&u);
        if (g_r[0][0] == NULL) { fuzz_once(); }
        int f = fam == FIRC_IPT_PROTO_IPV6 ? 1 : 0;
        firc_xt_stage_t stage = {g_ch[f], 3, "FIRC_"};
        uint32_t exts = 0;
        if (firc_xt_merge(&t, &stage, &exts, w, sizeof(w)) == FIRC_OK) {
            uint8_t *m = NULL;
            int32_t *om = NULL;
            firc_xt_info_t mi;
            if (firc_xt_serialise(&t, &m, &mi, &om, w, sizeof(w)) == FIRC_OK) {
                firc_xt_table_t again;
                if (firc_xt_parse(fam, &mi, m, &again, &why) != FIRC_OK) { abort(); }
                firc_xt_table_clear(&again);
            }
            free(m);
            free(om);
        }
        firc_xt_table_clear(&t);
        free(a);
        free(b);
        free(oa);
        free(ob);
    }
    free(blob);
    return 0;
}
