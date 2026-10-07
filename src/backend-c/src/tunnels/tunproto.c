#include "firc/tunproto.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <string.h>

size_t firc_tun_lines_feed(firc_tun_lines_t *l, const char *data, size_t n, firc_tun_line_fn fn, void *ud)
{
    size_t dropped = 0;
    for (size_t i = 0; i < n; i++) {
        char c = data[i];
        if (l->dropping) {
            if (c == '\n')
                l->dropping = false;
            continue;
        }
        if (c == '\n') {
            l->buf[l->len] = '\0';
            fn(l->buf, l->len, ud);
            l->len = 0;
        } else if (l->len == FIRC_TUN_LINE_MAX - 1) {
            l->dropping = true;
            l->len = 0;
            dropped++;
        } else {
            l->buf[l->len++] = c;
        }
    }
    return dropped;
}

static bool copy_str(const cJSON *obj, const char *key, char *dst, size_t cap)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(v) || !v->valuestring)
        return false;
    snprintf(dst, cap, "%s", v->valuestring);
    return true;
}

static bool count_of(const cJSON *v, int *out)
{
    if (!cJSON_IsNumber(v) || !(v->valuedouble >= 0) || v->valuedouble > 1e9)
        return false;
    *out = (int)v->valuedouble;
    return true;
}

static bool opt_index(const cJSON *root, int *out)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, "index");
    return v == NULL || count_of(v, out);
}

static bool parse_active(const cJSON *root, firc_tev_t *out)
{
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "nodes");
    if (!cJSON_IsArray(arr) || cJSON_GetArraySize(arr) > 8)
        return false;
    const cJSON *it;
    cJSON_ArrayForEach(it, arr)
    {
        if (!cJSON_IsString(it) || !it->valuestring)
            return false;
        snprintf(out->active[out->n_active++], sizeof(out->active[0]), "%s", it->valuestring);
    }
    const cJSON *ix = cJSON_GetObjectItemCaseSensitive(root, "index");
    if (ix == NULL)
        return true;
    if (!cJSON_IsArray(ix) || (size_t)cJSON_GetArraySize(ix) != out->n_active)
        return false;
    size_t k = 0;
    cJSON_ArrayForEach(it, ix)
    {
        if (!count_of(it, &out->active_index[k++]))
            return false;
    }
    return true;
}

static bool parse_fields(const cJSON *root, const char *type, firc_tev_t *out)
{
    if (strcmp(type, "ready") == 0) {
        out->kind = FIRC_TEV_READY;
        return copy_str(root, "dev", out->dev, sizeof(out->dev));
    }
    if (strcmp(type, "active") == 0) {
        out->kind = FIRC_TEV_ACTIVE;
        return parse_active(root, out);
    }
    if (strcmp(type, "node_down") == 0) {
        out->kind = FIRC_TEV_NODE_DOWN;
        return copy_str(root, "node", out->node, sizeof(out->node)) &&
               copy_str(root, "why", out->why, sizeof(out->why)) && opt_index(root, &out->index);
    }
    if (strcmp(type, "node_up") == 0) {
        out->kind = FIRC_TEV_NODE_UP;
        return copy_str(root, "node", out->node, sizeof(out->node)) && opt_index(root, &out->index);
    }
    if (strcmp(type, "nodes") == 0) {
        out->kind = FIRC_TEV_NODES;
        return count_of(cJSON_GetObjectItemCaseSensitive(root, "count"), &out->count);
    }
    if (strcmp(type, "pins_full") == 0) {
        out->kind = FIRC_TEV_PINS_FULL;
        return true;
    }
    if (strcmp(type, "no_node") == 0) {
        out->kind = FIRC_TEV_NO_NODE;
        const cJSON *r = cJSON_GetObjectItemCaseSensitive(root, "retry");
        if (!cJSON_IsNumber(r) || !(r->valuedouble >= 0) || r->valuedouble > 86400)
            return false;
        out->retry_s = (int)r->valuedouble;
        return true;
    }
    return false;
}

static void unset_indexes(firc_tev_t *out)
{
    out->index = -1;
    out->pos = -1;
    for (size_t i = 0; i < 8; i++) {
        out->active_index[i] = -1;
        out->active_pos[i] = -1;
    }
}

void firc_tun_event_parse(const char *line, size_t len, firc_tev_t *out)
{
    memset(out, 0, sizeof(*out));
    unset_indexes(out);
    out->kind = FIRC_TEV_BAD;
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(line, len, &end, 0);
    if (!root)
        return;
    while (end && end < line + len && (*end == ' ' || *end == '\t' || *end == '\r'))
        end++;
    if (!end || end != line + len) {
        cJSON_Delete(root);
        return;
    }
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
    bool ok = cJSON_IsObject(root) && cJSON_IsString(type) && type->valuestring &&
              parse_fields(root, type->valuestring, out);
    cJSON_Delete(root);
    if (!ok) {
        memset(out, 0, sizeof(*out));
        unset_indexes(out);
        out->kind = FIRC_TEV_BAD;
    }
}
