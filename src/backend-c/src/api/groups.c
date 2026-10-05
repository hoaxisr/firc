#include "firc/groups.h"
#include "firc/match.h"

#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>

#include "firc/id.h"
#include "firc/ifacename.h"
#include "firc/log.h"
#include "firc/json.h"
#include "firc/resolve_check.h"
#include "firc/resolver_addr.h"
#include "firc/sub_fetch.h"

#include "groups_internal.h"

/* absent/null is unset, a string is the value, anything else sets *bad; get_string would silently widen the rule */
static const char *get_opt_string(const cJSON *obj, const char *key, bool *bad) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (item == NULL || cJSON_IsNull(item)) { return ""; }
    if (!cJSON_IsString(item)) { *bad = true; return ""; }
    return item->valuestring;
}

static const char why_not_strings[] = "proto and ports are strings";

/* list is config only here; the app's carry_list gate moves a live list's arena/sync state in when the url matches */

/* absent list keeps the group's own, as an absent devices/rules does; NULL on OOM */
static firc_group_list_t *list_config_copy(const firc_group_list_t *src) {
    firc_group_list_t *list = firc_group_list_new();
    if (list == NULL) { return NULL; }
    if (firc_strset(&list->url, src->url ? src->url : "") != FIRC_OK) {
        firc_group_list_free(list);
        return NULL;
    }
    list->interval = src->interval;
    list->last_update = src->last_update;
    for (size_t i = 0; i < src->n_overrides; i++) {
        const firc_sub_override_t *o = src->overrides[i];
        firc_sub_rule_key_t key = {o->rule, o->list_type, o->proto, o->ports};
        if (firc_group_list_set_override(list, &key, o->type,
                                         o->has_enable ? &o->enable : NULL) != FIRC_OK) {
            firc_group_list_free(list);
            return NULL;
        }
    }
    return list;
}

/* url is required; interval absent keeps the live list's own; overrides always come from existing, never the body */
static firc_err_t list_from_req(const cJSON *list_j, const firc_group_list_t *existing,
                               firc_group_list_t **out, const char **err_msg) {
    const char *url = get_string(list_j, "url");
    if (url[0] == '\0' || !firc_sub_url_is_supported(url)) {
        *err_msg = "invalid list";
        return FIRC_ERR_INVAL;
    }
    firc_group_list_t *list = firc_group_list_new();
    if (list == NULL) { return FIRC_ERR_NOMEM; }
    firc_err_t err = firc_strset(&list->url, url);
    if (err != FIRC_OK) {
        firc_group_list_free(list);
        return err;
    }
    cJSON *interval_j = cJSON_GetObjectItemCaseSensitive(list_j, "interval");
    if (cJSON_IsNumber(interval_j)) {
        list->interval = (uint32_t)interval_j->valuedouble;
    } else if (existing != NULL) {
        list->interval = existing->interval;
    }
    if (existing != NULL) {
        list->last_update = existing->last_update;
        for (size_t i = 0; i < existing->n_overrides; i++) {
            const firc_sub_override_t *o = existing->overrides[i];
            firc_sub_rule_key_t key = {o->rule, o->list_type, o->proto, o->ports};
            if (firc_group_list_set_override(list, &key, o->type,
                                             o->has_enable ? &o->enable : NULL) != FIRC_OK) {
                firc_group_list_free(list);
                return FIRC_ERR_NOMEM;
            }
        }
    }
    *out = list;
    return FIRC_OK;
}

#define FIRC_RULE_WHERE_MAX 384

int firc_api_utf8_clamp(const char *s, int max_bytes) {
    int n = 0;
    while (n < max_bytes && s[n] != '\0') { n++; } /* "scan at most max_bytes"; cppcheck arrayIndexThenCheck */
    if (s[n] == '\0') { return n; }
    while (n > 0 && ((unsigned char)s[n] & 0xc0) == 0x80) { n--; } /* step back to the lead byte of a split char */
    return n;
}

static const char *locate_rule(char *buf, size_t len, const char *group_name, const char *type,
                               const char *pattern, int index, const char *why) {
    char num[16]; /* empty pattern identifies nothing, so the 1-based index is used instead */
    bool by_pattern = (pattern != NULL && *pattern != '\0');
    snprintf(num, sizeof(num), "%d", index + 1);
    const char *q = by_pattern ? "\"" : "";
    const char *which = by_pattern ? pattern : num;
    int wn = firc_api_utf8_clamp(which, 120); /* bounded so the whole message fits FIRC_RULE_WHERE_MAX */
    const char *cut = (by_pattern && which[wn] != '\0') ? "..." : ""; /* a truncated pattern must not read as one that exists */
    const char *t = (type != NULL && *type != '\0') ? type : "?";
    int tn = firc_api_utf8_clamp(t, 20); /* client-supplied too; must stay UTF-8-clamped like the pattern */
    if (group_name != NULL && *group_name != '\0') {
        snprintf(buf, len, "group \"%.*s\", rule %s%.*s%s%s (type \"%.*s\"): %.90s",
                 firc_api_utf8_clamp(group_name, 60), group_name, q, wn, which, cut, q, tn, t, why);
    } else {
        snprintf(buf, len, "rule %s%.*s%s%s (type \"%.*s\"): %.90s", q, wn, which, cut, q, tn, t,
                 why);
    }
    return buf;
}

/* why (a static string) is set only when the rule is refused as unusable; the caller turns that into a 400 */
static firc_err_t fill_rule_fields(firc_rule_t *rule, const cJSON *req, const char **why) {
    if (why != NULL) { *why = NULL; }
    if (firc_strset(&rule->type, get_string(req, "type")) != FIRC_OK) { return FIRC_ERR_NOMEM; }
    if (firc_strset(&rule->rule, get_string(req, "rule")) != FIRC_OK) { return FIRC_ERR_NOMEM; }
    bool bad = false;
    const char *proto = get_opt_string(req, "proto", &bad);
    const char *ports = get_opt_string(req, "ports", &bad);
    if (bad) {
        if (why != NULL) { *why = why_not_strings; }
        return FIRC_ERR_INVAL;
    }
    if (firc_strset(&rule->proto, proto) != FIRC_OK) { return FIRC_ERR_NOMEM; }
    if (firc_strset(&rule->ports, ports) != FIRC_OK) { return FIRC_ERR_NOMEM; }
    if (!firc_rule_spec_is_usable(rule->type, rule->rule, rule->proto, rule->ports, why)) {
        return FIRC_ERR_INVAL;
    }
    cJSON *enable_j = cJSON_GetObjectItemCaseSensitive(req, "enable"); /* absent/wrong-type/null all read as false */
    rule->enable = cJSON_IsBool(enable_j) && cJSON_IsTrue(enable_j);
    return FIRC_OK;
}

/* an id matching baseline_rules keeps that identity; any other case silently gets a fresh random id; NULL on OOM */
static firc_rule_t *rule_from_req(const cJSON *req, firc_rule_t **baseline_rules, size_t n_baseline,
                                  const char **why) {
    firc_id_t id;
    bool has_id;
    bool found = false;
    if (parse_optional_id(req, "id", &id, &has_id) == FIRC_OK && has_id) {
        for (size_t i = 0; i < n_baseline; i++) {
            if (firc_id_equal(baseline_rules[i]->id, id)) {
                found = true;
                break;
            }
        }
    }
    firc_rule_t *rule = firc_rule_new();
    if (!rule) { return NULL; }
    rule->id = found ? id : firc_id_random();
    if (fill_rule_fields(rule, req, why) != FIRC_OK) {
        firc_rule_free(rule);
        return NULL; /* *why set == refused, not out of memory */
    }
    return rule;
}

/* unlike rule_from_req, an explicit id that matches nothing in existing_rules is FIRC_ERR_NOENT */
static firc_err_t rule_from_req_strict(const cJSON *req, firc_rule_t **existing_rules, size_t n_existing,
                                     firc_rule_t **out, const char **why) {
    firc_id_t id;
    bool has_id;
    if (parse_optional_id(req, "id", &id, &has_id) != FIRC_OK) { return FIRC_ERR_INVAL; }
    firc_id_t final_id = firc_id_random();
    if (has_id) {
        bool found = false;
        for (size_t i = 0; i < n_existing; i++) {
            if (firc_id_equal(existing_rules[i]->id, id)) {
                found = true;
                break;
            }
        }
        if (!found) { return FIRC_ERR_NOENT; }
        final_id = id;
    }
    firc_rule_t *rule = firc_rule_new();
    if (!rule) { return FIRC_ERR_NOMEM; }
    rule->id = final_id;
    firc_err_t err = fill_rule_fields(rule, req, why);
    if (err != FIRC_OK) {
        firc_rule_free(rule);
        return err;
    }
    *out = rule;
    return FIRC_OK;
}

/* absent keeps the group's own (new group: tunnel on, no server); null is the default; an object replaces it */
static firc_err_t resolve_from_req(const cJSON *req, const firc_group_t *existing, const firc_fakeip_t *pool,
                                   firc_group_resolve_t *out, const char **err_msg, const char **err_field,
                                   char *msgbuf, size_t msgbuf_len) {
    const cJSON *r = cJSON_GetObjectItemCaseSensitive(req, "resolve");
    out->tunnel = true;
    if (r == NULL) {
        if (existing == NULL) { return FIRC_OK; }
        out->tunnel = existing->resolve.tunnel;
        return firc_strset(&out->server, existing->resolve.server);
    }
    if (cJSON_IsNull(r)) { return FIRC_OK; }
    if (!cJSON_IsObject(r)) {
        *err_msg = "resolve must be an object of tunnel and server";
        *err_field = "resolve";
        return FIRC_ERR_INVAL;
    }
    const cJSON *t = cJSON_GetObjectItemCaseSensitive(r, "tunnel");
    if (t != NULL && !cJSON_IsNull(t)) {
        if (!cJSON_IsBool(t)) {
            *err_msg = "resolve.tunnel must be true or false";
            *err_field = "resolve.tunnel";
            return FIRC_ERR_INVAL;
        }
        out->tunnel = cJSON_IsTrue(t);
    }
    const cJSON *s = cJSON_GetObjectItemCaseSensitive(r, "server");
    if (s == NULL || cJSON_IsNull(s)) { return FIRC_OK; }
    if (!cJSON_IsString(s)) {
        *err_msg = "resolve.server must be a string";
        *err_field = "resolve.server";
        return FIRC_ERR_INVAL;
    }
    if (s->valuestring[0] == '\0') { return FIRC_OK; }
    firc_resolver_addr_t a;
    firc_resolver_addr_res_t pr = firc_resolver_addr_parse(s->valuestring, &a);
    if (pr != FIRC_RESOLVER_ADDR_OK) {
        snprintf(msgbuf, msgbuf_len, "resolve.server \"%.64s\" %s", s->valuestring, firc_resolver_addr_why(pr));
        *err_msg = msgbuf;
        *err_field = "resolve.server";
        return FIRC_ERR_INVAL;
    }
    if (firc_resolve_server_in_pool(s->valuestring, pool)) {
        snprintf(msgbuf, msgbuf_len, "resolve.server \"%.64s\" is inside firc's address pool, where no resolver can be",
                 s->valuestring);
        *err_msg = msgbuf;
        *err_field = "resolve.server";
        return FIRC_ERR_INVAL;
    }
    return firc_strset(&out->server, s->valuestring);
}

/* group_id is "" for a POST with no "id": a dialog for an id the client was never given would be wrong to mark */
static void write_group_error(firc_http_res_t *res, const char *msg, const char *field, const char *group_id) {
    if (field == NULL) {
        firc_http_res_write_error(res, 400, msg);
        return;
    }
    cJSON *o = cJSON_CreateObject();
    if (o == NULL) {
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    cJSON_AddStringToObject(o, "error", msg);
    cJSON_AddStringToObject(o, "field", field);
    cJSON_AddStringToObject(o, "group", group_id);
    firc_http_res_write_json(res, 400, o);
}

/* builds a brand-new, independent firc_group_t; existing supplies the id to validate against and baseline rules
 * for lenient nested rule-id reuse; the caller transplants the result onto the live group itself */
static firc_err_t group_from_req(const cJSON *req, const firc_group_t *existing, firc_group_t **out,
                               const char **err_msg, const char **err_field, char *err_group,
                               const firc_fakeip_t *pool, char *msgbuf, size_t msgbuf_len) {
    firc_id_t req_id;
    bool has_req_id;
    if (parse_optional_id(req, "id", &req_id, &has_req_id) != FIRC_OK) {
        *err_msg = "invalid group id";
        return FIRC_ERR_INVAL;
    }
    if (existing && has_req_id && !firc_id_equal(existing->id, req_id)) {
        *err_msg = "group ID mismatch";
        return FIRC_ERR_INVAL;
    }

    firc_group_t *group = firc_group_new();
    if (!group) { return FIRC_ERR_NOMEM; }
    group->id = existing ? existing->id : (has_req_id ? req_id : firc_id_random());

    /* the interface name is written unquoted into an iptables-restore transcript; a newline corrupts the whole thing */
    const char *iface = get_string(req, "interface");
    if (iface != NULL && iface[0] != '\0' && !firc_is_interface_name(iface)) {
        firc_group_free(group);
        *err_msg = "interface is not an interface name";
        return FIRC_ERR_INVAL;
    }

    firc_err_t err = firc_strset(&group->name, get_string(req, "name"));
    if (err == FIRC_OK) { err = firc_strset(&group->iface, iface); }
    if (err != FIRC_OK) {
        firc_group_free(group);
        return err;
    }

    bool enable_present, enable_val;
    get_optional_bool(req, "enable", &enable_val, &enable_present);
    group->enable = enable_present ? enable_val : true;

    if (existing != NULL || has_req_id) { /* "" when the id is fresh and random (see write_group_error) */
        firc_id_format(group->id, err_group);
    } else {
        err_group[0] = '\0';
    }

    err = firc_api_devices_from_req(req, existing != NULL ? &existing->devices : NULL, &group->devices,
                                    err_msg, err_field, msgbuf, msgbuf_len);
    if (err != FIRC_OK) {
        firc_group_free(group);
        return err;
    }

    err = resolve_from_req(req, existing, pool, &group->resolve, err_msg, err_field, msgbuf, msgbuf_len);
    if (err != FIRC_OK) {
        firc_group_free(group);
        return err;
    }

    /* absent keeps the live list as a config copy; null removes it; an object replaces it; anything else is refused */
    cJSON *list_j = cJSON_GetObjectItemCaseSensitive(req, "list");
    if (list_j == NULL) {
        if (existing != NULL && existing->list != NULL) {
            group->list = list_config_copy(existing->list);
            if (group->list == NULL) {
                firc_group_free(group);
                return FIRC_ERR_NOMEM;
            }
        }
    } else if (cJSON_IsNull(list_j)) {
        /* group->list is already NULL */
    } else if (cJSON_IsObject(list_j)) {
        err = list_from_req(list_j, existing != NULL ? existing->list : NULL, &group->list, err_msg);
        if (err != FIRC_OK) {
            firc_group_free(group);
            return err;
        }
    } else {
        firc_group_free(group);
        *err_msg = "invalid list";
        return FIRC_ERR_INVAL;
    }

    cJSON *rules_j = cJSON_GetObjectItemCaseSensitive(req, "rules");
    if (rules_j && !cJSON_IsNull(rules_j)) {
        if (!cJSON_IsArray(rules_j)) {
            firc_group_free(group);
            *err_msg = "invalid rules";
            return FIRC_ERR_INVAL;
        }
        firc_rule_t **baseline = existing ? existing->rules : NULL;
        size_t n_baseline = existing ? existing->n_rules : 0;
        int n = cJSON_GetArraySize(rules_j);
        for (int i = 0; i < n; i++) {
            const char *rule_why = NULL;
            cJSON *rule_j = cJSON_GetArrayItem(rules_j, i);
            firc_rule_t *r = rule_from_req(rule_j, baseline, n_baseline, &rule_why);
            if (r == NULL && rule_why != NULL) {
                /* falls back to existing->name when the PUT left "name" out, which is the one the operator is looking at */
                const char *gname = (group->name != NULL && group->name[0] != '\0')
                                        ? group->name
                                        : (existing != NULL ? existing->name : NULL);
                *err_msg = locate_rule(msgbuf, msgbuf_len, gname, get_string(rule_j, "type"),
                                       get_string(rule_j, "rule"), i, rule_why);
                firc_group_free(group);
                return FIRC_ERR_INVAL;
            }
            if (!r || firc_group_add_rule(group, r) != FIRC_OK) {
                firc_rule_free(r);
                firc_group_free(group);
                return FIRC_ERR_NOMEM;
            }
        }
    } else if (existing) {
        /* this returns an independent object, so existing's rules are deep-copied rather than aliased */
        for (size_t i = 0; i < existing->n_rules; i++) {
            firc_rule_t *r = firc_rule_new();
            firc_err_t e = r ? FIRC_OK : FIRC_ERR_NOMEM;
            if (e == FIRC_OK) { r->id = existing->rules[i]->id; }
            if (e == FIRC_OK) { e = firc_strset(&r->type, existing->rules[i]->type); }
            if (e == FIRC_OK) { e = firc_strset(&r->rule, existing->rules[i]->rule); }
            if (e == FIRC_OK) { e = firc_strset(&r->proto, existing->rules[i]->proto); }
            if (e == FIRC_OK) { e = firc_strset(&r->ports, existing->rules[i]->ports); }
            if (e == FIRC_OK) { r->enable = existing->rules[i]->enable; }
            if (e != FIRC_OK || firc_group_add_rule(group, r) != FIRC_OK) {
                firc_rule_free(r);
                firc_group_free(group);
                return e != FIRC_OK ? e : FIRC_ERR_NOMEM;
            }
        }
    }
    *out = group;
    return FIRC_OK;
}

static cJSON *rule_to_json(const firc_rule_t *r) {
    char id_buf[FIRC_ID_STR_LEN];
    firc_id_format(r->id, id_buf);
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "id", id_buf);
    cJSON_AddStringToObject(obj, "type", r->type ? r->type : "");
    cJSON_AddStringToObject(obj, "rule", r->rule ? r->rule : "");
    cJSON_AddBoolToObject(obj, "enable", r->enable);
    /* only when set, so an unset rule has neither key */
    if (r->proto != NULL && *r->proto != '\0') { cJSON_AddStringToObject(obj, "proto", r->proto); }
    if (r->ports != NULL && *r->ports != '\0') { cJSON_AddStringToObject(obj, "ports", r->ports); }
    return obj;
}

static cJSON *rules_to_json_array(firc_rule_t **rules, size_t n) {
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < n; i++) { cJSON_AddItemToArray(arr, rule_to_json(rules[i])); }
    return arr;
}

static cJSON *wrap_rules(firc_rule_t **rules, size_t n) {
    cJSON *out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "rules", rules_to_json_array(rules, n));
    return out;
}

/* never the rules themselves, only their count; sync.progress is null outside QUEUED/FETCHING; NULL on OOM */
static cJSON *list_to_json(const firc_group_list_t *l) {
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) { return NULL; }
    if (cJSON_AddStringToObject(obj, "url", l->url ? l->url : "") == NULL ||
        cJSON_AddNumberToObject(obj, "interval", l->interval) == NULL ||
        cJSON_AddNumberToObject(obj, "lastUpdate", l->last_update) == NULL ||
        cJSON_AddNumberToObject(obj, "rulesTotal", (double)l->rules.n) == NULL) {
        cJSON_Delete(obj);
        return NULL;
    }
    cJSON *sync = firc_api_list_sync_json(l);
    if (sync == NULL) {
        cJSON_Delete(obj);
        return NULL;
    }
    bool running = l->sync_state == FIRC_SUB_SYNC_QUEUED || l->sync_state == FIRC_SUB_SYNC_FETCHING;
    cJSON *progress = running ? firc_api_list_progress_json(l) : cJSON_CreateNull();
    if (progress == NULL) {
        cJSON_Delete(sync);
        cJSON_Delete(obj);
        return NULL;
    }
    cJSON_AddItemToObject(sync, "progress", progress);
    cJSON_AddItemToObject(obj, "sync", sync);
    return obj;
}

/* fails whole (NULL) rather than coming back with devices or list silently missing; app nullable omits resolver */
cJSON *firc_groups_group_json(firc_app_t *app, const firc_group_t *g, bool with_rules) {
    char id_buf[FIRC_ID_STR_LEN];
    firc_id_format(g->id, id_buf);
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) { return NULL; }
    cJSON_AddStringToObject(obj, "id", id_buf);
    cJSON_AddStringToObject(obj, "name", g->name ? g->name : "");
    cJSON_AddStringToObject(obj, "interface", g->iface ? g->iface : "");
    cJSON_AddBoolToObject(obj, "enable", g->enable);
    if (app != NULL) {
        const char *reason = NULL;
        bool live = firc_app_group_live(app, g->id, &reason);
        cJSON_AddBoolToObject(obj, "live", live);
        if (!live) { cJSON_AddStringToObject(obj, "liveReason", reason); }
    }
    cJSON *devices = firc_api_devices_to_json(&g->devices);
    if (devices == NULL) {
        cJSON_Delete(obj);
        return NULL;
    }
    cJSON_AddItemToObject(obj, "devices", devices);
    cJSON *resolve = cJSON_AddObjectToObject(obj, "resolve");
    if (resolve == NULL) {
        cJSON_Delete(obj);
        return NULL;
    }
    cJSON_AddBoolToObject(resolve, "tunnel", g->resolve.tunnel);
    cJSON_AddStringToObject(resolve, "server", g->resolve.server != NULL ? g->resolve.server : "");
    if (app != NULL) {
        firc_app_resolver_info_t info;
        firc_app_group_resolver(app, g, &info);
        cJSON *rv = cJSON_AddObjectToObject(obj, "resolver");
        cJSON *servers = rv != NULL ? cJSON_AddArrayToObject(rv, "servers") : NULL;
        if (servers == NULL) {
            cJSON_Delete(obj);
            return NULL;
        }
        cJSON_AddStringToObject(rv, "source", firc_resolve_source_name(info.source));
        for (size_t i = 0; i < info.n_servers; i++) {
            char s[FIRC_RESOLVER_ADDR_STRLEN];
            if (firc_resolver_addr_format(&info.servers[i], s, sizeof(s)) > 0) {
                cJSON_AddItemToArray(servers, cJSON_CreateString(s));
            }
        }
        cJSON_AddNumberToObject(rv, "fallbacks", (double)info.fallbacks);
    }
    /* "rules" key omitted otherwise */
    if (with_rules) { cJSON_AddItemToObject(obj, "rules", rules_to_json_array(g->rules, g->n_rules)); }
    if (g->list != NULL) {
        cJSON *list = list_to_json(g->list);
        if (list == NULL) {
            cJSON_Delete(obj);
            return NULL;
        }
        cJSON_AddItemToObject(obj, "list", list);
    }
    return obj;
}

void firc_groups_maybe_save(firc_groups_ctx_t *ctx, firc_http_req_t *req) {
    if (!firc_http_req_query_is_true(req, "save") || !ctx->config_path) { return; }
    firc_err_t err = firc_app_save_groups(ctx->app, ctx->config_path, ctx->config_version ? ctx->config_version : "");
    if (err != FIRC_OK) { FIRC_ERROR("failed to save config file: %s", firc_err_str(err)); }
}

/* must follow every in-place edit through firc_ruleset_group_mut, or a new rule updates netfilter but never resolves */
static void republish_dns_snapshot(firc_groups_ctx_t *ctx) {
    firc_err_t err = firc_app_republish_dns_snapshot(ctx->app);
    if (err != FIRC_OK) { FIRC_ERROR("failed to republish DNS-matching snapshot: %s", firc_err_str(err)); }
}

bool firc_groups_resolve(firc_groups_ctx_t *ctx, firc_http_req_t *req, firc_http_res_t *res,
                         firc_ruleset_t **out) {
    const char *id_str = firc_http_req_param(req, "groupID");
    firc_id_t id;
    if (!id_str || firc_id_parse(id_str, &id) != FIRC_OK) {
        firc_http_res_write_error(res, 400, "invalid group id");
        return false;
    }
    firc_ruleset_t *rs = firc_app_find_group_by_id(ctx->app, id);
    if (!rs) {
        firc_http_res_write_error(res, 404, "group not exist");
        return false;
    }
    *out = rs;
    return true;
}

static bool resolve_rule(firc_ruleset_t *rs, firc_http_req_t *req, firc_http_res_t *res, size_t *out_idx) {
    const char *id_str = firc_http_req_param(req, "ruleID");
    firc_id_t id;
    if (!id_str || firc_id_parse(id_str, &id) != FIRC_OK) {
        firc_http_res_write_error(res, 400, "invalid rule id");
        return false;
    }
    const firc_group_t *g = firc_ruleset_group(rs);
    for (size_t i = 0; i < g->n_rules; i++) {
        if (firc_id_equal(g->rules[i]->id, id)) {
            *out_idx = i;
            return true;
        }
    }
    firc_http_res_write_error(res, 404, "rule not exist");
    return false;
}

static void handle_get_groups(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    bool with_rules = firc_http_req_query_is_true(req, "with_rules");
    cJSON *out = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(out, "groups");
    size_t n = firc_app_user_group_count(ctx->app);
    for (size_t i = 0; i < n; i++) {
        const firc_group_t *g = firc_ruleset_group(firc_app_user_group_at(ctx->app, i));
        cJSON *gj = firc_groups_group_json(ctx->app, g, with_rules);
        if (gj == NULL) {
            cJSON_Delete(out);
            firc_http_res_write_error(res, 500, "out of memory");
            return;
        }
        cJSON_AddItemToArray(arr, gj);
    }
    firc_http_res_write_json(res, 200, out);
}

static void handle_put_groups(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    cJSON *json = parse_body_json(req);
    if (!json) {
        firc_http_res_write_error(res, 400, "failed to parse request");
        return;
    }
    cJSON *groups_j = cJSON_GetObjectItemCaseSensitive(json, "groups");
    if (!groups_j || cJSON_IsNull(groups_j) || !cJSON_IsArray(groups_j)) {
        cJSON_Delete(json);
        firc_http_res_write_error(res, 400, "no groups in request");
        return;
    }

    /* parsed against the CURRENT groups first; the swap below disables and replaces them under one lock acquisition */
    int n_req = cJSON_GetArraySize(groups_j);
    firc_group_t **new_groups = n_req > 0 ? calloc((size_t)n_req, sizeof(*new_groups)) : NULL;
    if (n_req > 0 && !new_groups) {
        cJSON_Delete(json);
        firc_http_res_write_error(res, 500, "out of memory");
        return;
    }
    for (int i = 0; i < n_req; i++) {
        cJSON *group_req = cJSON_GetArrayItem(groups_j, i);
        firc_id_t wanted_id;
        bool has_id;
        const firc_group_t *existing = NULL;
        if (parse_optional_id(group_req, "id", &wanted_id, &has_id) == FIRC_OK && has_id) {
            firc_ruleset_t *rs = firc_app_find_group_by_id(ctx->app, wanted_id);
            if (rs) { existing = firc_ruleset_group(rs); }
        }
        const char *err_msg = "invalid group";
        const char *err_field = NULL;
        char err_group[FIRC_ID_STR_LEN] = "";
        char msgbuf[FIRC_RULE_WHERE_MAX];
        firc_err_t err = group_from_req(group_req, existing, &new_groups[i], &err_msg, &err_field, err_group,
                                        firc_app_pool(ctx->app), msgbuf, sizeof(msgbuf));
        if (err == FIRC_ERR_NOMEM) { /* not the client's fault -- see handle_create_group */
            cJSON_Delete(json);
            for (int j = 0; j < i; j++) { firc_group_free(new_groups[j]); }
            free(new_groups);
            firc_http_res_write_error(res, 500, firc_err_str(err));
            return;
        }
        if (err != FIRC_OK) {
            cJSON_Delete(json);
            for (int j = 0; j < i; j++) { firc_group_free(new_groups[j]); }
            free(new_groups);
            write_group_error(res, err_msg, err_field, err_group);
            return;
        }
    }
    cJSON_Delete(json);

    /* built AFTER the swap, from the live groups: the swap is what moves a carried list's arena in */
    firc_err_t err = firc_app_replace_groups(ctx->app, new_groups, (size_t)n_req);
    if (err != FIRC_OK) {
        firc_http_res_write_error(res, 500, firc_err_str(err));
        return;
    }
    cJSON *out = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(out, "groups");
    size_t n_live = firc_app_user_group_count(ctx->app);
    for (size_t i = 0; i < n_live; i++) {
        cJSON *gj = firc_groups_group_json(ctx->app, firc_ruleset_group(firc_app_user_group_at(ctx->app, i)), true);
        if (gj == NULL) {
            /* the replace already happened, so a ?save=true is still owed even though the response build failed */
            cJSON_Delete(out);
            firc_http_res_write_error(res, 500, "out of memory");
            firc_groups_maybe_save(ctx, req);
            return;
        }
        cJSON_AddItemToArray(arr, gj);
    }
    firc_http_res_write_json(res, 200, out);
    firc_groups_maybe_save(ctx, req);
}

static void handle_create_group(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    cJSON *json = parse_body_json(req);
    if (!json) {
        firc_http_res_write_error(res, 400, "failed to parse request");
        return;
    }
    firc_group_t *group = NULL;
    const char *err_msg = "invalid group";
    const char *err_field = NULL;
    char err_group[FIRC_ID_STR_LEN] = "";
    char msgbuf[FIRC_RULE_WHERE_MAX];
    firc_err_t err = group_from_req(json, NULL, &group, &err_msg, &err_field, err_group,
                                    firc_app_pool(ctx->app), msgbuf, sizeof(msgbuf));
    cJSON_Delete(json);
    if (err == FIRC_ERR_NOMEM) { /* not the client's fault: a 400 would tell the operator to fix a body that was fine */
        firc_http_res_write_error(res, 500, firc_err_str(err));
        return;
    }
    if (err != FIRC_OK) {
        write_group_error(res, err_msg, err_field, err_group);
        return;
    }

    char why[FIRC_APP_WHY_MAX] = "";
    err = firc_app_add_group_why(ctx->app, group, why, sizeof(why)); /* always takes ownership */
    if (err != FIRC_OK) {
        int status = err == FIRC_ERR_EXIST ? 409 : 500; /* a group that did not come up says which step failed */
        firc_http_res_write_error(res, status, why[0] != '\0' ? why : firc_err_str(err));
        return;
    }
    firc_http_res_write_json(res, 200, firc_groups_group_json(ctx->app, group, true)); /* still valid: no free on success */
    firc_groups_maybe_save(ctx, req);
}

static void handle_get_group(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    firc_ruleset_t *rs;
    if (!firc_groups_resolve(ctx, req, res, &rs)) { return; }
    bool with_rules = firc_http_req_query_is_true(req, "with_rules");
    firc_http_res_write_json(res, 200, firc_groups_group_json(ctx->app, firc_ruleset_group(rs), with_rules));
}

static void handle_put_group(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    firc_ruleset_t *rs;
    if (!firc_groups_resolve(ctx, req, res, &rs)) { return; }

    cJSON *json = parse_body_json(req);
    if (!json) {
        firc_http_res_write_error(res, 400, "failed to parse request");
        return;
    }

    /* built and validated before the group leaves the kernel: a 400 must leave it exactly as it was */
    firc_group_t *live = firc_ruleset_group_mut(rs);
    firc_group_t *built = NULL;
    const char *err_msg = "invalid group";
    const char *err_field = NULL;
    char err_group[FIRC_ID_STR_LEN] = "";
    char msgbuf[FIRC_RULE_WHERE_MAX];
    firc_err_t err = group_from_req(json, live, &built, &err_msg, &err_field, err_group,
                                    firc_app_pool(ctx->app), msgbuf, sizeof(msgbuf));
    cJSON_Delete(json);
    if (err == FIRC_ERR_NOMEM) {
        firc_http_res_write_error(res, 500, firc_err_str(err));
        return;
    }
    if (err != FIRC_OK) {
        write_group_error(res, err_msg, err_field, err_group);
        return;
    }

    err = firc_app_update_group(ctx->app, live->id, built); /* takes built either way; live keeps its address */
    if (err != FIRC_OK) {
        firc_http_res_write_error(res, 500, firc_err_str(err));
        return;
    }

    firc_http_res_write_json(res, 200, firc_groups_group_json(ctx->app, live, true));
    firc_groups_maybe_save(ctx, req);
}

static void handle_delete_group(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    firc_ruleset_t *rs;
    if (!firc_groups_resolve(ctx, req, res, &rs)) { return; }
    /* a teardown error is logged by the app and keeps nothing, so this answers 200 regardless */
    firc_app_remove_group_by_id(ctx->app, firc_ruleset_group(rs)->id);
    firc_http_res_write(res, 200, NULL, NULL, 0);
    firc_groups_maybe_save(ctx, req);
}

static void handle_get_rules(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    firc_ruleset_t *rs;
    if (!firc_groups_resolve(ctx, req, res, &rs)) { return; }
    const firc_group_t *g = firc_ruleset_group(rs);
    firc_http_res_write_json(res, 200, wrap_rules(g->rules, g->n_rules));
}

static void handle_put_rules(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    firc_ruleset_t *rs;
    if (!firc_groups_resolve(ctx, req, res, &rs)) { return; }

    cJSON *json = parse_body_json(req);
    if (!json) {
        firc_http_res_write_error(res, 400, "failed to parse request");
        return;
    }
    cJSON *rules_j = cJSON_GetObjectItemCaseSensitive(json, "rules");
    if (!rules_j || cJSON_IsNull(rules_j) || !cJSON_IsArray(rules_j)) {
        cJSON_Delete(json);
        firc_http_res_write_error(res, 400, "no rules in request");
        return;
    }

    firc_group_t *group = firc_ruleset_group_mut(rs);
    int n = cJSON_GetArraySize(rules_j);
    firc_group_t built = {0}; /* built through firc_group_add_rule, as a later POST append assumes */
    for (int i = 0; i < n; i++) {
        const char *why = NULL;
        cJSON *rule_j = cJSON_GetArrayItem(rules_j, i);
        firc_rule_t *rule = NULL;
        firc_err_t err = rule_from_req_strict(rule_j, group->rules, group->n_rules, &rule, &why);
        if (err == FIRC_OK) {
            err = firc_group_add_rule(&built, rule);
            if (err != FIRC_OK) { firc_rule_free(rule); }
        }
        if (err != FIRC_OK) {
            for (size_t j = 0; j < built.n_rules; j++) { firc_rule_free(built.rules[j]); }
            free(built.rules);
            if (err == FIRC_ERR_INVAL && why != NULL) {
                char msgbuf[FIRC_RULE_WHERE_MAX]; /* built before json is freed: the pattern points into it */
                const char *msg = locate_rule(msgbuf, sizeof(msgbuf), group->name,
                                              get_string(rule_j, "type"),
                                              get_string(rule_j, "rule"), i, why);
                cJSON_Delete(json);
                firc_http_res_write_error(res, 400, msg);
                return;
            }
            cJSON_Delete(json);
            if (err == FIRC_ERR_NOENT) {
                firc_http_res_write_error(res, 404, "rule not found");
            } else if (err == FIRC_ERR_NOMEM) {
                firc_http_res_write_error(res, 500, "out of memory");
            } else {
                firc_http_res_write_error(res, 400, "invalid rule");
            }
            return;
        }
    }
    cJSON_Delete(json);

    for (size_t i = 0; i < group->n_rules; i++) { firc_rule_free(group->rules[i]); }
    free(group->rules);
    group->rules = built.rules;
    group->n_rules = built.n_rules;
    republish_dns_snapshot(ctx);

    if (firc_ruleset_runtime_enabled(rs)) {
        firc_err_t err = firc_app_sync_group(ctx->app, rs);
        if (err != FIRC_OK) {
            firc_http_res_write_error(res, 500, firc_err_str(err));
            return;
        }
    }

    firc_http_res_write_json(res, 200, wrap_rules(group->rules, group->n_rules));
    firc_groups_maybe_save(ctx, req);
}

static void handle_create_rule(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    firc_ruleset_t *rs;
    if (!firc_groups_resolve(ctx, req, res, &rs)) { return; }

    cJSON *json = parse_body_json(req);
    if (!json) {
        firc_http_res_write_error(res, 400, "failed to parse request");
        return;
    }
    firc_group_t *group = firc_ruleset_group_mut(rs);
    const char *why = NULL;
    firc_rule_t *rule = rule_from_req(json, group->rules, group->n_rules, &why);
    if (rule == NULL && why != NULL) {
        char msgbuf[FIRC_RULE_WHERE_MAX];
        const char *msg = locate_rule(msgbuf, sizeof(msgbuf), NULL, get_string(json, "type"),
                                      get_string(json, "rule"), (int)group->n_rules, why);
        cJSON_Delete(json);
        firc_http_res_write_error(res, 400, msg);
        return;
    }
    cJSON_Delete(json);
    if (!rule) {
        firc_http_res_write_error(res, 500, "out of memory");
        return;
    }
    if (firc_group_add_rule(group, rule) != FIRC_OK) {
        firc_rule_free(rule);
        firc_http_res_write_error(res, 500, "out of memory");
        return;
    }
    republish_dns_snapshot(ctx);

    if (firc_ruleset_runtime_enabled(rs)) {
        firc_err_t err = firc_app_sync_group(ctx->app, rs);
        if (err != FIRC_OK) {
            firc_http_res_write_error(res, 500, firc_err_str(err));
            return;
        }
    }

    firc_http_res_write_json(res, 200, rule_to_json(rule));
    firc_groups_maybe_save(ctx, req);
}

static void handle_get_rule(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    firc_ruleset_t *rs;
    if (!firc_groups_resolve(ctx, req, res, &rs)) { return; }
    size_t idx;
    if (!resolve_rule(rs, req, res, &idx)) { return; }
    firc_http_res_write_json(res, 200, rule_to_json(firc_ruleset_group(rs)->rules[idx]));
}

static void handle_put_rule(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    firc_ruleset_t *rs;
    if (!firc_groups_resolve(ctx, req, res, &rs)) { return; }
    size_t idx;
    if (!resolve_rule(rs, req, res, &idx)) { return; }

    cJSON *json = parse_body_json(req);
    if (!json) {
        firc_http_res_write_error(res, 400, "failed to parse request");
        return;
    }
    /* the rule's identity always stays the path-resolved one; the body's own "id" is never read */
    firc_rule_t *rule = firc_ruleset_group_mut(rs)->rules[idx];
    /* checked before a single field is written: a refusal partway would leave the rule half-replaced */
    const char *why = NULL;
    bool bad = false;
    const char *proto = get_opt_string(json, "proto", &bad);
    const char *ports = get_opt_string(json, "ports", &bad);
    if (bad) { why = why_not_strings; }
    if (bad || !firc_rule_spec_is_usable(get_string(json, "type"), get_string(json, "rule"), proto, ports, &why)) {
        char msgbuf[FIRC_RULE_WHERE_MAX];
        const char *msg =
            locate_rule(msgbuf, sizeof(msgbuf), NULL, get_string(json, "type"),
                        get_string(json, "rule"), (int)idx, why);
        cJSON_Delete(json);
        firc_http_res_write_error(res, 400, msg);
        return;
    }
    firc_err_t err = fill_rule_fields(rule, json, NULL);
    cJSON_Delete(json);
    if (err == FIRC_ERR_INVAL) { /* unreachable while the pre-check above stands */
        firc_http_res_write_error(res, 400, why != NULL ? why : "the rule is unusable");
        return;
    }
    if (err != FIRC_OK) {
        firc_http_res_write_error(res, 500, "out of memory");
        return;
    }
    republish_dns_snapshot(ctx);

    if (firc_ruleset_runtime_enabled(rs)) {
        err = firc_app_sync_group(ctx->app, rs);
        if (err != FIRC_OK) {
            firc_http_res_write_error(res, 500, firc_err_str(err));
            return;
        }
    }

    firc_http_res_write_json(res, 200, rule_to_json(rule));
    firc_groups_maybe_save(ctx, req);
}

static void handle_delete_rule(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    firc_ruleset_t *rs;
    if (!firc_groups_resolve(ctx, req, res, &rs)) { return; }
    size_t idx;
    if (!resolve_rule(rs, req, res, &idx)) { return; }

    firc_group_t *group = firc_ruleset_group_mut(rs);
    firc_rule_free(group->rules[idx]);
    for (size_t i = idx; i + 1 < group->n_rules; i++) { group->rules[i] = group->rules[i + 1]; }
    group->n_rules--;
    republish_dns_snapshot(ctx);

    if (firc_ruleset_runtime_enabled(rs)) {
        firc_err_t err = firc_app_sync_group(ctx->app, rs);
        if (err != FIRC_OK) {
            firc_http_res_write_error(res, 500, firc_err_str(err));
            return;
        }
    }

    firc_http_res_write(res, 200, NULL, NULL, 0);
    firc_groups_maybe_save(ctx, req);
}

void firc_groups_register_routes(firc_httpd_t *h, firc_groups_ctx_t *ctx) {
    firc_group_lists_register_routes(h, ctx);
    must_route(h, "GET", "/api/v1/groups", handle_get_groups, ctx);
    must_route(h, "PUT", "/api/v1/groups", handle_put_groups, ctx);
    must_route(h, "POST", "/api/v1/groups", handle_create_group, ctx);
    must_route(h, "GET", "/api/v1/groups/{groupID}", handle_get_group, ctx);
    must_route(h, "PUT", "/api/v1/groups/{groupID}", handle_put_group, ctx);
    must_route(h, "DELETE", "/api/v1/groups/{groupID}", handle_delete_group, ctx);
    must_route(h, "GET", "/api/v1/groups/{groupID}/rules", handle_get_rules, ctx);
    must_route(h, "PUT", "/api/v1/groups/{groupID}/rules", handle_put_rules, ctx);
    must_route(h, "POST", "/api/v1/groups/{groupID}/rules", handle_create_rule, ctx);
    must_route(h, "GET", "/api/v1/groups/{groupID}/rules/{ruleID}", handle_get_rule, ctx);
    must_route(h, "PUT", "/api/v1/groups/{groupID}/rules/{ruleID}", handle_put_rule, ctx);
    must_route(h, "DELETE", "/api/v1/groups/{groupID}/rules/{ruleID}", handle_delete_rule, ctx);
}
