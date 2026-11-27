#ifndef FIRC_LIST_CATALOG_H
#define FIRC_LIST_CATALOG_H

#include <stdbool.h>
#include <stddef.h>

#include <cjson/cJSON.h>

#include "firc/err.h"

#define FIRC_LIST_CATALOG_URL "https://raw.githubusercontent.com/hoaxisr/rulesets/master/catalog.json"
#define FIRC_LIST_CATALOG_MAX_BYTES ((size_t)1024 * 1024)
/* Provider catalogs kept at once beside the index, including in-flight fetches. */
#define FIRC_LIST_CATALOG_PROVIDERS_MAX 16

/* Checks a rule-set index and copies {"generated","sources"} into *out (caller deletes). INVAL: why names the first offence.
 * provider NULL: the index, whose optional "providers" ([{id,name}]) is checked and copied too. Otherwise the file of
 * that provider, every source id of which must be provider or start with provider and a dash. */
firc_err_t firc_list_catalog_parse(const char *body, size_t len, const char *provider, cJSON **out, char *why,
                                   size_t why_cap);

/* True for a source or provider id: [a-z0-9-]{1,32}. */
bool firc_list_catalog_id_ok(const char *s);

/* Writes the URL of provider's file into buf: catalog/<provider>.json in the directory of the index at base.
 * False when base has no path or buf is too short. */
bool firc_list_catalog_provider_url(const char *base, const char *provider, char *buf, size_t cap);

#endif
