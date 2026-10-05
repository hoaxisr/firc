#ifndef FIRC_SUBPARSE_INTERNAL_H
#define FIRC_SUBPARSE_INTERNAL_H
/* What the two list parsers share; not a public API. */
#include "firc/subparse.h"

typedef struct firc_sub_sink firc_sub_sink_t;

/* Stores one rule; piece is trimmed/folded in place; type NULL means guess it; proto/ports NULL means none. */
firc_err_t firc_sub_sink_take(firc_sub_sink_t *s, char *piece, const char *type, const char *proto,
                              const char *ports, bool *took);

/* The sing-box walker: body starts with '{'; emits into sink, counts into st. */
firc_err_t firc_sub_parse_singbox(const char *body, firc_sub_sink_t *sink, firc_sub_parse_stats_t *st,
                                  firc_sub_parse_progress_fn progress, void *ud);
#endif
