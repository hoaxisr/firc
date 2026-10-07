#ifndef TUNVLESS_CONTROL_H
#define TUNVLESS_CONTROL_H

#include <stddef.h>

void ctl_init(int enabled);
void ctl_close_inherited_fds(void);
void ctl_emit_ready(const char *dev);
void ctl_emit_active(const char *const *names, const int *index, size_t n);
void ctl_emit_node_down(const char *node, int index, const char *why);
void ctl_emit_node_up(const char *node, int index);
void ctl_emit_nodes(int count);
void ctl_emit_pins_full(void);
void ctl_emit_no_node(int retry_s);

size_t ctl_json_str(char *out, size_t cap, const char *s);

#endif
