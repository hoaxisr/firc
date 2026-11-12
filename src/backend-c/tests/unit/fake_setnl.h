#ifndef FIRC_TEST_FAKE_SETNL_H
#define FIRC_TEST_FAKE_SETNL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/ipset_to_link.h"
#include "firc/setnl.h"

typedef struct fake_setnl fake_setnl_t;

typedef struct {
    char type[32];
    uint8_t family;
    uint8_t revision;
    uint32_t maxelem;
    uint32_t hashsize;
    bool referenced;
} fake_setnl_meta_t;

fake_setnl_t *fake_setnl_start(firc_setnl_t **out);
void fake_setnl_stop(fake_setnl_t *f);

void fake_setnl_set_revision(fake_setnl_t *f, uint8_t family, uint8_t rev);
void fake_setnl_no_type(fake_setnl_t *f);
void fake_setnl_no_subsystem(fake_setnl_t *f);
void fake_setnl_reference(fake_setnl_t *f, const char *name, bool on);
void fake_setnl_fail_add_at(fake_setnl_t *f, size_t nth, int err);
void fake_setnl_fail_add_also(fake_setnl_t *f, size_t nth, int err);
void fake_setnl_fail_next(fake_setnl_t *f, uint8_t cmd, int err, bool apply);
void fake_setnl_never_answer(fake_setnl_t *f);
void fake_setnl_plant(fake_setnl_t *f, const char *name, uint8_t family);
void fake_setnl_hold_adds(fake_setnl_t *f, bool on);
void fake_setnl_on_step(fake_setnl_t *f, void (*fn)(const char *what, const char *name, void *ud), void *ud);

bool fake_setnl_has(fake_setnl_t *f, const char *name);
size_t fake_setnl_count(fake_setnl_t *f, const char *name);
bool fake_setnl_contains(fake_setnl_t *f, const char *name, const firc_nf_prefix_t *p);
bool fake_setnl_meta(fake_setnl_t *f, const char *name, fake_setnl_meta_t *out);
size_t fake_setnl_sets(fake_setnl_t *f);
size_t fake_setnl_messages(fake_setnl_t *f);
size_t fake_setnl_sends(fake_setnl_t *f);
size_t fake_setnl_largest_send(fake_setnl_t *f);
bool fake_setnl_last_datagram(fake_setnl_t *f, uint8_t cmd, const uint8_t **data, size_t *len);

#endif
