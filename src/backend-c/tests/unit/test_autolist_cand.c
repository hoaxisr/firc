#include "greatest.h"

#include <stdio.h>
#include <string.h>

#include "firc/autolistcand.h"

static firc_ip_t ip4(uint8_t last) {
    firc_ip_t a;
    memset(&a, 0, sizeof(a));
    a.len = 4;
    a.b[0] = 192; a.b[1] = 168; a.b[2] = 1; a.b[3] = last;
    return a;
}

static void name(char *buf, int i) { snprintf(buf, 32, "site%d.example", i); }

TEST sixty_fifth_drops_oldest(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    char n[32];
    for (int i = 0; i < 65; i++) {
        name(n, i);
        ASSERT(firc_al_cands_note(c, n, n, FIRC_AL_WHY_RESET, 1, NULL, 1000 + i) != NULL);
    }
    name(n, 0);
    ASSERT_EQ(NULL, firc_al_cands_find(c, n));
    name(n, 1);
    ASSERT(firc_al_cands_find(c, n) != NULL);
    name(n, 64);
    ASSERT(firc_al_cands_find(c, n) != NULL);
    const firc_al_cand_t *out[80];
    ASSERT_EQ(64, firc_al_cands_list(c, out, 80));
    firc_al_cands_free(c);
    PASS();
}

TEST refreshed_entry_survives_eviction(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    char n[32];
    for (int i = 0; i < 64; i++) { name(n, i); firc_al_cands_note(c, n, n, FIRC_AL_WHY_RESET, 1, NULL, 1000 + i); }
    name(n, 0);
    firc_al_cands_note(c, n, n, FIRC_AL_WHY_RESET, 2, NULL, 2000);
    firc_al_cands_note(c, "new.example", "new.example", FIRC_AL_WHY_RESET, 1, NULL, 2001);
    ASSERT(firc_al_cands_find(c, n) != NULL);
    name(n, 1);
    ASSERT_EQ(NULL, firc_al_cands_find(c, n));
    firc_al_cands_free(c);
    PASS();
}

TEST dismissed_is_not_noted_for_a_day(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    firc_al_cands_note(c, "a.example", "www.a.example", FIRC_AL_WHY_RESET, 3, NULL, 500);
    ASSERT(firc_al_cands_dismiss(c, "a.example", 1000));
    ASSERT_EQ(NULL, firc_al_cands_find(c, "a.example"));
    ASSERT_EQ(NULL, firc_al_cands_note(c, "a.example", "a.example", FIRC_AL_WHY_RESET, 3, NULL, 1000 + 86399));
    ASSERT(firc_al_cands_note(c, "a.example", "a.example", FIRC_AL_WHY_RESET, 3, NULL, 1000 + 86400) != NULL);
    ASSERT(firc_al_cands_note(c, "a.example", "a.example", FIRC_AL_WHY_RESET, 4, NULL, 1000 + 86401) != NULL);
    firc_al_cands_free(c);
    PASS();
}

TEST dismissing_an_unknown_name_is_false(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    ASSERT_FALSE(firc_al_cands_dismiss(c, "nope.example", 1));
    ASSERT(firc_al_cands_note(c, "nope.example", "nope.example", FIRC_AL_WHY_RESET, 1, NULL, 2) != NULL);
    firc_al_cands_free(c);
    PASS();
}

TEST dismissals_beyond_sixty_four_forget_the_oldest(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    char n[32];
    for (int i = 0; i < 65; i++) {
        name(n, i);
        firc_al_cands_note(c, n, n, FIRC_AL_WHY_RESET, 1, NULL, 10);
        ASSERT(firc_al_cands_dismiss(c, n, 100 + i));
    }
    name(n, 0);
    ASSERT(firc_al_cands_note(c, n, n, FIRC_AL_WHY_RESET, 1, NULL, 200) != NULL);
    name(n, 1);
    ASSERT_EQ(NULL, firc_al_cands_note(c, n, n, FIRC_AL_WHY_RESET, 1, NULL, 200));
    firc_al_cands_free(c);
    PASS();
}

TEST note_updates_in_place(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    firc_ip_t a = ip4(10), b = ip4(11);
    firc_al_cand_t *e = firc_al_cands_note(c, "a.example", "www.a.example", FIRC_AL_WHY_NO_ANSWER, 3, &a, 100);
    ASSERT(e != NULL);
    ASSERT_STR_EQ("a.example", e->domain);
    ASSERT_STR_EQ("www.a.example", e->host);
    ASSERT_EQ(FIRC_AL_WHY_NO_ANSWER, e->why);
    ASSERT_EQ(FIRC_AL_CAND, e->state);
    ASSERT_EQ(0, e->notes);
    ASSERT_EQ(1, e->n_clients);
    e->state = FIRC_AL_CHECKING;
    e->notes = 2;
    firc_al_cand_t *f = firc_al_cands_note(c, "a.example", "m.a.example", FIRC_AL_WHY_RESET, 5, &a, 200);
    ASSERT_EQ(e, f);
    ASSERT_EQ(5, f->fails);
    ASSERT_EQ(200, f->last_at);
    ASSERT_EQ(FIRC_AL_WHY_RESET, f->why);
    ASSERT_STR_EQ("m.a.example", f->host);
    ASSERT_EQ(1, f->n_clients);
    ASSERT_EQ(FIRC_AL_CHECKING, f->state);
    ASSERT_EQ(2, f->notes);
    firc_al_cands_note(c, "a.example", "m.a.example", FIRC_AL_WHY_RESET, 5, &b, 201);
    ASSERT_EQ(2, f->n_clients);
    ASSERT_EQ(11, f->clients[1].b[3]);
    const firc_al_cand_t *out[4];
    ASSERT_EQ(1, firc_al_cands_list(c, out, 4));
    firc_al_cands_free(c);
    PASS();
}

TEST at_most_four_clients_kept(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    firc_al_cand_t *e = NULL;
    for (uint8_t i = 1; i <= 6; i++) {
        firc_ip_t a = ip4(i);
        e = firc_al_cands_note(c, "a.example", "a.example", FIRC_AL_WHY_FREEZE, 1, &a, 100 + i);
    }
    ASSERT_EQ(4, e->n_clients);
    ASSERT_EQ(1, e->clients[0].b[3]);
    ASSERT_EQ(4, e->clients[3].b[3]);
    firc_al_cands_free(c);
    PASS();
}

TEST list_is_newest_first(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    firc_al_cands_note(c, "a.example", "a.example", FIRC_AL_WHY_RESET, 1, NULL, 100);
    firc_al_cands_note(c, "b.example", "b.example", FIRC_AL_WHY_RESET, 1, NULL, 200);
    firc_al_cands_note(c, "c.example", "c.example", FIRC_AL_WHY_RESET, 1, NULL, 300);
    firc_al_cands_note(c, "a.example", "a.example", FIRC_AL_WHY_RESET, 2, NULL, 400);
    const firc_al_cand_t *out[8];
    ASSERT_EQ(3, firc_al_cands_list(c, out, 8));
    ASSERT_STR_EQ("a.example", out[0]->domain);
    ASSERT_STR_EQ("c.example", out[1]->domain);
    ASSERT_STR_EQ("b.example", out[2]->domain);
    ASSERT_EQ(2, firc_al_cands_list(c, out, 2));
    ASSERT_STR_EQ("c.example", out[1]->domain);
    ASSERT_EQ(0, firc_al_cands_list(c, out, 0));
    firc_al_cands_free(c);
    PASS();
}

TEST long_names_are_refused_not_truncated(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    char big[300];
    memset(big, 'a', sizeof(big));
    big[253] = '\0';
    ASSERT(firc_al_cands_note(c, big, "h.example", FIRC_AL_WHY_RESET, 1, NULL, 1) != NULL);
    big[254] = '\0';
    big[253] = 'a';
    ASSERT_EQ(NULL, firc_al_cands_note(c, big, "h.example", FIRC_AL_WHY_RESET, 1, NULL, 1));
    ASSERT_EQ(NULL, firc_al_cands_note(c, "d.example", big, FIRC_AL_WHY_RESET, 1, NULL, 1));
    ASSERT_EQ(NULL, firc_al_cands_find(c, "d.example"));
    ASSERT_EQ(NULL, firc_al_cands_note(c, NULL, "h", FIRC_AL_WHY_RESET, 1, NULL, 1));
    firc_al_cands_free(c);
    PASS();
}

TEST forgotten_is_gone_but_may_come_back_at_once(void) {
    firc_al_cands_t *c = firc_al_cands_new();
    firc_ip_t a = ip4(1);
    ASSERT(firc_al_cands_note(c, "x.example", "www.x.example", FIRC_AL_WHY_FREEZE, 0, &a, 100) != NULL);
    ASSERT(firc_al_cands_forget(c, "x.example"));
    ASSERT_EQ(NULL, firc_al_cands_find(c, "x.example"));
    ASSERT_FALSE(firc_al_cands_forget(c, "x.example"));
    ASSERT(firc_al_cands_note(c, "x.example", "www.x.example", FIRC_AL_WHY_RESET, 2, &a, 101) != NULL);
    firc_al_cands_free(c);
    PASS();
}

SUITE(autolist_cand_suite) {
    RUN_TEST(sixty_fifth_drops_oldest);
    RUN_TEST(refreshed_entry_survives_eviction);
    RUN_TEST(dismissed_is_not_noted_for_a_day);
    RUN_TEST(dismissing_an_unknown_name_is_false);
    RUN_TEST(dismissals_beyond_sixty_four_forget_the_oldest);
    RUN_TEST(note_updates_in_place);
    RUN_TEST(at_most_four_clients_kept);
    RUN_TEST(list_is_newest_first);
    RUN_TEST(long_names_are_refused_not_truncated);
    RUN_TEST(forgotten_is_gone_but_may_come_back_at_once);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(autolist_cand_suite);
    GREATEST_MAIN_END();
}
