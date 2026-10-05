#include "greatest.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "firc/auth.h"
#include "firc/events.h"
#include "firc/log.h"
#include "firc/httpd.h"
#include "firc/jwt.h"
#include "firc/loop.h"
#include "firc/system.h"

/* Catches: years added as a fixed number of seconds instead of on the civil calendar. */
TEST add_years_matches_go(void) {
    ASSERT_EQ(1731622400, firc_auth_add_years_utc(1700000000, 1));
    ASSERT_EQ(31536000, firc_auth_add_years_utc(0, 1));
    ASSERT_EQ(951782399, firc_auth_add_years_utc(920246399, 1));
    ASSERT_EQ(1826230400, firc_auth_add_years_utc(1700000000, 4));
    ASSERT_EQ(1835395200, firc_auth_add_years_utc(1709164800, 4));
    ASSERT_EQ(983404800, firc_auth_add_years_utc(951782400, 1));
    ASSERT_EQ(1740787200, firc_auth_add_years_utc(1709164800, 1));
    ASSERT_EQ(3508056000, firc_auth_add_years_utc(3476433600, 1));
    ASSERT_EQ(3155760000, firc_auth_add_years_utc(0, 100));
    ASSERT_EQ(4107585600, firc_auth_add_years_utc(3476433600, 20));
    ASSERT_EQ(2331152000, firc_auth_add_years_utc(1700000000, 20));
    ASSERT_EQ(631152000, firc_auth_add_years_utc(0, 20));
    ASSERT_EQ(1582934400, firc_auth_add_years_utc(951782400, 20));
    ASSERT_EQ(2214086400, firc_auth_add_years_utc(1582934400, 20));
    ASSERT_EQ(1551398399, firc_auth_add_years_utc(920246399, 20));
    PASS();
}

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    fputs(content, f);
    fclose(f);
}

#define SHADOW_FIXTURE "/tmp/firc_test_shadow"
#define PASSWD_FIXTURE "/tmp/firc_test_passwd"

TEST load_password_hash_cases(void) {
    write_file(SHADOW_FIXTURE,
              "# comment\n"
              "root:$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
              "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/:19000:0:99999:7:::\n"
              "nopass:x:19000:0:99999:7:::\n"
              "locked:*:19000:0:99999:7:::\n"
              "empty::19000:0:99999:7:::\n");

    char out[128];
    ASSERT_EQ(FIRC_OK, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "root", out,
                                                     sizeof(out)));
    ASSERT_STR_EQ(
        "$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
        "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/",
        out);

    ASSERT_EQ(FIRC_ERR_NOENT, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE,
                                                            "nopass", out, sizeof(out)));
    write_file(PASSWD_FIXTURE, "locked:$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/:1000:1000::/root:/bin/sh\n");
    ASSERT_EQ_FMT(FIRC_ERR_STATE, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE,
                                                            "locked", out, sizeof(out)), "%d");
    unlink(PASSWD_FIXTURE);
    firc_auth_forget_cached_hash();
    ASSERT_EQ(FIRC_ERR_NOENT, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE,
                                                            "empty", out, sizeof(out)));
    ASSERT_EQ(FIRC_ERR_NOENT, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE,
                                                            "ghost", out, sizeof(out)));

    unlink(SHADOW_FIXTURE);
    PASS();
}

TEST load_password_hash_falls_back_to_passwd(void) {
    unlink(SHADOW_FIXTURE);
    write_file(PASSWD_FIXTURE, "admin:$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/:1000:1000::/root:/bin/sh\n");

    char out[128];
    ASSERT_EQ(FIRC_OK, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin", out,
                                                     sizeof(out)));
    ASSERT_STR_EQ("$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/", out);

    unlink(PASSWD_FIXTURE);
    PASS();
}

TEST an_account_only_in_passwd_is_found_past_a_shadow_that_exists(void) {
    write_file(SHADOW_FIXTURE, "someoneelse:$6$xx$yy:19000:0:99999:7:::\n");
    write_file(PASSWD_FIXTURE, "admin:$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/:1000:1000::/root:/bin/sh\n");

    char out[128];
    ASSERT_EQ_FMT(FIRC_OK,
                  firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin", out,
                                                    sizeof(out)), "%d");
    ASSERT_STR_EQ("$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/", out);

    firc_auth_forget_cached_hash();
    write_file(SHADOW_FIXTURE, "admin:x:19000:0:99999:7:::\n");
    ASSERT_EQ_FMT(FIRC_OK,
                  firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin", out,
                                                    sizeof(out)), "%d");
    ASSERT_STR_EQ("$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/", out);

    firc_auth_forget_cached_hash();
    ASSERT_EQ_FMT(FIRC_ERR_NOENT,
                  firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "nobody", out,
                                                    sizeof(out)), "%d");
    unlink(SHADOW_FIXTURE);
    unlink(PASSWD_FIXTURE);
    firc_auth_forget_cached_hash();
    PASS();
}

static char *mkdtemp_dup(const char *tmpl) {
    char *path = strdup(tmpl);
    return mkdtemp(path);
}

TEST authenticate_and_verify_round_trip(void) {
    write_file(SHADOW_FIXTURE,
              "admin:$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
              "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/:19000:0:99999:7:::\n");
    char *state_dir = mkdtemp_dup("/tmp/firc_auth_state_XXXXXX");
    ASSERT(state_dir != NULL);

    char token[FIRC_JWT_MAX_TOKEN];
    ASSERT_EQ(FIRC_OK, firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir, "admin",
                                               "hunter2", token, sizeof(token)));
    ASSERT(strlen(token) > 0);

    ASSERT_EQ(FIRC_OK, firc_auth_verify_token_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir, token));

    ASSERT_EQ(FIRC_ERR_INVAL, firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir,
                                                      "admin", "wrongpw", token, sizeof(token)));
    ASSERT_EQ(FIRC_ERR_NOENT, firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir,
                                                      "ghost", "hunter2", token, sizeof(token)));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir,
                                                      "", "hunter2", token, sizeof(token)));

    unlink(SHADOW_FIXTURE);
    free(state_dir);
    PASS();
}

/* Catches: every wrong password costing a SHA-512-crypt on the DNS thread. */
TEST a_run_of_wrong_passwords_stops_costing_a_crypt(void) {
    write_file(SHADOW_FIXTURE,
              "admin:$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
              "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/:19000:0:99999:7:::\n");
    char *state_dir = mkdtemp_dup("/tmp/firc_auth_throttle_XXXXXX");
    ASSERT(state_dir != NULL);
    firc_auth_reset_throttle_for_test();
    char token[FIRC_JWT_MAX_TOKEN];

    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_FMTm("judged and refused", FIRC_ERR_INVAL,
                       firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir,
                                                   "admin", "wrongpw", token, sizeof(token)),
                       "%d");
    }
    ASSERT_EQ_FMTm("refused without being judged", FIRC_ERR_AGAIN,
                   firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir, "admin",
                                               "wrongpw", token, sizeof(token)),
                   "%d");
    ASSERT_EQ_FMT(FIRC_ERR_AGAIN,
                  firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir, "admin",
                                              "hunter2", token, sizeof(token)),
                  "%d");

    struct timespec pause = {.tv_sec = 1, .tv_nsec = 100 * 1000 * 1000};
    nanosleep(&pause, NULL);
    ASSERT_EQ_FMTm("the window expires by itself", FIRC_OK,
                   firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir, "admin",
                                               "hunter2", token, sizeof(token)),
                   "%d");
    for (int i = 0; i < 2; i++) {
        ASSERT_EQ_FMTm("a success starts the count over", FIRC_ERR_INVAL,
                       firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir,
                                                   "admin", "wrongpw", token, sizeof(token)),
                       "%d");
    }

    firc_auth_reset_throttle_for_test();
    unlink(SHADOW_FIXTURE);
    free(state_dir);
    PASS();
}

/* Catches: a hash cache that outlives a password change, or never answers. */
TEST what_the_cache_cannot_hold_it_does_not_answer_for(void) {
    firc_auth_forget_cached_hash();
    char huge_name[200];
    memset(huge_name, 'n', sizeof(huge_name) - 1);
    huge_name[sizeof(huge_name) - 1] = '\0';
    char huge_hash[200];
    memset(huge_hash, 'h', sizeof(huge_hash) - 1);
    huge_hash[sizeof(huge_hash) - 1] = '\0';

    char body[600];
    snprintf(body, sizeof(body),
             "%s:$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/:1:1::/root:/bin/sh\n"
             "fat:%s:1:1::/root:/bin/sh\n"
             "admin:$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/:1:1::/root:/bin/sh\n",
             huge_name, huge_hash);
    write_file(SHADOW_FIXTURE, body);

    char out[128];
    for (int i = 0; i < 2; i++) {
        ASSERT_EQ_FMTm("an account the cache cannot hold is still found", FIRC_OK,
                       firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, huge_name,
                                                         out, sizeof(out)),
                       "%d");
        ASSERT_EQ_FMTm("a hash too long to keep is a hash too long, not a missing account",
                       FIRC_ERR_LIMIT,
                       firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "fat", out,
                                                         sizeof(out)),
                       "%d");
        ASSERT_EQ_FMTm("and the ordinary account either way", FIRC_OK,
                       firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin",
                                                         out, sizeof(out)),
                       "%d");
    }

    firc_auth_forget_cached_hash();
    unlink(SHADOW_FIXTURE);
    PASS();
}

TEST a_login_name_cannot_write_its_own_log_line(void) {
    unlink(SHADOW_FIXTURE);
    unlink(PASSWD_FIXTURE);
    firc_auth_forget_cached_hash();
    firc_auth_reset_throttle_for_test();
    firc_event_reset_for_test();
    firc_log_set_level(FIRC_LOG_WARN);
    char *state_dir = mkdtemp_dup("/tmp/firc_auth_forge_XXXXXX");
    ASSERT(state_dir != NULL);

    char token[FIRC_JWT_MAX_TOKEN];
    (void)firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir,
                                      "root\n2026-01-01T00:00:00Z INF all is well", "x", token,
                                      sizeof(token));

    firc_event_t kept[16];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, kept, 16, &next, &dropped);
    ASSERTm("the refusal was logged", n >= 1);
    bool named = false;
    for (size_t i = 0; i < n; i++) {
        ASSERT_FALSEm("no line carries a line ending of the caller's",
                      strchr(kept[i].u.log.text, '\n') != NULL);
        ASSERT_FALSEm("and nothing the caller wrote begins a line of its own",
                      strncmp(kept[i].u.log.text, "2026-01-01", 10) == 0);
        if (strstr(kept[i].u.log.text, "root?") != NULL) { named = true; }
    }
    ASSERTm("the name is still recognisable in it", named);

    firc_event_reset_for_test();
    firc_auth_reset_throttle_for_test();
    free(state_dir);
    PASS();
}

TEST the_password_file_is_read_once_per_change(void) {
    static const char *const before =
        "admin:$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
        "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/:19000:0:99999:7:::\n";
    static const char *const after =
        "admin:$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
        "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfX/:19000:0:99999:7:::\n";
    firc_auth_forget_cached_hash();
    write_file(SHADOW_FIXTURE, before);

    char first[128];
    ASSERT_EQ(FIRC_OK, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin",
                                                         first, sizeof(first)));
    struct stat st;
    ASSERT_EQ(0, stat(SHADOW_FIXTURE, &st));

    write_file(SHADOW_FIXTURE, after);
    struct timespec times[2] = {st.st_atim, st.st_mtim};
    ASSERT_EQ(0, utimensat(AT_FDCWD, SHADOW_FIXTURE, times, 0));

    char second[128];
    ASSERT_EQ(FIRC_OK, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin",
                                                         second, sizeof(second)));
    ASSERT_STR_EQm("the file was not read again: this is the cache answering", first, second);

    struct timespec moved[2] = {st.st_atim, {st.st_mtim.tv_sec + 1, st.st_mtim.tv_nsec}};
    ASSERT_EQ(0, utimensat(AT_FDCWD, SHADOW_FIXTURE, moved, 0));
    char third[128];
    ASSERT_EQ(FIRC_OK, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin",
                                                         third, sizeof(third)));
    ASSERT_FALSEm("and the new hash is what comes back", strcmp(first, third) == 0);

    firc_auth_forget_cached_hash();
    unlink(SHADOW_FIXTURE);
    PASS();
}

TEST an_edited_password_file_is_noticed(void) {
    write_file(SHADOW_FIXTURE,
              "admin:$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
              "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/:19000:0:99999:7:::\n");
    firc_auth_forget_cached_hash();
    char hash[128];
    ASSERT_EQ(FIRC_OK, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin",
                                                         hash, sizeof(hash)));
    ASSERTm("the hash came back", strncmp(hash, "$6$", 3) == 0);

    char again[128];
    ASSERT_EQ(FIRC_OK, firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin",
                                                         again, sizeof(again)));
    ASSERT_STR_EQ(hash, again);

    write_file(SHADOW_FIXTURE, "someoneelse:$6$xx$yy:19000:0:99999:7:::\n");
    ASSERT_EQ_FMTm("the edit is seen", FIRC_ERR_NOENT,
                   firc_auth_load_password_hash_from(SHADOW_FIXTURE, PASSWD_FIXTURE, "admin", again,
                                                     sizeof(again)),
                   "%d");

    firc_auth_forget_cached_hash();
    unlink(SHADOW_FIXTURE);
    PASS();
}

TEST verify_rejects_token_for_unknown_user(void) {
    write_file(SHADOW_FIXTURE,
              "admin:$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
              "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/:19000:0:99999:7:::\n");
    char *state_dir = mkdtemp_dup("/tmp/firc_auth_state_XXXXXX");
    ASSERT(state_dir != NULL);

    char token[FIRC_JWT_MAX_TOKEN];
    ASSERT_EQ(FIRC_OK, firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir, "admin",
                                               "hunter2", token, sizeof(token)));

    unlink(SHADOW_FIXTURE);
    write_file(SHADOW_FIXTURE, "someoneelse:$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/:19000:0:99999:7:::\n");
    ASSERT_EQ(FIRC_ERR_INVAL,
             firc_auth_verify_token_from(SHADOW_FIXTURE, PASSWD_FIXTURE, state_dir, token));

    unlink(SHADOW_FIXTURE);
    free(state_dir);
    PASS();
}

typedef struct auth_test_state {
    char state_dir[256];
} auth_test_state_t;

static const char *test_auth_state_dir(void *ud) {
    return ((auth_test_state_t *)ud)->state_dir;
}

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *tcp;
    pthread_t thread;
    auth_test_state_t state;
    firc_auth_ctx_t ctx;
} harness_t;

static void *loop_thread(void *ud) {
    harness_t *h = ud;
    firc_loop_run(h->loop);
    return NULL;
}

/* One port per test binary, never reused: 18087 is test_settings_api.c's. */
#define AUTH_TEST_PORT 18086

static const char *g_shadow_path;
static const char *g_passwd_path;

static harness_t *harness_start(void) {
    harness_t *h = calloc(1, sizeof(*h));
    char *dir = mkdtemp_dup("/tmp/firc_auth_http_XXXXXX");
    snprintf(h->state.state_dir, sizeof(h->state.state_dir), "%s", dir);
    free(dir);
    h->ctx.state_dir = test_auth_state_dir;
    h->ctx.ud = &h->state;
    h->ctx.shadow_path = g_shadow_path;
    h->ctx.passwd_path = g_passwd_path;

    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
    if (firc_httpd_create(h->loop, &h->tcp) != FIRC_OK) { return NULL; }
    firc_httpd_route(h->tcp, "GET", "/api/v1/auth", firc_auth_status_handler, &h->ctx);
    firc_httpd_route(h->tcp, "POST", "/api/v1/auth", firc_auth_login_handler, &h->ctx);
    firc_httpd_set_middleware(h->tcp, firc_auth_middleware, &h->ctx);
    if (firc_httpd_listen_tcp(h->tcp, "127.0.0.1", AUTH_TEST_PORT) != FIRC_OK) { return NULL; }

    pthread_create(&h->thread, NULL, loop_thread, h);
    return h;
}

static void harness_stop(harness_t *h) {
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->tcp);
    firc_loop_destroy(h->loop);
    free(h);
}

static int connect_tcp(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    for (int i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { return fd; }
        struct timespec ts = {0, 10000000};
        nanosleep(&ts, NULL);
    }
    close(fd);
    return -1;
}

static ssize_t recv_response(int fd, char *buf, size_t cap) {
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t total = 0;
    char *body_start = NULL;
    long content_length = -1;
    for (;;) {
        if (total >= cap - 1) { break; }
        ssize_t n = recv(fd, buf + total, cap - 1 - total, 0);
        if (n <= 0) { break; }
        total += (size_t)n;
        buf[total] = '\0';
        if (!body_start) {
            char *marker = strstr(buf, "\r\n\r\n");
            if (marker) {
                body_start = marker + 4;
                char *cl = strstr(buf, "Content-Length:");
                if (cl && cl < marker) { content_length = strtol(cl + 15, NULL, 10); }
            }
        }
        if (body_start && content_length >= 0) {
            size_t body_have = (size_t)(buf + total - body_start);
            if ((long)body_have >= content_length) { break; }
        }
    }
    return (ssize_t)total;
}

static int status_code_of(const char *resp) {
    int code = 0;
    sscanf(resp, "HTTP/1.1 %d", &code);
    return code;
}
static const char *body_of(const char *resp) {
    const char *marker = strstr(resp, "\r\n\r\n");
    return marker ? marker + 4 : "";
}

TEST status_endpoint_reflects_enabled_flag(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(AUTH_TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /api/v1/auth HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    send(fd, req, strlen(req), 0);
    char resp[2048];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));
    ASSERT_STR_EQ("{\"enabled\":true}", body_of(resp));
    close(fd);
    harness_stop(h);
    PASS();
}

/* Catches: a login for an unknown user answered other than 403. */
TEST login_with_no_such_user_is_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(AUTH_TEST_PORT);
    ASSERT(fd >= 0);
    const char *body = "{\"login\":\"nosuchuser\",\"password\":\"x\"}";
    char req[512];
    snprintf(req, sizeof(req),
            "POST /api/v1/auth HTTP/1.1\r\nHost: x\r\nContent-Length: %zu\r\n"
            "Connection: close\r\n\r\n%s",
            strlen(body), body);
    send(fd, req, strlen(req), 0);
    char resp[2048];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(403, status_code_of(resp));
    close(fd);
    harness_stop(h);
    PASS();
}

static void unreachable_handler(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write_error(res, 500, "should never be called");
}

TEST protected_route_requires_bearer_token(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_httpd_route(h->tcp, "GET", "/api/v1/groups", unreachable_handler, NULL);

    int fd = connect_tcp(AUTH_TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /api/v1/groups HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    send(fd, req, strlen(req), 0);
    char resp[2048];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(401, status_code_of(resp));
    close(fd);
    harness_stop(h);
    PASS();
}

/* One request, with or without a bearer token; returns the status and copies the body into `body`. */
static int get_hosts(const char *token, char *body, size_t cap) {
    int fd = connect_tcp(AUTH_TEST_PORT);
    if (fd < 0) { return -1; }
    char req[1024];
    if (token != NULL) {
        snprintf(req, sizeof(req),
                 "GET /api/v1/system/hosts HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Connection: close\r\n\r\n",
                 token);
    } else {
        snprintf(req, sizeof(req), "GET /api/v1/system/hosts HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    }
    send(fd, req, strlen(req), 0);
    char resp[4096];
    ssize_t n = recv_response(fd, resp, sizeof(resp));
    close(fd);
    if (n <= 0) { return -1; }
    snprintf(body, cap, "%s", body_of(resp));
    return status_code_of(resp);
}

/* Catches: the host list missing, exempt from auth, or answered without a token. */
TEST the_host_list_answers_a_signed_in_caller_and_nobody_else(void) {
    write_file(SHADOW_FIXTURE,
               "admin:$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
               "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/:19000:0:99999:7:::\n");
    firc_auth_forget_cached_hash();
    g_shadow_path = SHADOW_FIXTURE;
    g_passwd_path = PASSWD_FIXTURE;
    harness_t *h = harness_start();
    g_shadow_path = NULL;
    g_passwd_path = NULL;
    ASSERT(h != NULL);
    firc_system_ctx_t sys;
    memset(&sys, 0, sizeof(sys));
    firc_system_register_routes(h->tcp, &sys);

    firc_auth_forget_secret_for_test();
    firc_auth_reset_throttle_for_test();
    char token[FIRC_JWT_MAX_TOKEN];
    ASSERT_EQ(FIRC_OK, firc_auth_authenticate_from(SHADOW_FIXTURE, PASSWD_FIXTURE, h->state.state_dir, "admin",
                                                   "hunter2", token, sizeof(token)));

    char body[1024];
    ASSERT_EQm("signed in: the handler answers", 200, get_hosts(token, body, sizeof(body)));
    ASSERT_STR_EQ("{\"hosts\":[]}", body);
    ASSERT_EQm("no token: the middleware refuses", 401, get_hosts(NULL, body, sizeof(body)));
    harness_stop(h);
    unlink(SHADOW_FIXTURE);
    PASS();
}

TEST auth_path_itself_is_exempt_even_when_enabled(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(AUTH_TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /api/v1/auth HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    send(fd, req, strlen(req), 0);
    char resp[2048];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));
    close(fd);
    harness_stop(h);
    PASS();
}

TEST bare_lf_request_line_endings_are_accepted(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(AUTH_TEST_PORT);
    ASSERT(fd >= 0);
    const char *body = "{\"login\":\"admin\",\"password\":\"x\"}";
    char req[512];
    snprintf(req, sizeof(req),
            "POST /api/v1/auth HTTP/1.1\nHost:\nContent-Type: application/json\n"
            "Content-Length: %zu\n\n%s",
            strlen(body), body);
    send(fd, req, strlen(req), 0);
    char resp[2048];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(403, status_code_of(resp));
    close(fd);
    harness_stop(h);
    PASS();
}

/* Catches: the config directory's mode left to the inherited umask. */
TEST the_config_directory_is_not_left_to_the_umask(void) {
    char *parent = mkdtemp_dup("/tmp/firc_auth_umask_XXXXXX");
    ASSERT(parent != NULL);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/conf", parent);

    mode_t kept = umask(077);
    firc_auth_forget_secret_for_test();
    uint8_t secret[64];
    size_t n = 0;
    firc_err_t err = firc_auth_load_secret(dir, secret, &n);
    umask(kept);
    firc_auth_forget_secret_for_test();
    ASSERT_EQ_FMT(FIRC_OK, err, "%d");

    struct stat st;
    ASSERT_EQ(0, stat(dir, &st));
    ASSERT_EQ_FMTm("the mode the comment claims is the mode it gets", 0755u,
                   (unsigned)(st.st_mode & 07777), "%o");

    char sp[600];
    snprintf(sp, sizeof(sp), "%s/auth_secret", dir);
    ASSERT_EQ(0, stat(sp, &st));
    ASSERT_EQ_FMTm("and the secret in it is nobody else's", 0600u,
                   (unsigned)(st.st_mode & 07777), "%o");

    unlink(sp);
    rmdir(dir);
    rmdir(parent);
    free(parent);
    PASS();
}

TEST a_secret_file_longer_than_any_secret_is_refused(void) {
    char *dir = mkdtemp_dup("/tmp/firc_auth_long_XXXXXX");
    ASSERT(dir != NULL);
    char sp[600];
    snprintf(sp, sizeof(sp), "%s/auth_secret", dir);
    char text[256];
    memset(text, 'A', 255);
    text[255] = '\0';
    FILE *f = fopen(sp, "we");
    ASSERT(f != NULL);
    fputs(text, f);
    fclose(f);

    firc_auth_forget_secret_for_test();
    uint8_t secret[64];
    size_t n = 0;
    firc_err_t err = firc_auth_load_secret(dir, secret, &n);
    firc_auth_forget_secret_for_test();

    unlink(sp);
    rmdir(dir);
    free(dir);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, err, "%d");
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(add_years_matches_go);
    RUN_TEST(load_password_hash_cases);
    RUN_TEST(load_password_hash_falls_back_to_passwd);
    RUN_TEST(an_account_only_in_passwd_is_found_past_a_shadow_that_exists);
    RUN_TEST(authenticate_and_verify_round_trip);
    RUN_TEST(the_config_directory_is_not_left_to_the_umask);
    RUN_TEST(a_secret_file_longer_than_any_secret_is_refused);
    RUN_TEST(a_run_of_wrong_passwords_stops_costing_a_crypt);
    RUN_TEST(what_the_cache_cannot_hold_it_does_not_answer_for);
    RUN_TEST(a_login_name_cannot_write_its_own_log_line);
    RUN_TEST(the_password_file_is_read_once_per_change);
    RUN_TEST(an_edited_password_file_is_noticed);
    RUN_TEST(verify_rejects_token_for_unknown_user);
    RUN_TEST(status_endpoint_reflects_enabled_flag);
    RUN_TEST(login_with_no_such_user_is_refused);
    RUN_TEST(protected_route_requires_bearer_token);
    RUN_TEST(the_host_list_answers_a_signed_in_caller_and_nobody_else);
    RUN_TEST(auth_path_itself_is_exempt_even_when_enabled);
    RUN_TEST(bare_lf_request_line_endings_are_accepted);
    GREATEST_MAIN_END();
}
