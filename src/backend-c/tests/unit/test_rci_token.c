#include "greatest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "firc/keenetic_rci.h"
#include "firc/log.h"
#include "firc/rci_token.h"

#define TOK_A "1dz8KNQ3YSk74t3W2NtZfmWidUurH8i7XPyXIEOHsHRWmAIdoUWhmSdM"
#define TOK_B "kka0Hq7ZtR2mW9xLpV4nB6cD8eF1gJ3s5uY0aZ2bX4c6d8e3uC"
#define STALE "rRA7Pq2WmZ9xKcLvB4nT6yH8jD1fG3sQ5uE0aI2oU4rT6yxeA"

static const char GENERATE_OUT[] = "\x1b[K\n"
                                   "               id: 3\n"
                                   "            value:\n"
                                   "                   " TOK_A "\n"
                                   "\n"
                                   "Core::Security::Authenticator: Added a token for user \"admin\".\n"
                                   "\x1b[K";

static const char GENERATE_11_OUT[] = "\x1b[K\n               id: 11\n            value:\n"
                                      "                   " TOK_A "\n\x1b[K";

static const char SHOW_OUT[] = "\x1b[K\n"
                               "            token:\n"
                               "                   id: 2\n"
                               "          fingerprint: 27...1f\n"
                               "      truncated-value: kka...3uC\n"
                               "              service: Core::Security::Authenticator\n"
                               "                local: yes\n"
                               "                 user: admin\n"
                               "            user-data: firc\n"
                               "              expires: never\n"
                               "          last-access: 19\n"
                               "\n"
                               "            token:\n"
                               "                   id: 3\n"
                               "          fingerprint: 47...06\n"
                               "      truncated-value: 1dz...SdM\n"
                               "              service: Core::Security::Authenticator\n"
                               "                local: yes\n"
                               "                 user: admin\n"
                               "            user-data: xkeen\n"
                               "              expires: never\n"
                               "          last-access: never\n"
                               "\n"
                               "            token:\n"
                               "                   id: 11\n"
                               "          fingerprint: 6a...c4\n"
                               "      truncated-value: rRA...xeA\n"
                               "              service: Core::Security::Authenticator\n"
                               "                local: yes\n"
                               "                 user: admin\n"
                               "            user-data: firc\n"
                               "              expires: never\n"
                               "          last-access: never\n"
                               "\x1b[K";

/* Catches: a 5.01 router asked for tokens it lacks, or a 5.02 or 6.x router left without one. */
TEST only_5_02_and_later_get_a_token(void)
{
    ASSERT(firc_kn_token_release_ok("5.02.A.11.0-1"));
    ASSERT(firc_kn_token_release_ok("5.02.A.1.0-0"));
    ASSERT(firc_kn_token_release_ok("5.10.C.1.0-0"));
    ASSERT(firc_kn_token_release_ok("6.00.A.1.0-0"));
    ASSERT_FALSE(firc_kn_token_release_ok("5.01.C.6.0-1"));
    ASSERT_FALSE(firc_kn_token_release_ok("4.03.C.6.3-9"));
    ASSERT_FALSE(firc_kn_token_release_ok("5"));
    ASSERT_FALSE(firc_kn_token_release_ok("x.02.A"));
    ASSERT_FALSE(firc_kn_token_release_ok(""));
    ASSERT_FALSE(firc_kn_token_release_ok(NULL));
    PASS();
}

/* Catches: the value taken from the "value:" line itself, which the bench's ndmc leaves empty. */
TEST a_generated_token_is_read_from_the_bench_output(void)
{
    char id[16], tok[FIRC_KN_TOKEN_MAX];
    ASSERT(firc_kn_token_parse_generated(GENERATE_OUT, id, sizeof id, tok, sizeof tok));
    ASSERT_STR_EQ("3", id);
    ASSERT_STR_EQ(TOK_A, tok);
    PASS();
}

/* Catches: a value ndmc wrapped by the terminal width read as its first line only. */
TEST a_wrapped_value_is_joined(void)
{
    char id[16], tok[FIRC_KN_TOKEN_MAX];
    ASSERT(firc_kn_token_parse_generated("value: \n   1dz8KNQ3YSk74t3W2NtZfmWidUurH8i7\n   XPyXIEOHsHRWmAIdoUWhmSdM\n\n"
                                         "Core::X: y\n",
                                         id, sizeof id, tok, sizeof tok));
    ASSERT_STR_EQ("", id);
    ASSERT_STR_EQ(TOK_A, tok);
    PASS();
}

/* Catches: a missing, short or garbled value accepted and sent as a token that only earns a lockout strike. */
TEST a_value_that_is_no_token_is_refused(void)
{
    char id[16], tok[FIRC_KN_TOKEN_MAX];
    ASSERT_FALSE(firc_kn_token_parse_generated("id: 3\n", id, sizeof id, tok, sizeof tok));
    ASSERT_FALSE(firc_kn_token_parse_generated("value: \n   abc\n", id, sizeof id, tok, sizeof tok));
    ASSERT_FALSE(firc_kn_token_parse_generated("value: \n   abc def!ghi-jkl-mno-pqr-stu-vwx-yz0123456789\n", id,
                                               sizeof id, tok, sizeof tok));
    ASSERT_FALSE(firc_kn_token_parse_generated("", id, sizeof id, tok, sizeof tok));
    PASS();
}

/* Catches: another program's token (xkeen) deleted, or one of firc's missed. */
TEST only_firc_tokens_are_listed(void)
{
    char ids[8][16];
    ASSERT_EQ(2, firc_kn_token_ids(SHOW_OUT, "firc", ids, 8));
    ASSERT_STR_EQ("2", ids[0]);
    ASSERT_STR_EQ("11", ids[1]);
    ASSERT_EQ(1, firc_kn_token_ids(SHOW_OUT, "xkeen", ids, 8));
    ASSERT_STR_EQ("3", ids[0]);
    ASSERT_EQ(0, firc_kn_token_ids("", "firc", ids, 8));
    PASS();
}

/* Catches: any 403 taken for a dead token, which reissues on a refusal no token can fix. */
TEST only_a_token_refusal_is_one(void)
{
    ASSERT(firc_kn_token_refusal(403, "0x2312, not identified"));
    ASSERT(firc_kn_token_refusal(401, "0x1218, token required"));
    ASSERT_FALSE(firc_kn_token_refusal(403, "0x0001, forbidden"));
    ASSERT_FALSE(firc_kn_token_refusal(500, "0x2312"));
    ASSERT_FALSE(firc_kn_token_refusal(403, NULL));
    PASS();
}

typedef struct {
    int fd;
    int port;
    int expect;
    int served;
    int switch_at;
    char good[FIRC_KN_TOKEN_MAX];
    char good2[FIRC_KN_TOKEN_MAX];
    char detail[64];
    char req[8][4096];
} rci_stub_t;

static size_t read_request(int c, char *buf, size_t cap)
{
    size_t len = 0;
    for (;;) {
        ssize_t n = recv(c, buf + len, cap - 1 - len, 0);
        if (n < 0 && errno == EINTR) { continue; }
        if (n <= 0) { break; }
        len += (size_t)n;
        buf[len] = '\0';
        char *end = strstr(buf, "\r\n\r\n");
        if (end == NULL) { continue; }
        const char *cl = strstr(buf, "Content-Length: ");
        size_t want = (size_t)(end + 4 - buf) + (cl != NULL && cl < end ? (size_t)atol(cl + 16) : 0);
        if (len >= want) { break; }
    }
    buf[len] = '\0';
    return len;
}

static void *stub_serve(void *ud)
{
    rci_stub_t *s = ud;
    while (s->served < s->expect) {
        int c = accept(s->fd, NULL, NULL);
        if (c < 0 && errno == EINTR) { continue; }
        if (c < 0) { break; }
        char *req = s->req[s->served < 8 ? s->served : 7];
        read_request(c, req, sizeof s->req[0]);
        const char *good = s->switch_at > 0 && s->served >= s->switch_at ? s->good2 : s->good;
        char want[FIRC_KN_TOKEN_MAX + 32];
        snprintf(want, sizeof want, "X-NDMA-TKN: %s\r\n", good);
        char reply[512];
        if (good[0] == '\0' || strstr(req, want) != NULL) {
            snprintf(reply, sizeof reply,
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n"
                     "Connection: close\r\n\r\n{}");
        } else {
            snprintf(reply, sizeof reply,
                     "HTTP/1.1 403 Forbidden\r\nX-Detail: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                     s->detail);
        }
        ssize_t sent = send(c, reply, strlen(reply), MSG_NOSIGNAL);
        (void)sent;
        close(c);
        s->served++;
    }
    return NULL;
}

static bool stub_listen(rci_stub_t *s)
{
    s->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof a;
    struct timeval tv = {.tv_sec = 3};
    if (s->fd < 0 || setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0 || bind(s->fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(s->fd, 8) != 0 ||
        getsockname(s->fd, (struct sockaddr *)&a, &len) != 0) {
        return false;
    }
    s->port = ntohs(a.sin_port);
    return true;
}

typedef struct {
    char dir[64];
    char ndmc[96];
    char token[96];
    char calls[96];
} bench_t;

static bool write_text(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) { return false; }
    bool ok = fputs(text, f) >= 0;
    ok = fclose(f) == 0 && ok;
    return ok && chmod(path, mode) == 0;
}

static bool bench_make(bench_t *b, const char *generate_out)
{
    snprintf(b->dir, sizeof b->dir, "/tmp/firc_tkn_XXXXXX");
    if (mkdtemp(b->dir) == NULL) { return false; }
    snprintf(b->ndmc, sizeof b->ndmc, "%s/ndmc", b->dir);
    snprintf(b->token, sizeof b->token, "%s/lib/rci-token", b->dir);
    snprintf(b->calls, sizeof b->calls, "%s/calls", b->dir);
    char path[128], script[2560];
    snprintf(path, sizeof path, "%s/generate", b->dir);
    if (!write_text(path, generate_out, 0600)) { return false; }
    snprintf(path, sizeof path, "%s/show", b->dir);
    if (!write_text(path, SHOW_OUT, 0600)) { return false; }
    snprintf(script, sizeof script,
             "#!/bin/sh\n"
             "[ \"$1\" = -c ] || exit 2\n"
             "echo \"$2\" >> %s/calls\n"
             "[ ! -e %s/old ] || { echo 'no such command'; exit 127; }\n"
             "[ ! -e %s/firmware-libs ] || [ \"$LD_LIBRARY_PATH\" = /lib:/usr/lib ] || { echo 'ndmc: initialization failure.' >&2; exit 1; }\n"
             "case \"$2\" in\n"
             "  'authentication token generate firc') [ ! -e %s/slow-generate ] || { echo $$ > %s/pid; exec sleep 30; }; [ ! -e %s/fail-generate ] || { printf '\\033[K\\n\\nCore::Security: user \"admin\" not found.\\n' >&2; exit 1; }; if [ -e %s/noisy-generate ]; then head -n 3 %s/generate; printf 'Core::Note: a note.\\n' >&2; tail -n +4 %s/generate; else cat %s/generate; fi ;;\n"
             "  'show authentication token') cat %s/show ;;\n"
             "  'authentication token delete '*) [ ! -e %s/fail-delete ] || exit 1 ;;\n"
             "  *) echo 'no such command'; exit 127 ;;\n"
             "esac\n",
             b->dir, b->dir, b->dir, b->dir, b->dir, b->dir, b->dir, b->dir, b->dir, b->dir, b->dir, b->dir);
    return write_text(b->ndmc, script, 0700);
}

static void slurp(const char *path, char *out, size_t cap)
{
    out[0] = '\0';
    FILE *f = fopen(path, "r");
    if (f == NULL) { return; }
    size_t n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    fclose(f);
}

static void bench_drop(bench_t *b)
{
    char cmd[160];
    snprintf(cmd, sizeof cmd, "rm -rf %s", b->dir);
    int rc = system(cmd);
    (void)rc;
    firc_kn_token_setup("", "");
}

static bool bench_flag(bench_t *b, const char *name)
{
    char path[128];
    snprintf(path, sizeof path, "%s/%s", b->dir, name);
    return write_text(path, "", 0600);
}

static bool bench_keep(bench_t *b, const char *tok)
{
    char lib[96], line[FIRC_KN_TOKEN_MAX + 2];
    snprintf(lib, sizeof lib, "%s/lib", b->dir);
    snprintf(line, sizeof line, "%s\n", tok);
    return mkdir(lib, 0700) == 0 && write_text(b->token, line, 0600);
}

static firc_err_t get_from(rci_stub_t *s, const char *path)
{
    char base[64];
    snprintf(base, sizeof base, "http://127.0.0.1:%d", s->port);
    char *body = NULL;
    firc_err_t err = firc_kn_rci_get(base, path, &body);
    free(body);
    return err;
}

static bool has_token_header(const char *req, const char *tok)
{
    char want[FIRC_KN_TOKEN_MAX + 32];
    snprintf(want, sizeof want, "X-NDMA-TKN: %s\r\n", tok);
    return strstr(req, want) != NULL;
}

/* Catches: a token header sent, or ndmc run, on a firmware older than 5.02. */
TEST below_5_02_requests_go_without_a_token(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.01.C.6.0-1");
    rci_stub_t s = {.expect = 1};
    ASSERT(stub_listen(&s));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, stub_serve, &s));
    firc_err_t err = get_from(&s, "/rci/show/version");
    pthread_join(th, NULL);
    close(s.fd);
    char calls[1024];
    slurp(b.calls, calls, sizeof calls);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT(strstr(s.req[0], "X-NDMA-TKN") == NULL);
    ASSERT_STR_EQ("", calls);
    bench_drop(&b);
    PASS();
}

/* Catches: no token issued on 5.02, the file not kept 0600, the old firc token left behind, or xkeen's deleted. */
TEST the_first_request_on_5_02_issues_and_keeps_a_token(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_11_OUT));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    rci_stub_t s = {.expect = 1};
    snprintf(s.good, sizeof s.good, "%s", TOK_A);
    snprintf(s.detail, sizeof s.detail, "0x1218, token required");
    ASSERT(stub_listen(&s));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, stub_serve, &s));
    firc_err_t err = get_from(&s, "/rci/show/version");
    pthread_join(th, NULL);
    close(s.fd);
    char calls[1024], kept[256];
    slurp(b.calls, calls, sizeof calls);
    slurp(b.token, kept, sizeof kept);
    struct stat st;
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_STR_EQ("authentication token generate firc\n"
                  "show authentication token\n"
                  "authentication token delete 2\n",
                  calls);
    ASSERT_STR_EQ(TOK_A "\n", kept);
    ASSERT_EQ(0, stat(b.token, &st));
    ASSERT_EQ(0600, st.st_mode & 0777);
    bench_drop(&b);
    PASS();
}

/* Catches: a token issued at every start although the file holds a working one. */
TEST a_kept_token_is_sent_without_asking_ndmc(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    char lib[96];
    snprintf(lib, sizeof lib, "%s/lib", b.dir);
    ASSERT_EQ(0, mkdir(lib, 0700));
    ASSERT(write_text(b.token, TOK_B "\n", 0600));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    rci_stub_t s = {.expect = 2};
    snprintf(s.good, sizeof s.good, "%s", TOK_B);
    snprintf(s.detail, sizeof s.detail, "0x2312, not identified");
    ASSERT(stub_listen(&s));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, stub_serve, &s));
    firc_err_t e1 = get_from(&s, "/rci/show/version");
    firc_err_t e2 = get_from(&s, "/rci/show/interface");
    pthread_join(th, NULL);
    close(s.fd);
    char calls[1024];
    slurp(b.calls, calls, sizeof calls);
    ASSERT_EQ(FIRC_OK, e1);
    ASSERT_EQ(FIRC_OK, e2);
    ASSERT_STR_EQ("", calls);
    bench_drop(&b);
    PASS();
}

/* Catches: a restart sending its first requests tokenless until the identity round has read the release. */
TEST a_kept_token_is_sent_before_the_release_is_known(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_keep(&b, TOK_B));
    firc_kn_token_setup(b.token, b.ndmc);
    char tok[FIRC_KN_TOKEN_MAX], calls[1024];
    firc_kn_token_current(tok, NULL);
    slurp(b.calls, calls, sizeof calls);
    ASSERT_STR_EQ(TOK_B, tok);
    ASSERT_STR_EQ("", calls);
    bench_drop(&b);
    PASS();
}

/* Catches: a refused batch POST not repeated, repeated with the dead token, or repeated without its body. */
TEST a_refused_token_is_replaced_and_the_post_repeated(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    char lib[96];
    snprintf(lib, sizeof lib, "%s/lib", b.dir);
    ASSERT_EQ(0, mkdir(lib, 0700));
    ASSERT(write_text(b.token, STALE "\n", 0600));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    rci_stub_t s = {.expect = 3, .switch_at = 1};
    snprintf(s.good, sizeof s.good, "%s", STALE);
    snprintf(s.good2, sizeof s.good2, "%s", TOK_A);
    snprintf(s.detail, sizeof s.detail, "0x2312, not identified");
    ASSERT(stub_listen(&s));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, stub_serve, &s));
    char base[64];
    snprintf(base, sizeof base, "http://127.0.0.1:%d", s.port);
    char *body = NULL;
    firc_err_t first = firc_kn_rci_get(base, "/rci/show/version", &body);
    free(body);
    firc_err_t err = firc_kn_rci_post(base, "/rci/", "[{\"show\":{\"version\":{}}}]", &body);
    free(body);
    pthread_join(th, NULL);
    close(s.fd);
    ASSERT_EQ(FIRC_OK, first);
    char kept[256];
    slurp(b.token, kept, sizeof kept);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT(has_token_header(s.req[1], STALE));
    ASSERT(has_token_header(s.req[2], TOK_A));
    ASSERT(strstr(s.req[2], "\r\n\r\n[{\"show\":{\"version\":{}}}]") != NULL);
    ASSERT_STR_EQ(TOK_A "\n", kept);
    bench_drop(&b);
    PASS();
}

/* Catches: a token reissued on every refusal, a lockout strike and an admin token per request. */
TEST a_second_refusal_within_the_minute_issues_nothing(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    char lib[96];
    snprintf(lib, sizeof lib, "%s/lib", b.dir);
    ASSERT_EQ(0, mkdir(lib, 0700));
    ASSERT(write_text(b.token, STALE "\n", 0600));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    rci_stub_t s = {.expect = 5};
    snprintf(s.good, sizeof s.good, "%s", TOK_B);
    snprintf(s.detail, sizeof s.detail, "0x2312, not identified");
    ASSERT(stub_listen(&s));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, stub_serve, &s));
    firc_err_t e1 = get_from(&s, "/rci/show/version");
    firc_err_t e2 = get_from(&s, "/rci/show/version");
    firc_err_t e3 = get_from(&s, "/rci/show/version");
    pthread_join(th, NULL);
    close(s.fd);
    char calls[1024];
    slurp(b.calls, calls, sizeof calls);
    ASSERT_EQ(FIRC_ERR_UPSTREAM, e1);
    ASSERT_EQ(FIRC_ERR_UPSTREAM, e2);
    ASSERT_EQ(FIRC_ERR_UPSTREAM, e3);
    ASSERT(has_token_header(s.req[0], STALE));
    ASSERT(has_token_header(s.req[1], TOK_A));
    ASSERT(has_token_header(s.req[2], TOK_A));
    ASSERT(strstr(s.req[3], "X-NDMA-TKN") == NULL);
    ASSERT(strstr(s.req[4], "X-NDMA-TKN") == NULL);
    ASSERT_STR_EQ("authentication token generate firc\n"
                  "show authentication token\n"
                  "authentication token delete 2\n"
                  "authentication token delete 11\n",
                  calls);
    bench_drop(&b);
    PASS();
}

/* Catches: a firmware that already refuses tokenless RCI never getting a token, since show version is refused too. */
TEST a_token_refusal_turns_the_token_on_before_the_release_is_known(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    firc_kn_token_setup(b.token, b.ndmc);
    rci_stub_t s = {.expect = 3};
    snprintf(s.good, sizeof s.good, "%s", TOK_A);
    snprintf(s.detail, sizeof s.detail, "0x1218, token required");
    ASSERT(stub_listen(&s));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, stub_serve, &s));
    firc_err_t err = get_from(&s, "/rci/show/version");
    firc_kn_token_set_release("");
    firc_err_t later = get_from(&s, "/rci/show/version");
    pthread_join(th, NULL);
    close(s.fd);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT(strstr(s.req[0], "X-NDMA-TKN") == NULL);
    ASSERT(has_token_header(s.req[1], TOK_A));
    ASSERT_EQ(FIRC_OK, later);
    ASSERT(has_token_header(s.req[2], TOK_A));
    bench_drop(&b);
    PASS();
}

/* Catches: a 403 that names no token taken as a reason to issue one. */
TEST another_refusal_issues_nothing(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    char lib[96];
    snprintf(lib, sizeof lib, "%s/lib", b.dir);
    ASSERT_EQ(0, mkdir(lib, 0700));
    ASSERT(write_text(b.token, STALE "\n", 0600));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    rci_stub_t s = {.expect = 1};
    snprintf(s.good, sizeof s.good, "%s", TOK_B);
    snprintf(s.detail, sizeof s.detail, "0x0001, forbidden");
    ASSERT(stub_listen(&s));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, stub_serve, &s));
    firc_err_t err = get_from(&s, "/rci/show/version");
    pthread_join(th, NULL);
    close(s.fd);
    char calls[1024];
    slurp(b.calls, calls, sizeof calls);
    ASSERT_EQ(FIRC_ERR_UPSTREAM, err);
    ASSERT_EQ(1, s.served);
    ASSERT_STR_EQ("", calls);
    bench_drop(&b);
    PASS();
}

/* Catches: an unreadable generate leaving a fresh admin token on the router, or sending garbage as a token. */
TEST an_unreadable_issue_deletes_the_new_token_too(void)
{
    bench_t b;
    ASSERT(bench_make(&b, "\x1b[K\n               id: 11\n            value:\n                   short\n"));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    rci_stub_t s = {.expect = 1};
    ASSERT(stub_listen(&s));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, stub_serve, &s));
    firc_err_t err = get_from(&s, "/rci/show/version");
    pthread_join(th, NULL);
    close(s.fd);
    char calls[1024];
    slurp(b.calls, calls, sizeof calls);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT(strstr(s.req[0], "X-NDMA-TKN") == NULL);
    ASSERT_STR_EQ("authentication token generate firc\n"
                  "show authentication token\n"
                  "authentication token delete 2\n"
                  "authentication token delete 11\n",
                  calls);
    ASSERT_EQ(-1, access(b.token, F_OK));
    bench_drop(&b);
    PASS();
}

/* Catches: purge leaving firc's admin tokens on the router, deleting xkeen's, or keeping the file. */
TEST revoke_deletes_firc_tokens_then_the_file(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    char lib[96];
    snprintf(lib, sizeof lib, "%s/lib", b.dir);
    ASSERT_EQ(0, mkdir(lib, 0700));
    ASSERT(write_text(b.token, TOK_A "\n", 0600));
    ASSERT_EQ(FIRC_OK, firc_kn_token_revoke(b.token, b.ndmc, "5.01.C.6.0-1"));
    char calls[1024];
    slurp(b.calls, calls, sizeof calls);
    ASSERT_STR_EQ("show authentication token\n"
                  "authentication token delete 2\n"
                  "authentication token delete 11\n",
                  calls);
    ASSERT_EQ(-1, access(b.token, F_OK));
    bench_drop(&b);
    PASS();
}

/* Catches: purge asking ndmc on a router that never had a token, an E line on a pre-5.02 firmware. */
TEST revoke_without_a_file_on_an_old_firmware_asks_nothing(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT_EQ(FIRC_OK, firc_kn_token_revoke(b.token, b.ndmc, "5.01.C.6.0-1"));
    char calls[1024];
    slurp(b.calls, calls, sizeof calls);
    ASSERT_STR_EQ("", calls);
    bench_drop(&b);
    PASS();
}

/* Catches: a refusal of a token another thread already replaced throwing the fresh one away and issuing again. */
TEST a_refusal_of_a_replaced_token_gives_the_current_one(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_keep(&b, TOK_B));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    char tok[FIRC_KN_TOKEN_MAX], fresh[FIRC_KN_TOKEN_MAX], calls[1024];
    firc_kn_token_current(tok, NULL);
    firc_kn_token_refused(STALE, fresh, NULL);
    slurp(b.calls, calls, sizeof calls);
    ASSERT_STR_EQ(TOK_B, tok);
    ASSERT_STR_EQ(TOK_B, fresh);
    ASSERT_STR_EQ("", calls);
    bench_drop(&b);
    PASS();
}

/* Catches: a token whose file was not written left on the router, where no purge could find it. */
TEST a_token_that_cannot_be_kept_is_deleted_again(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_11_OUT));
    char path[128];
    snprintf(path, sizeof path, "%s/generate/rci-token", b.dir);
    firc_kn_token_setup(path, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    char tok[FIRC_KN_TOKEN_MAX], calls[1024];
    firc_kn_token_current(tok, NULL);
    slurp(b.calls, calls, sizeof calls);
    ASSERT_STR_EQ("", tok);
    ASSERT_STR_EQ("authentication token generate firc\n"
                  "show authentication token\n"
                  "authentication token delete 2\n"
                  "authentication token delete 11\n",
                  calls);
    bench_drop(&b);
    PASS();
}

/* Catches: a generate that ndmc reports as failed taken as a token. */
TEST a_failed_generate_gives_no_token(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_flag(&b, "fail-generate"));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    char tok[FIRC_KN_TOKEN_MAX];
    firc_kn_token_current(tok, NULL);
    ASSERT_STR_EQ("", tok);
    ASSERT_EQ(-1, access(b.token, F_OK));
    bench_drop(&b);
    PASS();
}

/* Catches: the warning for a failed ndmc call leaving out what ndmc answered on stderr. */
TEST a_failed_generate_says_what_ndmc_answered(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_flag(&b, "fail-generate"));
    int lp[2];
    ASSERT_EQ(0, pipe(lp));
    firc_log_set_fd(lp[1]);
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    char tok[FIRC_KN_TOKEN_MAX];
    firc_kn_token_current(tok, NULL);
    firc_log_set_fd(STDOUT_FILENO);
    close(lp[1]);
    char log[4096];
    ssize_t n = read(lp[0], log, sizeof log - 1);
    close(lp[0]);
    log[n > 0 ? n : 0] = '\0';
    ASSERT(strstr(log, "rci token: ndmc \"authentication token generate firc\" failed (exit 1): "
                      "Core::Security: user \"admin\" not found.\n") != NULL);
    bench_drop(&b);
    PASS();
}

/* Catches: ndmc run with the daemon's Entware library path, which it cannot start with. */
TEST ndmc_runs_on_the_firmware_libraries(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_flag(&b, "firmware-libs"));
    ASSERT_EQ(0, setenv("LD_LIBRARY_PATH", "/opt/lib:/opt/usr/lib", 1));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    char tok[FIRC_KN_TOKEN_MAX];
    firc_kn_token_current(tok, NULL);
    unsetenv("LD_LIBRARY_PATH");
    ASSERT_STR_EQ(TOK_A, tok);
    bench_drop(&b);
    PASS();
}

/* Catches: ndmc's stderr read as part of its stdout, so a note amid the token cuts it short. */
TEST a_note_on_stderr_amid_the_token_keeps_it(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_flag(&b, "noisy-generate"));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    char tok[FIRC_KN_TOKEN_MAX];
    firc_kn_token_current(tok, NULL);
    ASSERT_STR_EQ(TOK_A, tok);
    bench_drop(&b);
    PASS();
}

/* Catches: the file deleted although the router kept the token, so nothing knows of it any more. */
TEST a_failed_revoke_keeps_the_file(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_keep(&b, TOK_A));
    ASSERT(bench_flag(&b, "fail-delete"));
    ASSERT_EQ(FIRC_ERR_UPSTREAM, firc_kn_token_revoke(b.token, b.ndmc, "5.02.A.11.0-1"));
    ASSERT_EQ(0, access(b.token, F_OK));
    bench_drop(&b);
    PASS();
}

/* Catches: a firmware without token commands turning a purge into a failure, or keeping the file. */
TEST revoke_on_a_router_without_token_commands_drops_the_file(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_keep(&b, TOK_A));
    ASSERT(bench_flag(&b, "old"));
    ASSERT_EQ(FIRC_OK, firc_kn_token_revoke(b.token, b.ndmc, ""));
    ASSERT_EQ(-1, access(b.token, F_OK));
    bench_drop(&b);
    PASS();
}

/* Catches: a token whose file is gone left on the router when the release is unknown or 5.02+. */
TEST revoke_without_a_file_asks_unless_the_firmware_is_known_old(void)
{
    const char *releases[] = {"", "5.02.A.11.0-1"};
    for (size_t i = 0; i < 2; i++) {
        bench_t b;
        ASSERT(bench_make(&b, GENERATE_OUT));
        ASSERT_EQ(FIRC_OK, firc_kn_token_revoke(b.token, b.ndmc, releases[i]));
        char calls[1024];
        slurp(b.calls, calls, sizeof calls);
        ASSERT_STR_EQ("show authentication token\n"
                      "authentication token delete 2\n"
                      "authentication token delete 11\n",
                      calls);
        bench_drop(&b);
    }
    PASS();
}

static void *raise_later(void *ud)
{
    struct timespec ts = {0, 200 * 1000000L};
    nanosleep(&ts, NULL);
    atomic_store((atomic_bool *)ud, true);
    return NULL;
}

static long ms_since(const struct timespec *a)
{
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    return (long)((b.tv_sec - a->tv_sec) * 1000 + (b.tv_nsec - a->tv_nsec) / 1000000);
}

static pid_t read_pid(bench_t *b)
{
    char path[128], text[32];
    snprintf(path, sizeof path, "%s/pid", b->dir);
    for (int i = 0; i < 2000; i++) {
        slurp(path, text, sizeof text);
        if (text[0] != '\0') { return (pid_t)atol(text); }
        struct timespec ts = {0, 1000000L};
        nanosleep(&ts, NULL);
    }
    return 0;
}

/* catches: a token issue not aborted, so a stop waits for ndmc */
TEST a_stop_during_a_token_issue_returns_within_a_second(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_flag(&b, "slow-generate"));
    firc_kn_token_setup(b.token, b.ndmc);
    atomic_bool stop = false;
    pthread_t rt;
    ASSERT_EQ(0, pthread_create(&rt, NULL, raise_later, &stop));
    char out[FIRC_KN_TOKEN_MAX];
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    bool got = firc_kn_token_refused("", out, &stop);
    long took = ms_since(&t0);
    pthread_join(rt, NULL);
    pid_t pid = read_pid(&b);
    bool gone = pid > 0 && kill(pid, 0) != 0 && errno == ESRCH;
    char again[FIRC_KN_TOKEN_MAX];
    firc_kn_token_current(again, NULL);
    char calls[1024];
    slurp(b.calls, calls, sizeof calls);
    ASSERT_FALSE(got);
    ASSERT_STR_EQ("", out);
    ASSERT(took < 1200);
    ASSERT(gone);
    ASSERT_STR_EQ("", again);
    ASSERT_STR_EQ("authentication token generate firc\n", calls);
    bench_drop(&b);
    PASS();
}

static void *issue_without_stop(void *ud)
{
    (void)ud;
    char tok[FIRC_KN_TOKEN_MAX];
    firc_kn_token_current(tok, NULL);
    return NULL;
}

/* catches: an untimed token-mutex wait, so a stop waits for another thread's issue */
TEST a_stop_while_another_thread_issues_a_token_returns_at_once(void)
{
    bench_t b;
    ASSERT(bench_make(&b, GENERATE_OUT));
    ASSERT(bench_flag(&b, "slow-generate"));
    firc_kn_token_setup(b.token, b.ndmc);
    firc_kn_token_set_release("5.02.A.11.0-1");
    pthread_t a;
    ASSERT_EQ(0, pthread_create(&a, NULL, issue_without_stop, NULL));
    ASSERT(read_pid(&b) > 0);
    atomic_bool stop = false;
    pthread_t rt;
    ASSERT_EQ(0, pthread_create(&rt, NULL, raise_later, &stop));
    char *body = NULL;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_err_t err = firc_kn_rci_get_timeout("http://127.0.0.1:1", "/rci/show/version", 10, &stop, &body);
    long took = ms_since(&t0);
    pthread_join(rt, NULL);
    pthread_join(a, NULL);
    ASSERT_EQ(FIRC_ERR_CANCELED, err);
    ASSERT_EQ(NULL, body);
    ASSERT(took < 1200);
    bench_drop(&b);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(only_5_02_and_later_get_a_token);
    RUN_TEST(a_stop_during_a_token_issue_returns_within_a_second);
    RUN_TEST(a_stop_while_another_thread_issues_a_token_returns_at_once);
    RUN_TEST(a_generated_token_is_read_from_the_bench_output);
    RUN_TEST(a_wrapped_value_is_joined);
    RUN_TEST(a_value_that_is_no_token_is_refused);
    RUN_TEST(only_firc_tokens_are_listed);
    RUN_TEST(only_a_token_refusal_is_one);
    RUN_TEST(below_5_02_requests_go_without_a_token);
    RUN_TEST(the_first_request_on_5_02_issues_and_keeps_a_token);
    RUN_TEST(a_kept_token_is_sent_without_asking_ndmc);
    RUN_TEST(a_kept_token_is_sent_before_the_release_is_known);
    RUN_TEST(a_refused_token_is_replaced_and_the_post_repeated);
    RUN_TEST(a_second_refusal_within_the_minute_issues_nothing);
    RUN_TEST(a_token_refusal_turns_the_token_on_before_the_release_is_known);
    RUN_TEST(another_refusal_issues_nothing);
    RUN_TEST(an_unreadable_issue_deletes_the_new_token_too);
    RUN_TEST(a_refusal_of_a_replaced_token_gives_the_current_one);
    RUN_TEST(a_token_that_cannot_be_kept_is_deleted_again);
    RUN_TEST(a_failed_generate_gives_no_token);
    RUN_TEST(a_failed_generate_says_what_ndmc_answered);
    RUN_TEST(ndmc_runs_on_the_firmware_libraries);
    RUN_TEST(a_note_on_stderr_amid_the_token_keeps_it);
    RUN_TEST(a_failed_revoke_keeps_the_file);
    RUN_TEST(revoke_on_a_router_without_token_commands_drops_the_file);
    RUN_TEST(revoke_without_a_file_asks_unless_the_firmware_is_known_old);
    RUN_TEST(revoke_deletes_firc_tokens_then_the_file);
    RUN_TEST(revoke_without_a_file_on_an_old_firmware_asks_nothing);
    GREATEST_MAIN_END();
}
