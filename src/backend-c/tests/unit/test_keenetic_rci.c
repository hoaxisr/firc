#include "greatest.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "firc/keenetic_rci.h"
#include "firc/log.h"

static const char *const LIST_JSON =
    "{\"Wireguard0\":{\"description\":\"Home VPN\"},"
    "\"Wireguard1\":{\"interface-name\":\"Backup VPN\"}}";

static const char *const NAMES_JSON =
    "[{\"show\":{\"interface\":{\"system-name\":\"nwg0\"}}},"
    "{\"show\":{\"interface\":{\"system-name\":\"nwg1\"}}}]";

static const firc_kn_iface_meta_t *find_meta(const firc_kn_iface_meta_t *metas, size_t n,
                                           const char *id)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(metas[i].id, id) == 0) {
            return &metas[i];
        }
    }
    return NULL;
}

TEST parse_interface_list_reads_both_label_fields(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(LIST_JSON, &metas, &n));
    ASSERT_EQ(2, n);

    const firc_kn_iface_meta_t *wg0 = find_meta(metas, n, "Wireguard0");
    const firc_kn_iface_meta_t *wg1 = find_meta(metas, n, "Wireguard1");
    ASSERT(wg0 != NULL);
    ASSERT(wg1 != NULL);
    ASSERT_STR_EQ("Home VPN", wg0->description);
    ASSERT_STR_EQ("", wg0->interface_name);
    ASSERT_STR_EQ("", wg1->description);
    ASSERT_STR_EQ("Backup VPN", wg1->interface_name);

    free(metas);
    PASS();
}

TEST parse_interface_list_skips_non_object_entries(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(
                         "{\"Good\":{\"description\":\"ok\"},\"Bad\":\"nope\",\"Also\":123}",
                         &metas, &n));
    ASSERT_EQ(1, n);
    ASSERT_STR_EQ("Good", metas[0].id);

    free(metas);
    PASS();
}

TEST parse_interface_list_rejects_malformed(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_parse_interface_list("{oops", &metas, &n));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_parse_interface_list("[\"an array\"]", &metas, &n));
    PASS();
}

TEST build_system_name_request_is_one_batch(void)
{
    firc_kn_iface_meta_t metas[2] = {0};
    snprintf(metas[0].id, sizeof(metas[0].id), "%s", "Wireguard0");
    snprintf(metas[1].id, sizeof(metas[1].id), "%s", "Wireguard1");

    char *body = firc_kn_build_system_name_request(metas, 2);
    ASSERT(body != NULL);
    ASSERT_STR_EQ(
        "[{\"show\":{\"interface\":{\"name\":\"Wireguard0\",\"details\":\"yes\","
        "\"system-name\":\"yes\"}}},"
        "{\"show\":{\"interface\":{\"name\":\"Wireguard1\",\"details\":\"yes\","
        "\"system-name\":\"yes\"}}}]",
        body);

    free(body);
    PASS();
}

/* Catches: RCI responses not matched to their requests by position. */
TEST parse_system_names_matches_positionally(void)
{
    firc_kn_iface_meta_t metas[2] = {0};
    snprintf(metas[0].id, sizeof(metas[0].id), "%s", "Wireguard0");
    snprintf(metas[1].id, sizeof(metas[1].id), "%s", "Wireguard1");

    ASSERT_EQ(FIRC_OK, firc_kn_parse_system_names(NAMES_JSON, metas, 2));
    ASSERT_STR_EQ("nwg0", metas[0].system_name);
    ASSERT_STR_EQ("nwg1", metas[1].system_name);
    PASS();
}

TEST parse_system_names_tolerates_length_mismatch(void)
{
    firc_kn_iface_meta_t few[1] = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_parse_system_names(NAMES_JSON, few, 1));
    ASSERT_STR_EQ("nwg0", few[0].system_name);

    firc_kn_iface_meta_t many[3] = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_parse_system_names(NAMES_JSON, many, 3));
    ASSERT_STR_EQ("nwg0", many[0].system_name);
    ASSERT_STR_EQ("nwg1", many[1].system_name);
    ASSERT_STR_EQ("", many[2].system_name);
    PASS();
}

/* Catches: the interface-name given as the description, or the description as the NDMS name. */
TEST aliases_keep_description_and_interface_name_apart(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(LIST_JSON, &metas, &n));
    ASSERT_EQ(2, n);

    for (size_t i = 0; i < n; i++) {
        if (strcmp(metas[i].id, "Wireguard0") == 0) {
            snprintf(metas[i].system_name, sizeof(metas[i].system_name), "%s", "nwg0");
        } else {
            snprintf(metas[i].system_name, sizeof(metas[i].system_name), "%s", "nwg1");
        }
    }

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, n, &aliases));
    ASSERT_EQ(2, aliases.n);
    ASSERT_STR_EQ("Home VPN", firc_kn_aliases_lookup(&aliases, "nwg0"));
    ASSERT(firc_kn_aliases_ndms_name(&aliases, "nwg0") == NULL);
    ASSERT(firc_kn_aliases_lookup(&aliases, "nwg1") == NULL);
    ASSERT_STR_EQ("Backup VPN", firc_kn_aliases_ndms_name(&aliases, "nwg1"));
    ASSERT(firc_kn_aliases_lookup(&aliases, "br0") == NULL);
    ASSERT(firc_kn_aliases_ndms_name(&aliases, "br0") == NULL);

    firc_kn_aliases_free(&aliases);
    free(metas);
    PASS();
}

/* Catches: an interface NDMS lists without a usable name forgotten, so the list drops it as unknown, or one with no kernel name kept. */
TEST aliases_skip_empty_and_redundant(void)
{
    firc_kn_iface_meta_t metas[4] = {0};

    snprintf(metas[0].description, sizeof(metas[0].description), "%s", "Orphan");

    snprintf(metas[1].system_name, sizeof(metas[1].system_name), "%s", "eth0");

    snprintf(metas[2].description, sizeof(metas[2].description), "%s", "eth1");
    snprintf(metas[2].system_name, sizeof(metas[2].system_name), "%s", "eth1");

    snprintf(metas[3].description, sizeof(metas[3].description), "%s", "   ");
    snprintf(metas[3].system_name, sizeof(metas[3].system_name), "%s", "eth2");

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, 4, &aliases));
    ASSERT_EQ(3, aliases.n);
    ASSERT(firc_kn_aliases_lookup(&aliases, "eth0") == NULL);
    ASSERT(firc_kn_aliases_lookup(&aliases, "eth1") == NULL);
    ASSERT(firc_kn_aliases_lookup(&aliases, "eth2") == NULL);
    ASSERT(firc_kn_aliases_known(&aliases, "eth0"));
    ASSERT(firc_kn_aliases_known(&aliases, "eth1"));
    ASSERT_FALSE(firc_kn_aliases_known(&aliases, "eth9"));
    ASSERT_FALSE(firc_kn_aliases_known(NULL, "eth0"));

    firc_kn_aliases_free(&aliases);
    PASS();
}

TEST labels_and_system_names_are_trimmed(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(
                         "{\"Wg\":{\"description\":\"  Padded VPN \\t\"}}", &metas, &n));
    ASSERT_EQ(1, n);
    ASSERT_STR_EQ("Padded VPN", metas[0].description);

    ASSERT_EQ(FIRC_OK, firc_kn_parse_system_names(
                         "[{\"show\":{\"interface\":{\"system-name\":\"  nwg0  \"}}}]", metas, 1));
    ASSERT_STR_EQ("nwg0", metas[0].system_name);

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, 1, &aliases));
    ASSERT_EQ(1, aliases.n);
    ASSERT_STR_EQ("Padded VPN", firc_kn_aliases_lookup(&aliases, "nwg0"));

    firc_kn_aliases_free(&aliases);
    free(metas);
    PASS();
}

TEST empty_list_yields_no_aliases(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list("{}", &metas, &n));
    ASSERT_EQ(0, n);

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, n, &aliases));
    ASSERT_EQ(0, aliases.n);
    ASSERT(aliases.items == NULL);

    firc_kn_aliases_free(&aliases);
    free(metas);
    PASS();
}

/* Catches: the default lookup misbehaving when RCI does not answer. */
TEST platform_default_is_empty_and_safe(void)
{
    firc_kn_aliases_t aliases = {0};
    firc_err_t err = firc_kn_get_iface_aliases(&aliases);
#ifdef FIRC_ENTWARE_KN
    (void)err;
#else
    ASSERT_EQ(FIRC_OK, err);
#endif
    ASSERT_EQ(0, aliases.n);
    ASSERT(aliases.items == NULL);
    ASSERT(firc_kn_aliases_lookup(&aliases, "br0") == NULL);

    firc_kn_aliases_free(&aliases);
    firc_kn_aliases_free(&aliases);
    PASS();
}

static const char *const ROLE_JSON =
    "{\"0\":{\"type\":\"Port\",\"role\":[{\"for\":\"GigabitEthernet1\",\"role\":\"inet\"}]},"
    "\"GigabitEthernet1\":{\"interface-name\":\"ISP\",\"type\":\"GigabitEthernet\",\"global\":false},"
    "\"PPPoE0\":{\"type\":\"PPPoE\",\"role\":[\"misc\",\"inet\"],\"global\":true,"
    "\"description\":\"Broadband connection\"},"
    "\"Wireguard1\":{\"type\":\"Wireguard\",\"global\":true},"
    "\"Bridge0\":{\"type\":\"Bridge\",\"role\":[\"misc\"]}}";

/* Catches: an interface's own inet role, or one a port gives it by "for", not read, or one given to the wrong entry. */
TEST inet_role_comes_from_the_entry_or_from_a_port(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(ROLE_JSON, &metas, &n));
    ASSERT_EQ(5, n);
    ASSERT(find_meta(metas, n, "PPPoE0")->inet);
    ASSERT(find_meta(metas, n, "GigabitEthernet1")->inet);
    ASSERT_FALSE(find_meta(metas, n, "0")->inet);
    ASSERT_FALSE(find_meta(metas, n, "Wireguard1")->inet);
    ASSERT_FALSE(find_meta(metas, n, "Bridge0")->inet);
    free(metas);
    PASS();
}

/* Catches: a port's "for" honoured only when the port comes after the interface it names. */
TEST a_port_role_reaches_an_interface_listed_after_it(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(
                           "{\"GigabitEthernet1\":{},"
                           "\"0\":{\"role\":[{\"for\":\"GigabitEthernet1\",\"role\":\"inet\"}]}}",
                           &metas, &n));
    ASSERT_EQ(2, n);
    ASSERT(find_meta(metas, n, "GigabitEthernet1")->inet);
    ASSERT_FALSE(find_meta(metas, n, "0")->inet);
    free(metas);
    PASS();
}

/* Catches: a role of the wrong shape, case or kind taken as inet. */
TEST malformed_roles_make_nothing_external(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK,
              firc_kn_parse_interface_list(
                  "{\"A\":{\"role\":\"inet\"},"
                  "\"B\":{\"role\":[\"INET\",\"inet0\",1,null]},"
                  "\"C\":{\"role\":{\"for\":\"C\",\"role\":\"inet\"}},"
                  "\"D\":{},"
                  "\"E\":{\"role\":[{\"for\":\"D\",\"role\":\"misc\"},{\"for\":\"D\",\"role\":[\"inet\"]},"
                  "{\"for\":7,\"role\":\"inet\"},{\"role\":\"inet\"},{\"for\":\"nobody\",\"role\":\"inet\"},"
                  "[\"inet\"]]}}",
                  &metas, &n));
    ASSERT_EQ(5, n);
    for (size_t i = 0; i < n; i++) { ASSERT_FALSEm(metas[i].id, metas[i].inet); }
    free(metas);
    PASS();
}

/* Catches: an external interface dropped from the set for having no label, or the flag lost on the way. */
TEST aliases_keep_external_interfaces_without_a_label(void)
{
    firc_kn_iface_meta_t metas[4] = {0};
    snprintf(metas[0].system_name, sizeof(metas[0].system_name), "%s", "eth3");
    metas[0].inet = true;
    snprintf(metas[1].description, sizeof(metas[1].description), "%s", "Broadband");
    snprintf(metas[1].system_name, sizeof(metas[1].system_name), "%s", "ppp0");
    metas[1].inet = true;
    snprintf(metas[2].description, sizeof(metas[2].description), "%s", "Home VPN");
    snprintf(metas[2].system_name, sizeof(metas[2].system_name), "%s", "nwg0");
    snprintf(metas[3].description, sizeof(metas[3].description), "%s", "No kernel name");
    metas[3].inet = true;

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, 4, &aliases));
    ASSERT_EQ(3, aliases.n);
    ASSERT(firc_kn_aliases_inet(&aliases, "eth3"));
    ASSERT(firc_kn_aliases_lookup(&aliases, "eth3") == NULL);
    ASSERT(firc_kn_aliases_inet(&aliases, "ppp0"));
    ASSERT_STR_EQ("Broadband", firc_kn_aliases_lookup(&aliases, "ppp0"));
    ASSERT_FALSE(firc_kn_aliases_inet(&aliases, "nwg0"));
    ASSERT_STR_EQ("Home VPN", firc_kn_aliases_lookup(&aliases, "nwg0"));
    ASSERT_FALSE(firc_kn_aliases_inet(&aliases, "br0"));
    ASSERT_FALSE(firc_kn_aliases_inet(NULL, "ppp0"));
    firc_kn_aliases_free(&aliases);
    PASS();
}

/* Catches: an unlabelled external entry for a kernel name hiding the label a later entry gives it. */
TEST a_label_after_an_unlabelled_external_entry_is_found(void)
{
    firc_kn_iface_meta_t metas[2] = {0};
    snprintf(metas[0].system_name, sizeof(metas[0].system_name), "%s", "eth3");
    metas[0].inet = true;
    snprintf(metas[1].description, sizeof(metas[1].description), "%s", "ISP");
    snprintf(metas[1].system_name, sizeof(metas[1].system_name), "%s", "eth3");

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, 2, &aliases));
    ASSERT_STR_EQ("ISP", firc_kn_aliases_lookup(&aliases, "eth3"));
    ASSERT(firc_kn_aliases_inet(&aliases, "eth3"));
    firc_kn_aliases_free(&aliases);
    PASS();
}

/* Catches: one of the two names lost when both are set, or a name equal to the kernel name kept. */
TEST an_entry_carries_both_names_and_drops_one_equal_to_the_kernel_name(void)
{
    firc_kn_iface_meta_t metas[2] = {0};
    snprintf(metas[0].description, sizeof(metas[0].description), "%s", "WARP");
    snprintf(metas[0].interface_name, sizeof(metas[0].interface_name), "%s", "Wireguard0");
    snprintf(metas[0].system_name, sizeof(metas[0].system_name), "%s", "nwg0");
    snprintf(metas[1].description, sizeof(metas[1].description), "%s", "Guest");
    snprintf(metas[1].interface_name, sizeof(metas[1].interface_name), "%s", "br1");
    snprintf(metas[1].system_name, sizeof(metas[1].system_name), "%s", "br1");

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, 2, &aliases));
    ASSERT_STR_EQ("WARP", firc_kn_aliases_lookup(&aliases, "nwg0"));
    ASSERT_STR_EQ("Wireguard0", firc_kn_aliases_ndms_name(&aliases, "nwg0"));
    ASSERT_STR_EQ("Guest", firc_kn_aliases_lookup(&aliases, "br1"));
    ASSERT(firc_kn_aliases_ndms_name(&aliases, "br1") == NULL);
    ASSERT(firc_kn_aliases_ndms_name(NULL, "nwg0") == NULL);
    firc_kn_aliases_free(&aliases);
    PASS();
}

typedef struct {
    int fd;
    int delay_ms;
    int port;
} slow_rci_server_t;

static void *slow_rci_serve(void *ud)
{
    slow_rci_server_t *s = ud;
    for (int k = 0; k < 2; k++) {
        int c = accept(s->fd, NULL, NULL);
        if (c < 0) {
            break;
        }
        char req[2048];
        ssize_t got = recv(c, req, sizeof req, 0);
        (void)got;
        struct timespec ts = {s->delay_ms / 1000, (long)(s->delay_ms % 1000) * 1000000L};
        nanosleep(&ts, NULL);
        static const char reply[] =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 23\r\n"
            "Connection: close\r\n\r\n{\"serial\":\"S987654321\"}";
        ssize_t sent = send(c, reply, sizeof reply - 1, MSG_NOSIGNAL);
        (void)sent;
        close(c);
    }
    return NULL;
}

static bool slow_rci_listen(slow_rci_server_t *s)
{
    s->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof a;
    if (s->fd < 0 || bind(s->fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(s->fd, 4) != 0 ||
        getsockname(s->fd, (struct sockaddr *)&a, &len) != 0) {
        return false;
    }
    s->port = ntohs(a.sin_port);
    return true;
}

/* Catches: the serial's call held to the 2 s every other RCI call has, so a router answering in 2.9 s never gives it. */
TEST a_call_with_its_own_timeout_outlasts_a_slow_answer(void)
{
    slow_rci_server_t s = {.delay_ms = 2600};
    ASSERT(slow_rci_listen(&s));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, slow_rci_serve, &s));
    char base[64];
    snprintf(base, sizeof base, "http://127.0.0.1:%d", s.port);
    char *body = NULL;
    ASSERT_EQ(FIRC_ERR_TIMEOUT, firc_kn_rci_get(base, "/rci/show/defaults", &body));
    ASSERT_EQ(NULL, body);
    firc_err_t err = firc_kn_rci_get_timeout(base, "/rci/show/defaults", 10, &body);
    pthread_join(th, NULL);
    close(s.fd);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_STR_EQ("{\"serial\":\"S987654321\"}", body);
    free(body);
    PASS();
}

/* Catches: a failed RCI call logged with libcurl's words alone, which Entware's libcurl reduces to "Error". */
TEST a_failed_call_names_the_curl_code(void)
{
    slow_rci_server_t s = {0};
    ASSERT(slow_rci_listen(&s));
    close(s.fd);
    char base[64], logpath[] = "/tmp/firc_rci_log_XXXXXX", text[2048] = "";
    snprintf(base, sizeof base, "http://127.0.0.1:%d", s.port);
    int fd = mkstemp(logpath);
    ASSERT(fd >= 0);
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    firc_log_set_fd(fd);
    char *body = NULL;
    firc_err_t err = firc_kn_rci_get(base, "/rci/show/version", &body);
    firc_log_set_fd(1);
    ssize_t n = pread(fd, text, sizeof text - 1, 0);
    close(fd);
    unlink(logpath);
    text[n > 0 ? n : 0] = '\0';
    ASSERT_EQ(FIRC_ERR_UPSTREAM, err);
    ASSERT(strstr(text, "/rci/show/version failed:") != NULL);
    ASSERT(strstr(text, "(curl 7)") != NULL);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(parse_interface_list_reads_both_label_fields);
    RUN_TEST(parse_interface_list_skips_non_object_entries);
    RUN_TEST(parse_interface_list_rejects_malformed);
    RUN_TEST(build_system_name_request_is_one_batch);
    RUN_TEST(parse_system_names_matches_positionally);
    RUN_TEST(parse_system_names_tolerates_length_mismatch);
    RUN_TEST(aliases_keep_description_and_interface_name_apart);
    RUN_TEST(an_entry_carries_both_names_and_drops_one_equal_to_the_kernel_name);
    RUN_TEST(aliases_skip_empty_and_redundant);
    RUN_TEST(labels_and_system_names_are_trimmed);
    RUN_TEST(empty_list_yields_no_aliases);
    RUN_TEST(platform_default_is_empty_and_safe);
    RUN_TEST(inet_role_comes_from_the_entry_or_from_a_port);
    RUN_TEST(a_port_role_reaches_an_interface_listed_after_it);
    RUN_TEST(malformed_roles_make_nothing_external);
    RUN_TEST(aliases_keep_external_interfaces_without_a_label);
    RUN_TEST(a_label_after_an_unlabelled_external_entry_is_found);
    RUN_TEST(a_call_with_its_own_timeout_outlasts_a_slow_answer);
    RUN_TEST(a_failed_call_names_the_curl_code);
    GREATEST_MAIN_END();
}
