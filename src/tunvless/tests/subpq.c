/* Subscription parsing of the newer Xray-core fields and of the other config formats: encryption
 * (VLESS encryption) and pqv / mldsa65Verify (Reality's ML-DSA-65 check) in vless:// links and in
 * Xray JSON (both settings forms, vnext/users and the flat one); sing-box and Clash/Mihomo
 * outbounds; certificate checks (pcs, vcn, allowInsecure); ECH; and the skip reasons.
 *
 * The values are real, from Xray-core 26.9.9 (tests/sub-pq-samples.h). No crypto is needed:
 * vencp.h decides whether an encryption string is valid, and the exchanges themselves are tested
 * on the real library against a real Xray by tests/venc.sh (`make interop`). */
#include <stdio.h>
#include <string.h>

#include "vless.h"
#include "vencp.h"
#include "sub-pq-samples.h"

static int g_pass, g_fail;
static void check(const char *what, int ok) {
    if (ok) g_pass++; else { g_fail++; printf("FAIL: %s\n", what); }
}
static void check_s(const char *what, const char *want, const char *got) {
    int ok = got && !strcmp(want, got);
    if (!ok) printf("  expected '%s', got '%s'\n", want, got ? got : "(null)");
    check(what, ok);
}

#define UUID "b831381d-6324-4d53-ad4f-8cda48b30811"

static int url(const char *fmt_tail, struct vless_node *n) {
    static char buf[9000];
    snprintf(buf, sizeof buf, "vless://" UUID "@example.org:443?%s", fmt_tail);
    return vless_parse_url(buf, n);
}

int main(void) {
    struct vless_node n, n2;
    char q[8000];

    /* --- encryption in a link --- */
    snprintf(q, sizeof q, "encryption=%s&type=tcp&security=none#a", ENC_X25519);
    check("encryption X25519 (0rtt): node usable", url(q, &n) == 0);
    check_s("encryption stored as the string, unchanged", ENC_X25519, n.encryption);

    snprintf(q, sizeof q, "encryption=%s&type=tcp&security=none#a", ENC_MLKEM);
    check("encryption ML-KEM (1579-character key): node usable", url(q, &n) == 0);
    check_s("long key not truncated", ENC_MLKEM, n.encryption);
    check("same value twice: one interned copy", url(q, &n2) == 0 && n.encryption == n2.encryption);

    {   /* modes and padding, parsed by vencp */
        static const char *modes[] = { "native", "xorpub", "random" };
        for (int i = 0; i < 3; i++) {
            char e[400];
            snprintf(e, sizeof e, "mlkem768x25519plus.%s.1rtt.100-111-1111.75-0-111.50-0-3333.YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKxkQ", modes[i]);
            snprintf(q, sizeof q, "encryption=%s&type=tcp&security=none#m", e);
            int rc = url(q, &n);
            struct venc_cfg c;
            int pr = n.encryption ? vencp_parse(n.encryption, &c, NULL) : -1;
            char w[80];
            snprintf(w, sizeof w, "mode %s with padding: usable and parsed", modes[i]);
            check(w, rc == 0 && pr == 0 && c.xor_mode == i && !c.zero_rtt && c.nkeys == 1 &&
                     c.npad_lens == 2 && c.npad_gaps == 1 && c.lens[0][2] == 1111 && c.gaps[0][0] == 75);
        }
    }

    check("encryption=none: no encryption", url("encryption=none&type=tcp&security=none#n", &n) == 0 && n.encryption == NULL);
    check("encryption empty: no encryption", url("encryption=&type=tcp&security=none#n", &n) == 0 && n.encryption == NULL);
    check("no encryption parameter: no encryption", url("type=tcp&security=none#n", &n) == 0 && n.encryption == NULL);

    check("encryption of a foreign kind: node skipped", url("encryption=aes-128-gcm&type=tcp&security=none#n", &n) == 1);
    check_s("skip reason named", "encryption is not supported", n.skip_reason);
    /* Each string below breaks one rule and keeps the rest, so that it is refused for that
     * rule: the mode has six letters like the known ones, the key has a valid base64url length,
     * the padding is valid. */
#define ENC(mid) "encryption=mlkem768x25519plus." mid "&type=tcp&security=none#n"
#define KEY "YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKxkQ"
    check("first padding of exactly 35, a 32-byte key: usable",
          url(ENC("native.0rtt.100-35-35." KEY), &n) == 0);
    check("unknown mode: skipped", url(ENC("custom.0rtt." KEY), &n) == 1);
    /* 40 characters: 30 bytes. */
    check("key neither 32 nor 1184 bytes: skipped",
          url(ENC("native.0rtt.YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNK"), &n) == 1);
    check("no key: skipped", url(ENC("native.0rtt.100-111-1111"), &n) == 1);
    /* The first padding: probability 100, both lengths at least 35. */
    check("first padding with a lower bound below 35: skipped",
          url(ENC("native.0rtt.100-34-111." KEY), &n) == 1);
    check("first padding with an upper bound below 35: skipped",
          url(ENC("native.0rtt.100-111-34." KEY), &n) == 1);
    check("first padding with a probability below 100: skipped",
          url(ENC("native.0rtt.99-111-111." KEY), &n) == 1);
#undef ENC
#undef KEY

    /* --- pqv --- */
    snprintf(q, sizeof q, "type=tcp&security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=01&sni=example.com&fp=chrome&pqv=%s#p", PQV_KEY);
    check("reality with pqv: usable", url(q, &n) == 0);
    check_s("pqv stored whole (2603 characters)", PQV_KEY, n.pqv);
    snprintf(q, sizeof q, "type=tcp&security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=01&sni=example.com&pqv=%.100s#p", PQV_KEY);
    check("short pqv: skipped", url(q, &n) == 1);
    check_s("pqv skip reason named", "pqv: not an ML-DSA-65 key", n.skip_reason);
    /* Exactly 1952 bytes: a longer key (2607 characters, 1955 bytes) is not ML-DSA-65 either. */
    snprintf(q, sizeof q,
             "type=tcp&security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng"
             "&sid=01&sni=example.com&pqv=%sAAAA#p", PQV_KEY);
    check("long pqv: skipped", url(q, &n) == 1);

    /* --- flow --- */
    check("flow vision-udp443 becomes vision",
          url("type=tcp&security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=01&sni=e.com&flow=xtls-rprx-vision-udp443#f", &n) == 0 &&
          !strcmp(n.flow, "xtls-rprx-vision"));

    /* --- Xray config: vnext/users and the flat settings form --- */
    {
        static char js[12000];
        snprintf(js, sizeof js,
            "[{\"remarks\":\"PQ\",\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
            "\"settings\":{\"vnext\":[{\"address\":\"example.org\",\"port\":443,\"users\":[{\"id\":\"" UUID "\","
            "\"flow\":\"xtls-rprx-vision\",\"encryption\":\"none\"}]}]},"
            "\"streamSettings\":{\"network\":\"raw\",\"security\":\"reality\",\"realitySettings\":{"
            "\"serverName\":\"example.com\",\"fingerprint\":\"chrome\",\"publicKey\":\"K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng\","
            "\"shortId\":\"01\",\"mldsa65Verify\":\"%s\"}}}]},"
            "{\"remarks\":\"ENC\",\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
            "\"settings\":{\"vnext\":[{\"address\":\"example.net\",\"port\":8443,\"users\":[{\"id\":\"" UUID "\","
            "\"encryption\":\"%s\"}]}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"none\"}}]},"
            "{\"remarks\":\"SIMPLE\",\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
            "\"settings\":{\"address\":\"example.io\",\"port\":\"9443\",\"id\":\"" UUID "\",\"encryption\":\"%s\"},"
            "\"streamSettings\":{\"network\":\"tcp\",\"security\":\"none\"}}]}]",
            PQV_KEY, ENC_X25519, ENC_MLKEM);
        struct vless_node out[8];
        struct vless_sub_stats st;
        memset(&st, 0, sizeof st);
        size_t cnt = vless_parse_sub(js, out, 8, &st);
        check("JSON: three nodes usable", cnt == 3);
        if (cnt == 3) {
            check("JSON: mldsa65Verify → pqv", out[0].pqv && !strcmp(out[0].pqv, PQV_KEY));
            check("JSON: encryption none: no encryption", out[0].encryption == NULL);
            check_s("JSON: users[].encryption", ENC_X25519, out[1].encryption);
            check("JSON: flat settings form: address, port, id", !strcmp(out[2].host, "example.io") && out[2].port == 9443 && !strcmp(out[2].uuid, UUID));
            check_s("JSON: flat settings form: encryption", ENC_MLKEM, out[2].encryption);
        }
        check("JSON: nothing skipped", st.skipped == 0);
    }

    /* --- a subscription of links: the counts add up --- */
    {
        static char sub[20000];
        snprintf(sub, sizeof sub,
                 "vless://" UUID "@a.example:443?encryption=%s&type=tcp&security=none#ok1\n"
                 "vless://" UUID "@b.example:443?encryption=bogus&type=tcp&security=none#bad1\n"
                 "vless://" UUID "@c.example:443?encryption=%s&type=tcp&security=none#ok2\n",
                 ENC_MLKEM, ENC_X25519);
        struct vless_node out[8];
        struct vless_sub_stats st;
        memset(&st, 0, sizeof st);
        size_t cnt = vless_parse_sub(sub, out, 8, &st);
        check("links: 2 usable, 1 skipped", cnt == 2 && st.skipped == 1);
        check("links: skip reason counted with its example node", st.reasons_n == 1 && !strcmp(st.reasons[0].reason, "encryption is not supported") &&
              !strcmp(st.reasons[0].example, "bad1"));
    }


    /* --- what the server requires and the client cannot do --- */
    check("tcp headerType=http: skipped", url("type=tcp&security=none&headerType=http#h", &n) == 1);
    check_s("headerType skip reason", "tcp headerType=http is not supported", n.skip_reason);
    check("tcp headerType=none: usable", url("type=tcp&security=none&headerType=none#h", &n) == 0);
    check("xhttp with downloadSettings in extra: skipped",
          url("type=xhttp&security=none&path=/x&extra=%7B%22downloadSettings%22%3A%7B%22address%22%3A%22d.example%22%7D%7D#x", &n) == 1);
    check_s("xhttp skip reason", "xhttp: obfuscation is not supported", n.skip_reason);
    check("xhttp with xPaddingBytes in extra: usable, padding read",
          url("type=xhttp&security=none&path=/x&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D#x", &n) == 0 && n.pad_from == 100);
    check("xhttp with xPaddingObfsMode=true: skipped",
          url("type=xhttp&security=none&path=/x&extra=%7B%22xPaddingObfsMode%22%3Atrue%7D#x", &n) == 1);

    /* --- sing-box: outbounds --- */
    {
        static char js[6000];
        snprintf(js, sizeof js,
            "{\"log\":{},\"outbounds\":[{\"type\":\"selector\",\"tag\":\"sel\",\"outbounds\":[\"a\"]},"
            "{\"type\":\"vless\",\"tag\":\"sb-reality\",\"server\":\"example.org\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"flow\":\"xtls-rprx-vision\",\"tls\":{\"enabled\":true,\"server_name\":\"example.com\","
            "\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"},\"reality\":{\"enabled\":true,"
            "\"public_key\":\"K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng\",\"short_id\":\"0123456789abcdef\"}}},"
            "{\"type\":\"vless\",\"tag\":\"sb-ws\",\"server\":\"cdn.example.org\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"tls\":{\"enabled\":true,\"server_name\":\"cdn.example.org\"},"
            "\"transport\":{\"type\":\"ws\",\"path\":\"/ws\","
            "\"headers\":{\"Host\":[\"front.example.org\",\"other.example.org\"]},"
            "\"max_early_data\":2048,\"early_data_header_name\":\"Sec-WebSocket-Protocol\"}},"
            "{\"type\":\"trojan\",\"tag\":\"t\",\"server\":\"x\",\"server_port\":1}]}");
        struct vless_node out[8];
        struct vless_sub_stats st;
        size_t cnt = vless_parse_sub(js, out, 8, &st);
        check("sing-box: two vless nodes", cnt == 2);
        /* selector and trojan are not VLESS nodes: neither usable nor skipped. */
        check("sing-box: selector and trojan not counted as skipped VLESS nodes", st.skipped == 0);
        if (cnt == 2) {
            check("sing-box: reality: pbk, sid, sni, fp, port, name, flow",
                  !strcmp(out[0].security, "reality") && !strcmp(out[0].pbk, "K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng") &&
                  !strcmp(out[0].sid, "0123456789abcdef") && !strcmp(out[0].sni, "example.com") && !strcmp(out[0].fp, "chrome") &&
                  out[0].port == 443 && !strcmp(out[0].name, "sb-reality") && !strcmp(out[0].flow, "xtls-rprx-vision"));
            check_s("sing-box: ws path with early data", "/ws?ed=2048", out[1].path);
            check_s("sing-box: ws Host, the first of the array", "front.example.org",
                    out[1].http_host);
            check("sing-box: tls and type ws", !strcmp(out[1].security, "tls") && !strcmp(out[1].type, "ws"));
        }
        /* Without early_data_header_name sing-box sends early data in the path, a form Xray does
         * not have: early data stays off. */
        snprintf(js, sizeof js,
            "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"a\",\"server\":\"x.example\","
            "\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"transport\":{\"type\":\"ws\",\"path\":\"/ws\",\"max_early_data\":2048}}]}");
        cnt = vless_parse_sub(js, out, 8, &st);
        check("sing-box: early data without the header name: path without ed",
              cnt == 1 && !strcmp(out[0].path, "/ws"));
    }

    /* --- Clash / Mihomo --- */
    {
        static char y[9000];
        snprintf(y, sizeof y,
            "port: 7890\nmixed-port: 7891\nproxies:\n"
            "  - name: \"clash-block\"   # комментарий\n"
            "    type: vless\n    server: example.org\n    port: 443\n    uuid: " UUID "\n"
            "    network: tcp\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n"
            "    servername: example.com   # SNI\n"
            "    client-fingerprint: chrome\n    encryption: \"\"\n"
            "    alpn:\n      - h2\n      - http/1.1\n"
            "    reality-opts:\n      public-key: K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng\n      short-id: 0123456789abcdef\n"
            "  - {name: clash-flow, type: vless, server: cdn.example.org, port: 8443, uuid: " UUID ", network: ws, tls: true, servername: cdn.example.org, "
            "ws-opts: {path: /ws, headers: {Host: front.example.org}, max-early-data: 2048, early-data-header-name: Sec-WebSocket-Protocol}}\n"
            "  - name: clash-enc\n    type: vless\n    server: enc.example.org\n    port: 9443\n    uuid: " UUID "\n    network: tcp\n    encryption: %s\n"
            "  - name: ss-node\n    type: ss\n    server: s\n    port: 1\n    cipher: aes-128-gcm\n    password: p\n"
            "  - name: grpc-node\n    type: vless\n    server: g.example.org\n    port: 443\n    uuid: " UUID "\n    network: grpc\n    tls: true\n"
            "    grpc-opts:\n      grpc-service-name: svc\n"
            "proxy-groups:\n  - name: auto\n    type: select\n    proxies:\n      - clash-block\n", ENC_X25519);
        struct vless_node out[8];
        struct vless_sub_stats st;
        size_t cnt = vless_parse_sub(y, out, 8, &st);
        check("Clash: four vless nodes, one foreign", cnt == 4 && st.foreign == 1);
        if (cnt == 4) {
            /* The comments: after a quoted name, and after a plain value (servername). */
            check("Clash (block style): reality, sni, fp, pbk, sid, flow, name; comments dropped",
                  !strcmp(out[0].security, "reality") && !strcmp(out[0].sni, "example.com") && !strcmp(out[0].fp, "chrome") &&
                  !strcmp(out[0].pbk, "K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng") && !strcmp(out[0].sid, "0123456789abcdef") &&
                  !strcmp(out[0].flow, "xtls-rprx-vision") && !strcmp(out[0].name, "clash-block") && out[0].encryption == NULL);
            check("Clash (flow style): ws, path, Host, early data, tls, port",
                  !strcmp(out[1].type, "ws") && !strcmp(out[1].path, "/ws?ed=2048") && !strcmp(out[1].http_host, "front.example.org") &&
                  !strcmp(out[1].security, "tls") && out[1].port == 8443);
            check_s("Clash: encryption", ENC_X25519, out[2].encryption);
            check("Clash: grpc-service-name", !strcmp(out[3].type, "grpc") && !strcmp(out[3].service, "svc"));
        }
        char dec[64];
        check("Clash recognised as text, not base64", vless_sub_text(y, strlen(y), dec, sizeof dec) == y);
    }

    /* ---- node certificate checks: pcs / vcn / allowInsecure (Xray-core, sing-box, Clash) ---- */
    {
        static const char H1[] = "f8c71232f26e142a9ec780c297bd500dcbfadd2bde91f4a97876ab4d73631c12";
        static const char H2[] = "a0cf13f5063002c9f3cf982cda1fdebcb9f1277a1f56969cfa1b1d7837becfc7";
        struct vless_node n;
        char q[400];

        snprintf(q, sizeof q, "security=tls&sni=t.example&pcs=%s", H1);
        check("pcs: node usable", url(q, &n) == 0);
        check_s("pcs: fingerprint stored", H1, n.pcs);
        snprintf(q, sizeof q, "security=tls&sni=t.example&pcs=F8:C7:12:32:F2:6E:14:2A:9E:C7:80:C2:97:BD:50:0D:CB:FA:DD:2B:DE:91:F4:A9:78:76:AB:4D:73:63:1C:12,%s&vcn=a.example,%%20b.example", H2);
        check("pcs with colons and a list, vcn with a space: usable", url(q, &n) == 0);
        char want2[140];
        snprintf(want2, sizeof want2, "%s,%s", H1, H2);
        check_s("pcs: colons dropped, lower-cased, list kept", want2, n.pcs);
        check_s("vcn: list of names, space dropped", "a.example,b.example", n.vcn);
        check("pcs not a SHA-256: node unusable", url("security=tls&sni=t.example&pcs=abcd", &n) == 1);
        check_s("  skip reason named", "pcs: not a hex SHA-256", n.skip_reason);
        check("pcs is ignored for reality", url("security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=0123&pcs=abcd", &n) == 0);

        /* allowInsecure: a subscription cannot turn the check off by itself. */
        vless_set_insecure(0);
        check("allowInsecure=1 on tls without --insecure: node unusable", url("security=tls&sni=t.example&allowInsecure=1", &n) == 1);
        check_s("  skip reason named", "allowInsecure: needs --insecure", n.skip_reason);
        check("insecure=1 (as panels write it): the same", url("security=tls&sni=t.example&insecure=1", &n) == 1);
        check("allowInsecure=0: ordinary node", url("security=tls&sni=t.example&allowInsecure=0", &n) == 0 && !n.insecure);
        check("allowInsecure does not affect reality", url("security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=0123&allowInsecure=1", &n) == 0);
        vless_set_insecure(1);
        check("with --insecure the node is usable and marked insecure", url("security=tls&sni=t.example&allowInsecure=1", &n) == 0 && n.insecure);
        vless_set_insecure(0);

        /* Xray config. */
        {
            static const char *js =
                "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"x.example\",\"port\":443,"
                "\"users\":[{\"id\":\"" UUID "\"}]}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"tls\","
                "\"tlsSettings\":{\"serverName\":\"x.example\",\"pinnedPeerCertSha256\":\"f8c71232f26e142a9ec780c297bd500dcbfadd2bde91f4a97876ab4d73631c12\","
                "\"verifyPeerCertByName\":\"v.example\"}}}]}";
            struct vless_node out[2];
            struct vless_sub_stats st;
            size_t cnt = vless_parse_sub(js, out, 2, &st);
            check("Xray JSON: pinnedPeerCertSha256 and verifyPeerCertByName", cnt == 1 && out[0].pcs && !strcmp(out[0].pcs, H1) &&
                  out[0].vcn && !strcmp(out[0].vcn, "v.example"));
            static const char *js2 =
                "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"x.example\",\"port\":443,"
                "\"users\":[{\"id\":\"" UUID "\"}]}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"tls\","
                "\"tlsSettings\":{\"serverName\":\"x.example\",\"allowInsecure\":true}}}]}";
            check("Xray JSON: allowInsecure: node skipped", vless_parse_sub(js2, out, 2, &st) == 0 && st.skipped == 1);
        }
        /* sing-box. */
        {
            static const char *sb =
                "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"a\",\"server\":\"x.example\",\"server_port\":443,\"uuid\":\"" UUID "\","
                "\"tls\":{\"enabled\":true,\"server_name\":\"x.example\","
                "\"certificate_public_key_sha256\":[\"1hD3S62x74la2vO7hT4FuMdtQwscW6lAZrzE1Ua3dn0=\"]}}]}";
            struct vless_node out[2];
            struct vless_sub_stats st;
            size_t cnt = vless_parse_sub(sb, out, 2, &st);
            check("sing-box: certificate_public_key_sha256 converted to hex",
                  cnt == 1 && out[0].pks && !strcmp(out[0].pks, "d610f74badb1ef895adaf3bb853e05b8c76d430b1c5ba94066bcc4d546b7767d"));
            static const char *sb2 =
                "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"a\",\"server\":\"x.example\",\"server_port\":443,\"uuid\":\"" UUID "\","
                "\"tls\":{\"enabled\":true,\"server_name\":\"x.example\",\"insecure\":true}}]}";
            check("sing-box: insecure: node skipped", vless_parse_sub(sb2, out, 2, &st) == 0 && st.skipped == 1);
        }
        /* Clash. */
        {
            static const char *y =
                "proxies:\n  - name: c1\n    type: vless\n    server: x.example\n    port: 443\n    uuid: " UUID "\n"
                "    network: tcp\n    tls: true\n    servername: x.example\n"
                "    fingerprint: f8c71232f26e142a9ec780c297bd500dcbfadd2bde91f4a97876ab4d73631c12\n"
                "  - name: c2\n    type: vless\n    server: y.example\n    port: 443\n    uuid: " UUID "\n"
                "    network: tcp\n    tls: true\n    servername: y.example\n    skip-cert-verify: true\n";
            struct vless_node out[3];
            struct vless_sub_stats st;
            size_t cnt = vless_parse_sub(y, out, 3, &st);
            check("Clash: fingerprint goes to pcs; skip-cert-verify: node skipped",
                  cnt == 1 && out[0].pcs && !strcmp(out[0].pcs, H1) && st.skipped == 1);
        }
    }

    /* ---- ECH: echConfigList / ech= (Xray), ech-opts (Clash), ech (sing-box) ---- */
    {
        static const char ECH[] = "AEX+DQBBNwAgACANG785NbYxf2vAoHiUugO7PDLchnWNz2f+95epg2DJewAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";
        struct vless_node n;
        char q[400];
        snprintf(q, sizeof q, "security=tls&sni=t.example&ech=%s", "AEX%2BDQBBNwAgACANG785NbYxf2vAoHiUugO7PDLchnWNz2f%2B95epg2DJewAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA%3D");
        check("ech= in a link: node usable", url(q, &n) == 0);
        check_s("  value decoded from percent-encoding", ECH, n.ech);
        /* One 0xfe0d entry of two bytes, the smallest list that passes; then lists each wrong in
         * one part, so that every part of the form check is needed to refuse them. */
        check("ech= of one minimal 0xfe0d entry: node usable",
              url("security=tls&sni=t.example&ech=AAb+DQACAAA=", &n) == 0);
        static const char *const bad_ech[][2] = {
            { "AAAA", "ech= not an ECHConfigList (3 bytes): node unusable" },
            { "AAf+DQACAAA=", "ech= not an ECHConfigList (length 7, 6 bytes): node unusable" },
            { "AAb+DQAFAAA=", "ech= not an ECHConfigList (entry past the end): node unusable" },
            { "AAb+CgACAAA=", "ech= not an ECHConfigList (only 0xfe0a): node unusable" },
        };
        for (size_t i = 0; i < sizeof bad_ech / sizeof *bad_ech; i++) {
            snprintf(q, sizeof q, "security=tls&sni=t.example&ech=%s", bad_ech[i][0]);
            check(bad_ech[i][1], url(q, &n) == 1);
            check_s("  skip reason named", "ech: not a base64 ECHConfigList", n.skip_reason);
        }
        check("ech= as 'domain+https://...' (a DNS lookup): node unusable",
              url("security=tls&sni=t.example&ech=cloudflare-ech.com%2Bhttps://1.1.1.1/dns-query", &n) == 1);
        check_s("  skip reason named", "ech: DNS lookup is not supported", n.skip_reason);
        check("ech is ignored for reality",
              url("security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=0123&ech=AAAA", &n) == 0);

        char js[1200];
        snprintf(js, sizeof js,
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"x.example\",\"port\":443,"
            "\"users\":[{\"id\":\"" UUID "\"}]}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"tls\","
            "\"tlsSettings\":{\"serverName\":\"x.example\",\"echConfigList\":\"%s\"}}}]}", ECH);
        struct vless_node out[2];
        struct vless_sub_stats st;
        size_t cnt = vless_parse_sub(js, out, 2, &st);
        check("Xray JSON: echConfigList", cnt == 1 && out[0].ech && !strcmp(out[0].ech, ECH));
        char y[900];
        snprintf(y, sizeof y,
            "proxies:\n  - name: c1\n    type: vless\n    server: x.example\n    port: 443\n    uuid: " UUID "\n"
            "    network: tcp\n    tls: true\n    servername: x.example\n    ech-opts:\n      enable: true\n      config: %s\n", ECH);
        cnt = vless_parse_sub(y, out, 2, &st);
        check("Clash: ech-opts.config", cnt == 1 && out[0].ech && !strcmp(out[0].ech, ECH));
        char sb[1300];
        snprintf(sb, sizeof sb,
            "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"a\",\"server\":\"x.example\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"tls\":{\"enabled\":true,\"server_name\":\"x.example\",\"ech\":{\"enabled\":true,\"config\":["
            "\"-----BEGIN ECH CONFIGS-----\",\"%s\",\"-----END ECH CONFIGS-----\"]}}}]}", ECH);
        cnt = vless_parse_sub(sb, out, 2, &st);
        check("sing-box: ech.config (PEM lines)", cnt == 1 && out[0].ech && !strcmp(out[0].ech, ECH));
        static const char *sb2 =
            "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"a\",\"server\":\"x.example\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"tls\":{\"enabled\":true,\"server_name\":\"x.example\",\"ech\":{\"enabled\":true}}}]}";
        check("sing-box: ech without config (a DNS lookup): node skipped", vless_parse_sub(sb2, out, 2, &st) == 0 && st.skipped == 1);
    }

    printf(g_fail ? "FAILED: %d (passed %d)\n" : "subpq: all matched (%d checks)\n", g_fail ? g_fail : g_pass, g_pass);
    return g_fail ? 1 : 0;
}
