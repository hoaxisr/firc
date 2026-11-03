#include <stdio.h>
#include <string.h>
#include "unit.h"
#include "xhopts.h"
#include "xhreq.h"

static char why[96];

static int parse(const char *xhx, const char *mode, const char *headers, uint16_t pad_to, struct xh_opts *o) {
    why[0] = '\0';
    return xh_opts_parse(xhx, mode, headers, pad_to, o, why, sizeof why);
}

static void check_why(const char *what, const char *want) {
    check_str(what, want, why);
}

static void t_defaults_differ_from_xray(void) {
    struct xh_opts o;
    check("defaults: parse", 0, parse(NULL, "", "", 0, &o));
    check("defaults: session in path", XHP_PATH, o.sess_place);
    check("defaults: seq in path", XHP_PATH, o.seq_place);
    check("defaults: data auto", XHP_AUTO, o.data_place);
    check("defaults: padding queryInHeader", XHP_QUERY_IN_HEADER, o.pad_place);
    check_str("defaults: method", "POST", o.method);
    check_str("defaults: table", "", o.table);
    check_str("defaults: padding key", "x_padding", o.pad_key);
    check_str("defaults: padding header", "X-Padding", o.pad_header);
    check_str("defaults: data key", "X-Data", o.data_key);
    check_str("defaults: session key", "", o.sess_key);
    check("defaults: obfs off", 0, o.obfs);
    check("defaults: repeat-x", 0, o.tokenish);
    check("defaults: chunk from scMaxEachPostBytes", 0, (long)o.chunk_to);
    check("empty string: parse", 0, parse("", "", "", 0, &o));
    check("empty string: session in path", XHP_PATH, o.sess_place);
}

static void t_header_keys_swapped_per_placement(void) {
    struct xh_opts o;
    check("header/cookie: parse", 0, parse("sessionIDPlacement=header\nseqPlacement=cookie\n", "", "", 0, &o));
    check("header/cookie: session header", XHP_HEADER, o.sess_place);
    check("header/cookie: seq cookie", XHP_COOKIE, o.seq_place);
    check_str("header/cookie: session key", "X-Session", o.sess_key);
    check_str("header/cookie: seq key", "x_seq", o.seq_key);
    check("query/header: parse", 0, parse("sessionIDPlacement=query\nseqPlacement=header\n", "", "", 0, &o));
    check_str("query/header: session key", "x_session", o.sess_key);
    check_str("query/header: seq key", "X-Seq", o.seq_key);
    check("seqKey given: parse", 0, parse("seqPlacement=query\nseqKey=n\n", "", "", 0, &o));
    check_str("seqKey given: key", "n", o.seq_key);
}

static void t_old_session_names_ignored_or_winning(void) {
    struct xh_opts o;
    check("both names: parse", 0, parse("sessionPlacement=query\nsessionIDPlacement=header\n", "", "", 0, &o));
    check("both names: sessionID wins", XHP_HEADER, o.sess_place);
    check_str("both names: key for header", "X-Session", o.sess_key);
    check("both names other order: parse", 0, parse("sessionIDPlacement=header\nsessionPlacement=query\n", "", "", 0, &o));
    check("both names other order: sessionID wins", XHP_HEADER, o.sess_place);
    check("old names: parse", 0, parse("sessionPlacement=cookie\nsessionKey=sk\n", "", "", 0, &o));
    check("old names: cookie", XHP_COOKIE, o.sess_place);
    check_str("old names: key", "sk", o.sess_key);
    check("both keys: parse", 0, parse("sessionPlacement=cookie\nsessionIDKey=new\nsessionKey=old\n", "", "", 0, &o));
    check_str("both keys: sessionIDKey wins", "new", o.sess_key);
}

static void t_data_placement_outside_packet_up(void) {
    struct xh_opts o;
    const char *modes[] = { "", "auto", "stream-up" };
    for (int i = 0; i < 3; i++) {
        char what[64];
        snprintf(what, sizeof what, "data header mode '%s': refused", modes[i]);
        check(what, -1, parse("uplinkDataPlacement=header\n", modes[i], "", 0, &o));
        check_why("data header: reason", "xhttp: uplinkDataPlacement needs mode=packet-up");
    }
    check("data cookie stream-one: refused", -1, parse("uplinkDataPlacement=cookie\n", "stream-one", "", 0, &o));
    check("data header packet-up: parse", 0, parse("uplinkDataPlacement=header\n", "packet-up", "", 0, &o));
    check("data header packet-up: header", XHP_HEADER, o.data_place);
    check_str("data header packet-up: key", "X-Data", o.data_key);
    check("data header packet-up: chunk from", 3000, (long)o.chunk_from);
    check("data header packet-up: chunk to", 4000, (long)o.chunk_to);
    check("data cookie packet-up: parse", 0, parse("uplinkDataPlacement=cookie\n", "packet-up", "", 0, &o));
    check_str("data cookie packet-up: key", "x_data", o.data_key);
    check("data cookie packet-up: chunk from", 2048, (long)o.chunk_from);
    check("data cookie packet-up: chunk to", 3072, (long)o.chunk_to);
    check("data body any mode: parse", 0, parse("uplinkDataPlacement=body\n", "stream-up", "", 0, &o));
    check("data body: body", XHP_BODY, o.data_place);
    check("data body: chunk from scMaxEachPostBytes", 0, (long)o.chunk_to);
}

static void t_get_outside_packet_up(void) {
    struct xh_opts o;
    check("get auto: refused", -1, parse("uplinkHTTPMethod=get\n", "", "", 0, &o));
    check_why("get auto: reason", "xhttp: uplinkHTTPMethod needs mode=packet-up");
    check("get packet-up: parse", 0, parse("uplinkHTTPMethod=get\n", "packet-up", "", 0, &o));
    check_str("get packet-up: upper-cased", "GET", o.method);
    check("put stream-up: parse", 0, parse("uplinkHTTPMethod=put\n", "stream-up", "", 0, &o));
    check_str("put stream-up: upper-cased", "PUT", o.method);
    check("method with a space: refused", -1, parse("uplinkHTTPMethod=PO ST\n", "packet-up", "", 0, &o));
}

static void t_chunk_floor_missing(void) {
    struct xh_opts o;
    check("chunk 10-20: parse", 0, parse("uplinkChunkSize=10-20\n", "", "", 0, &o));
    check("chunk 10-20: from", 64, (long)o.chunk_from);
    check("chunk 10-20: to", 64, (long)o.chunk_to);
    check("chunk 10-100: parse", 0, parse("uplinkChunkSize=10-100\n", "", "", 0, &o));
    check("chunk 10-100: from", 64, (long)o.chunk_from);
    check("chunk 10-100: to", 100, (long)o.chunk_to);
    check("chunk 500: parse", 0, parse("uplinkChunkSize=500\n", "", "", 0, &o));
    check("chunk 500: from", 500, (long)o.chunk_from);
    check("chunk 500: to", 500, (long)o.chunk_to);
    check("chunk given beats header default: parse", 0,
          parse("uplinkDataPlacement=header\nuplinkChunkSize=100-200\n", "packet-up", "", 0, &o));
    check("chunk given beats header default: from", 100, (long)o.chunk_from);
    check("chunk given beats header default: to", 200, (long)o.chunk_to);
    check("chunk 0 is not given: parse", 0, parse("uplinkDataPlacement=cookie\nuplinkChunkSize=0\n", "packet-up", "", 0, &o));
    check("chunk 0 is not given: cookie default", 2048, (long)o.chunk_from);
}

static int all_in(const char *s, const char *set) {
    for (; *s; s++) if (!strchr(set, *s)) return 0;
    return 1;
}

static void t_table_room_and_alphabet(void) {
    struct xh_opts o;
    check("hex 8: parse", 0, parse("sessionIDTable=hex\nsessionIDLength=8\n", "", "", 0, &o));
    check_str("hex 8: resolved table", "0123456789abcdef", o.table);
    int bad = 0;
    for (int i = 0; i < 100; i++) {
        char id[160];
        xh_session_id(&o, id, sizeof id);
        if (strlen(id) != 8 || !all_in(id, "0123456789abcdef")) bad++;
    }
    check("hex 8: 100 ids of 8 hex chars", 0, bad);
    check("hex 7: refused", -1, parse("sessionIDTable=hex\nsessionIDLength=7\n", "", "", 0, &o));
    check_why("hex 7: reason", "xhttp: sessionIDTable or sessionIDLength is too small");
    check("number 9-10: parse", 0, parse("sessionIDTable=number\nsessionIDLength=9-10\n", "", "", 0, &o));
    check("number 9-10: from", 9, o.id_len_from);
    check("number 9-10: to", 10, o.id_len_to);
    int lens = 0;
    for (int i = 0; i < 100; i++) {
        char id[160];
        xh_session_id(&o, id, sizeof id);
        size_t n = strlen(id);
        if ((n == 9 || n == 10) && all_in(id, "0123456789")) lens++;
    }
    check("number 9-10: 100 ids of 9 or 10 digits", 100, lens);
    check("number 9: refused", -1, parse("sessionIDTable=number\nsessionIDLength=9\n", "", "", 0, &o));
    check("table without length: refused", -1, parse("sessionIDTable=hex\n", "", "", 0, &o));
    check_why("table without length: reason", "xhttp: sessionIDTable or sessionIDLength is too small");
    check("non-ascii byte: refused", -1, parse("sessionIDTable=abcdefghij\xc3\xa9klmnop\nsessionIDLength=10\n", "", "", 0, &o));
    check("literal table: parse", 0, parse("sessionIDTable=abc._~-XYZ0\nsessionIDLength=10\n", "", "", 0, &o));
    check_str("literal table: kept", "abc._~-XYZ0", o.table);
    check("ALPHABET 7: parse", 0, parse("sessionIDTable=ALPHABET\nsessionIDLength=7\n", "", "", 0, &o));
    check_str("ALPHABET 7: resolved", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", o.table);
    check("ALPHABET 6: refused", -1, parse("sessionIDTable=ALPHABET\nsessionIDLength=6\n", "", "", 0, &o));
    check("from 0 with room: refused", -1, parse("sessionIDTable=hex\nsessionIDLength=0-10\n", "", "", 0, &o));
    check("length over 128: refused", -1, parse("sessionIDTable=hex\nsessionIDLength=8-129\n", "", "", 0, &o));
    check("length 128: parse", 0, parse("sessionIDTable=hex\nsessionIDLength=128\n", "", "", 0, &o));
    char id[160];
    xh_session_id(&o, id, sizeof id);
    check("length 128: id of 128", 128, (long)strlen(id));
}

static void t_uuid_id_shape(void) {
    struct xh_opts o;
    parse(NULL, "", "", 0, &o);
    char id[64];
    xh_session_id(&o, id, sizeof id);
    check("uuid: 36 chars", 36, (long)strlen(id));
    check("uuid: dashes", 1, id[8] == '-' && id[13] == '-' && id[18] == '-' && id[23] == '-');
    check("uuid: version 4", '4', id[14]);
    check("uuid: variant", 1, strchr("89ab", id[19]) != NULL);
    char id2[64];
    xh_session_id(&o, id2, sizeof id2);
    check("uuid: two differ", 1, strcmp(id, id2) != 0);
    parse("sessionIDLength=8\n", "", "", 0, &o);
    xh_session_id(&o, id, sizeof id);
    check("length without table: uuid", 36, (long)strlen(id));
}

static void t_padding_length_or_charset(void) {
    struct xh_opts o;
    parse(NULL, "", "", 0, &o);
    char p[2048];
    size_t n = xh_padding(&o, 37, p, sizeof p);
    check("repeat-x 37: length", 37, (long)n);
    check("repeat-x 37: all X", 1, strspn(p, "X") == 37 && p[37] == '\0');
    check("repeat-x 0: empty", 0, (long)xh_padding(&o, 0, p, sizeof p));
    check("tokenish: parse", 0, parse("xPaddingObfsMode=true\nxPaddingMethod=tokenish\n", "", "", 0, &o));
    check("tokenish: flag", 1, o.tokenish);
    check("tokenish: obfs", 1, o.obfs);
    int bad = 0;
    for (int i = 0; i < 50; i++) {
        n = xh_padding(&o, 100, p, sizeof p);
        size_t h = xh_huff_len(p, n);
        if (n != strlen(p) || !all_in(p, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") || h < 98 || h > 102)
            bad++;
    }
    check("tokenish 100: 50 paddings base62 with huffman 98..102", 0, bad);
    n = xh_padding(&o, 1000, p, 11);
    check("tokenish: cut to the buffer", 10, (long)n);
    check("tokenish: cut is terminated", 10, (long)strlen(p));
}

static void t_huff_len_table_or_rounding(void) {
    check("huff XXXX", 4, (long)xh_huff_len("XXXX", 4));
    check("huff XZ", 2, (long)xh_huff_len("XZ", 2));
    check("huff aceiost", 5, (long)xh_huff_len("aceiost", 7));
    check("huff 012", 2, (long)xh_huff_len("012", 3));
    check("huff 3", 1, (long)xh_huff_len("3", 1));
    check("huff empty", 0, (long)xh_huff_len("", 0));
    check("huff A (6 bits)", 1, (long)xh_huff_len("A", 1));
    check("huff BC (7+7 bits)", 2, (long)xh_huff_len("BC", 2));
    check("huff 0x00 (13 bits)", 2, (long)xh_huff_len("\0", 1));
    check("huff 0xff (26 bits)", 4, (long)xh_huff_len("\xff", 1));
}

static void t_truncated_unsafe_or_unswapped(void) {
    struct xh_opts o;
    char x[200];
    snprintf(x, sizeof x, "sessionIDPlacement=header\nsessionIDKey=%064d\n", 0);
    check("64-char key: refused", -1, parse(x, "", "", 0, &o));
    snprintf(x, sizeof x, "sessionIDPlacement=header\nsessionIDKey=%063d\n", 0);
    check("63-char key: parse", 0, parse(x, "", "", 0, &o));
    check("63-char key: kept", 63, (long)strlen(o.sess_key));
    check("table with slash: refused", -1, parse("sessionIDTable=ab/c\nsessionIDLength=40\n", "", "", 0, &o));
    check_why("table with slash: reason", "xhttp: unsupported sessionIDTable: ab/c");
    check("chunk 200-100: parse", 0, parse("uplinkChunkSize=200-100\n", "", "", 0, &o));
    check("chunk 200-100: from", 100, (long)o.chunk_from);
    check("chunk 200-100: to", 200, (long)o.chunk_to);
    check("length 10-9 number: parse", 0, parse("sessionIDTable=number\nsessionIDLength=10-9\n", "", "", 0, &o));
    check("length 10-9 number: from", 9, o.id_len_from);
    check("16-char method: refused", -1, parse("uplinkHTTPMethod=ABCDEFGHIJKLMNOP\n", "stream-up", "", 0, &o));
    check("range junk: refused", -1, parse("uplinkChunkSize=1x\n", "", "", 0, &o));
    check("range 3 parts: refused", -1, parse("uplinkChunkSize=1-2-3\n", "", "", 0, &o));
}

static void t_ua_profile_we_lack(void) {
    struct xh_opts o;
    check("ua firefox: refused", -1, parse(NULL, "", "User-Agent: firefox\n", 0, &o));
    check_why("ua firefox: reason", "xhttp: unsupported User-Agent profile: firefox");
    check("ua lower-case name, golang: refused", -1, parse(NULL, "", "Accept: */*\nuser-agent: golang\n", 0, &o));
    check("ua safari: refused", -1, parse(NULL, "", "User-Agent: safari\n", 0, &o));
    check("ua curl: refused", -1, parse(NULL, "", "User-Agent: curl\n", 0, &o));
    check("ua chrome: parse", 0, parse(NULL, "", "User-Agent: chrome\n", 0, &o));
    check("ua edge: parse", 0, parse(NULL, "", "User-Agent: edge\n", 0, &o));
    check("ua literal: parse", 0, parse(NULL, "", "User-Agent: Mozilla/5.0 firefox\n", 0, &o));
    check("firefox in another header: parse", 0, parse(NULL, "", "X-UA: firefox\n", 0, &o));
    check("no headers: parse", 0, parse(NULL, "", NULL, 0, &o));
}

static void t_ua_profile_case_folded(void) {
    struct xh_opts o;
    check("ua Firefox: parse", 0, parse(NULL, "", "User-Agent: Firefox\n", 0, &o));
    check("ua Golang: parse", 0, parse(NULL, "", "User-Agent: Golang\n", 0, &o));
    check("ua CURL: parse", 0, parse(NULL, "", "User-Agent: CURL\n", 0, &o));
    check("ua firefox after Firefox: refused", -1, parse(NULL, "", "User-Agent: firefox\n", 0, &o));
}

static void t_length_limit_without_table(void) {
    struct xh_opts o;
    char id[64];
    check("length 200 without table: parse", 0, parse("sessionIDLength=200\n", "", "", 0, &o));
    xh_session_id(&o, id, sizeof id);
    check("length 200 without table: uuid", 36, (long)strlen(id));
    check("length 8-70000 without table: parse", 0, parse("sessionIDLength=8-70000\n", "", "", 0, &o));
    xh_session_id(&o, id, sizeof id);
    check("length 8-70000 without table: uuid", 36, (long)strlen(id));
    check("length 129 with table: refused", -1, parse("sessionIDTable=hex\nsessionIDLength=129\n", "", "", 0, &o));
    check_why("length 129 with table: reason", "xhttp: unsupported sessionIDLength: 129");
}

static void t_id_length_draw_stuck(void) {
    struct xh_opts o;
    check("number 9-10 draw: parse", 0, parse("sessionIDTable=number\nsessionIDLength=9-10\n", "", "", 0, &o));
    char id[64];
    int nine = 0, ten = 0, other = 0;
    for (int i = 0; i < 100; i++) {
        xh_session_id(&o, id, sizeof id);
        size_t n = strlen(id);
        if (n == 9) nine++;
        else if (n == 10) ten++;
        else other++;
    }
    check("number 9-10 draw: 9 seen", 1, nine > 0);
    check("number 9-10 draw: 10 seen", 1, ten > 0);
    check("number 9-10 draw: nothing else", 0, other);
}

static void t_header_key_not_a_token(void) {
    struct xh_opts o;
    check("session header key with space: refused", -1,
          parse("sessionIDPlacement=header\nsessionIDKey=X Sess\n", "", "", 0, &o));
    check_why("session header key with space: reason", "xhttp: unsupported sessionIDKey: X Sess");
    check("old session header key with ':': refused", -1,
          parse("sessionPlacement=header\nsessionKey=X:S\n", "", "", 0, &o));
    check_why("old session header key with ':': reason", "xhttp: unsupported sessionKey: X:S");
    check("seq header key with ':': refused", -1, parse("seqPlacement=header\nseqKey=X:Seq\n", "", "", 0, &o));
    check_why("seq header key with ':': reason", "xhttp: unsupported seqKey: X:Seq");
    check("data header key with space: refused", -1,
          parse("uplinkDataPlacement=header\nuplinkDataKey=X Data\n", "packet-up", "", 0, &o));
    check_why("data header key with space: reason", "xhttp: unsupported uplinkDataKey: X Data");
    check("padding header with ':': refused", -1,
          parse("xPaddingObfsMode=true\nxPaddingPlacement=header\nxPaddingHeader=X:P\n", "", "", 0, &o));
    check_why("padding header with ':': reason", "xhttp: unsupported xPaddingHeader: X:P");
    check("padding queryInHeader header with space: refused", -1,
          parse("xPaddingObfsMode=true\nxPaddingHeader=X P\n", "", "", 0, &o));
    check_why("padding queryInHeader header with space: reason", "xhttp: unsupported xPaddingHeader: X P");
    check("lower-case token header key: parse", 0,
          parse("sessionIDPlacement=header\nsessionIDKey=x-sess_1~!\n", "", "", 0, &o));
    check("session query key with space: parse", 0,
          parse("sessionIDPlacement=query\nsessionIDKey=a b\n", "", "", 0, &o));
    check("seq cookie key: parse", 0, parse("seqPlacement=cookie\nseqKey=sq\n", "", "", 0, &o));
    check("padding header unused without obfs: parse", 0,
          parse("xPaddingPlacement=header\nxPaddingHeader=X P\n", "", "", 0, &o));
}

static void t_unknown_values_accepted(void) {
    struct xh_opts o;
    check("method zigzag: refused", -1, parse("xPaddingMethod=zigzag\n", "", "", 0, &o));
    check_why("method zigzag: reason", "xhttp: unsupported xPaddingMethod: zigzag");
    check("seq body: refused", -1, parse("seqPlacement=body\n", "", "", 0, &o));
    check_why("seq body: reason", "xhttp: unsupported seqPlacement: body");
    check("download: not an xhttp key", -1, parse("downloadSettings=present\n", "", "", 0, &o));
    check_why("download: reason", "xhttp: unsupported xhttp key: downloadSettings=present");
    check("session body: refused", -1, parse("sessionIDPlacement=body\n", "", "", 0, &o));
    check("data path: refused", -1, parse("uplinkDataPlacement=path\n", "packet-up", "", 0, &o));
    check("padding placement body: refused", -1, parse("xPaddingPlacement=body\n", "", "", 0, &o));
    check("obfs yes: refused", -1, parse("xPaddingObfsMode=yes\n", "", "", 0, &o));
    check("unknown key: refused", -1, parse("noSuchKey=1\n", "", "", 0, &o));
    check("line without '=': refused", -1, parse("sessionIDPlacement\n", "", "", 0, &o));
    char x[200];
    snprintf(x, sizeof x, "seqPlacement=%0150d\n", 0);
    check("long value: refused", -1, parse(x, "", "", 0, &o));
    check("long value: reason cut to fit", sizeof why - 1, (long)strlen(why));
    check("long value: reason starts right", 0, strncmp(why, "xhttp: unsupported seqPlacement: 000", 36));
    check("padding placements: parse", 0,
          parse("xPaddingObfsMode=true\nxPaddingPlacement=cookie\nxPaddingKey=pk\nxPaddingHeader=Ph\n", "", "", 0, &o));
    check("padding placements: cookie", XHP_COOKIE, o.pad_place);
    check_str("padding placements: key", "pk", o.pad_key);
    check_str("padding placements: header", "Ph", o.pad_header);
    check("padding header: parse", 0, parse("xPaddingPlacement=header\n", "", "", 0, &o));
    check("padding header: header", XHP_HEADER, o.pad_place);
    check("obfs false: parse", 0, parse("xPaddingObfsMode=false\n", "", "", 0, &o));
    check("obfs false: off", 0, o.obfs);
}

static void t_buffered_posts_read_or_refused(void) {
    struct xh_opts o;
    check("posts 40: parse", 0, parse("scMaxBufferedPosts=40\n", "packet-up", "", 0, &o));
    check("posts 40: kept", 40, (long)o.posts);
    check("posts absent: parse", 0, parse("", "packet-up", "", 0, &o));
    check("posts absent: 0", 0, (long)o.posts);
    check("posts 0: parse", 0, parse("scMaxBufferedPosts=0\n", "packet-up", "", 0, &o));
    check("posts 0: not given", 0, (long)o.posts);
    check("posts abc: refused", -1, parse("scMaxBufferedPosts=abc\n", "packet-up", "", 0, &o));
    check_why("posts abc: reason", "xhttp: unsupported scMaxBufferedPosts: abc");
    check("posts -5: refused", -1, parse("scMaxBufferedPosts=-5\n", "packet-up", "", 0, &o));
}

static void t_no_grpc_header_read_or_refused(void) {
    struct xh_opts o;
    /* catches: noGRPCHeader not read, read inverted, or a non-bool value taken */
    check("noGRPCHeader true: parse", 0, parse("noGRPCHeader=true\n", "stream-up", "", 0, &o));
    check("noGRPCHeader true: set", 1, o.no_grpc);
    check("noGRPCHeader false: parse", 0, parse("noGRPCHeader=false\n", "stream-up", "", 0, &o));
    check("noGRPCHeader false: clear", 0, o.no_grpc);
    check("noGRPCHeader absent: clear", 0, (parse("", "stream-up", "", 0, &o), o.no_grpc));
    check("noGRPCHeader yes: refused", -1, parse("noGRPCHeader=yes\n", "stream-up", "", 0, &o));
    check_why("noGRPCHeader yes: reason", "xhttp: unsupported noGRPCHeader: yes");
    check("noGRPCHeader 1: refused", -1, parse("noGRPCHeader=1\n", "", "", 0, &o));
}

static void t_server_max_header_bytes_read_or_refused(void) {
    struct xh_opts o;
    /* catches: serverMaxHeaderBytes not read, or a value that is not a non-negative integer taken */
    check("serverMaxHeaderBytes 4096: parse", 0, parse("serverMaxHeaderBytes=4096\n", "packet-up", "", 0, &o));
    check("serverMaxHeaderBytes 4096: kept", 4096, (long)o.max_hdr);
    check("serverMaxHeaderBytes 0: parse", 0, parse("serverMaxHeaderBytes=0\n", "packet-up", "", 0, &o));
    check("serverMaxHeaderBytes 0: 0", 0, (long)o.max_hdr);
    check("serverMaxHeaderBytes absent: 0", 0, (parse("", "", "", 0, &o), (long)o.max_hdr));
    check("serverMaxHeaderBytes -1: refused", -1, parse("serverMaxHeaderBytes=-1\n", "", "", 0, &o));
    check_why("serverMaxHeaderBytes -1: reason", "xhttp: unsupported serverMaxHeaderBytes: -1");
    check("serverMaxHeaderBytes 4k: refused", -1, parse("serverMaxHeaderBytes=4k\n", "", "", 0, &o));
    check("serverMaxHeaderBytes 1-2: refused", -1, parse("serverMaxHeaderBytes=1-2\n", "", "", 0, &o));
}

static void t_min_posts_interval_accepted_or_refused(void) {
    struct xh_opts o;
    /* catches: scMinPostsIntervalMs refused as an unknown key, or a value that is not a range taken */
    check("scMinPostsIntervalMs 30: parse", 0, parse("scMinPostsIntervalMs=30\n", "packet-up", "", 0, &o));
    check("scMinPostsIntervalMs 10-50: parse", 0, parse("scMinPostsIntervalMs=10-50\n", "packet-up", "", 0, &o));
    check("scMinPostsIntervalMs 50-10: parse", 0, parse("scMinPostsIntervalMs=50-10\n", "packet-up", "", 0, &o));
    check("scMinPostsIntervalMs abc: refused", -1, parse("scMinPostsIntervalMs=abc\n", "packet-up", "", 0, &o));
    check_why("scMinPostsIntervalMs abc: reason", "xhttp: unsupported scMinPostsIntervalMs: abc");
    check("scMinPostsIntervalMs 10-: refused", -1, parse("scMinPostsIntervalMs=10-\n", "packet-up", "", 0, &o));
    /* catches: a negative interval refused although Xray takes it, or a form Xray refuses taken */
    static const char *const ok[] = { "-1", "-5--1", "-114-514", "5--1", "+5", "0" };
    static const char *const bad[] = { "-", "--5", "5-", "-5-", "1-2-3", "1.5", "-5-x" };
    char line[64], what[96];
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        snprintf(line, sizeof line, "scMinPostsIntervalMs=%s\n", ok[i]);
        snprintf(what, sizeof what, "scMinPostsIntervalMs %s: parse", ok[i]);
        check(what, 0, parse(line, "packet-up", "", 0, &o));
    }
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        snprintf(line, sizeof line, "scMinPostsIntervalMs=%s\n", bad[i]);
        snprintf(what, sizeof what, "scMinPostsIntervalMs %s: refused", bad[i]);
        check(what, -1, parse(line, "packet-up", "", 0, &o));
    }
}

static void t_min_posts_interval_values(void) {
    struct xh_opts o;
    static const struct { const char *line; int32_t from, to; } c[] = {
        { "", 30, 30 }, { "scMinPostsIntervalMs=0\n", 30, 30 }, { "scMinPostsIntervalMs=10-50\n", 10, 50 },
        { "scMinPostsIntervalMs=50-10\n", 10, 50 }, { "scMinPostsIntervalMs=-1\n", -1, -1 },
        { "scMinPostsIntervalMs=-5-0\n", 30, 30 }, { "scMinPostsIntervalMs=100\n", 100, 100 },
    };
    char what[96];
    /* catches: the interval ignored, its absent or zero-ended default not 30 ms, or a range not swapped */
    for (size_t i = 0; i < sizeof c / sizeof *c; i++) {
        parse(c[i].line, "packet-up", "", 0, &o);
        snprintf(what, sizeof what, "interval '%.30s': from", c[i].line);
        check(what, c[i].from, o.interval.from);
        snprintf(what, sizeof what, "interval '%.30s': to", c[i].line);
        check(what, c[i].to, o.interval.to);
    }
}

static void t_query_padding_overflows_path(void) {
    struct xh_opts o;
    check("query pad 1368: parse", 0, parse("xPaddingObfsMode=true\nxPaddingPlacement=query\n", "", "", 1368, &o));
    check("query pad 1368: query", XHP_QUERY, o.pad_place);
    check("query pad 1369: refused", -1, parse("xPaddingObfsMode=true\nxPaddingPlacement=query\n", "", "", 1369, &o));
    check_why("query pad 1369: reason", "xhttp: padding too long for the path");
    check("query pad without obfs: parse", 0, parse("xPaddingPlacement=query\n", "", "", 4000, &o));
    check("header pad 4000: parse", 0, parse("xPaddingObfsMode=true\nxPaddingPlacement=header\n", "", "", 4000, &o));
    check("tokenish query pad 1368: refused", -1,
          parse("xPaddingObfsMode=true\nxPaddingPlacement=query\nxPaddingMethod=tokenish\n", "", "", 1368, &o));
    check("tokenish query pad 900: parse", 0,
          parse("xPaddingObfsMode=true\nxPaddingPlacement=query\nxPaddingMethod=tokenish\n", "", "", 900, &o));
    check("tokenish query pad 974: parse", 0,
          parse("xPaddingObfsMode=true\nxPaddingPlacement=query\nxPaddingMethod=tokenish\n", "", "", 974, &o));
    check("tokenish query pad 975: refused", -1,
          parse("xPaddingObfsMode=true\nxPaddingPlacement=query\nxPaddingMethod=tokenish\n", "", "", 975, &o));
}

static void t_xmux_parse(void) {
    struct xh_opts o;
    /* catches: an xmux key read into the wrong field, or one value read as a range */
    check("xmux parse: rc", 0,
          parse("xmux.maxConcurrency=16-32\nxmux.cMaxReuseTimes=8\nxmux.hKeepAlivePeriod=-1\n", "", "", 0, &o));
    check("xmux parse: maxConcurrency from", 16, o.xmux.max_conc.from);
    check("xmux parse: maxConcurrency to", 32, o.xmux.max_conc.to);
    check("xmux parse: cMaxReuseTimes from", 8, o.xmux.c_reuse.from);
    check("xmux parse: cMaxReuseTimes to", 8, o.xmux.c_reuse.to);
    check("xmux parse: hKeepAlivePeriod", -1, (long)o.xmux.keepalive_s);
    check("xmux parse: maxConnections from", 0, o.xmux.max_conns.from);
    check("xmux parse: maxConnections to", 0, o.xmux.max_conns.to);
    check("xmux parse: set", 1, o.xmux.set);
    check("xmux parse: hMaxRequestTimes untouched", 0, o.xmux.h_reqs.to);
    check("xmux parse: hMaxReusableSecs untouched", 0, o.xmux.h_secs.to);
    check("xmux parse rest: rc", 0,
          parse("xmux.hMaxRequestTimes=7\nxmux.hMaxReusableSecs=-3-9\n", "", "", 0, &o));
    check("xmux parse rest: hMaxRequestTimes", 7, o.xmux.h_reqs.from);
    check("xmux parse rest: hMaxReusableSecs from", -3, o.xmux.h_secs.from);
    check("xmux parse rest: hMaxReusableSecs to", 9, o.xmux.h_secs.to);
    check("xmux parse rest: maxConcurrency untouched", 0, o.xmux.max_conc.to);
    check("xmux absent: rc", 0, parse("seqKey=q\n", "", "", 0, &o));
    check("xmux absent: not set", 0, o.xmux.set);
    check("xmux abc: refused", -1, parse("xmux.cMaxReuseTimes=abc\n", "", "", 0, &o));
    check_why("xmux abc: reason", "xhttp: unsupported xmux.cMaxReuseTimes: abc");
}

static void t_xmux_swap(void) {
    struct xh_opts o;
    /* catches: Xray's swap missing */
    check("xmux swap: rc", 0, parse("xmux.hMaxRequestTimes=900-600\n", "", "", 0, &o));
    check("xmux swap: from", 600, o.xmux.h_reqs.from);
    check("xmux swap: to", 900, o.xmux.h_reqs.to);
}

static void t_xmux_both_refused(void) {
    struct xh_opts o;
    /* catches: the refusal tested on from instead of to, or hidden by the clamp */
    check("xmux 4 with 2: refused", -1, parse("xmux.maxConcurrency=4\nxmux.maxConnections=2\n", "", "", 0, &o));
    check_why("xmux 4 with 2: reason", "xhttp: maxConnections cannot be specified together with maxConcurrency");
    check("xmux 0-4 with 0-2: refused", -1, parse("xmux.maxConcurrency=0-4\nxmux.maxConnections=0-2\n", "", "", 0, &o));
    check("xmux 0 with 3: parse", 0, parse("xmux.maxConcurrency=0\nxmux.maxConnections=3\n", "", "", 0, &o));
    check("xmux 4 with 40: refused", -1, parse("xmux.maxConcurrency=4\nxmux.maxConnections=40\n", "", "", 0, &o));
}

static void t_xmux_cap(void) {
    static const struct { const char *v; int32_t from, to; } rows[] = {
        { "16", 16, 16 }, { "17", 16, 16 }, { "20-40", 16, 17 }, { "16-18", 16, 17 },
    };
    struct xh_opts o;
    struct xm_cfg e;
    char line[64], what[96];
    /* catches: a refusal instead of the clamp, or a draw above 16 */
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        snprintf(line, sizeof line, "xmux.maxConnections=%s\n", rows[i].v);
        snprintf(what, sizeof what, "xmux cap %s: usable", rows[i].v);
        check(what, 0, parse(line, "", "", 0, &o));
        xm_cfg_effective(&o.xmux, &e);
        snprintf(what, sizeof what, "xmux cap %s: from", rows[i].v);
        check(what, rows[i].from, e.max_conns.from);
        snprintf(what, sizeof what, "xmux cap %s: to", rows[i].v);
        check(what, rows[i].to, e.max_conns.to);
    }
}

static void t_xmux_keepalive_one_number(void) {
    struct xh_opts o;
    /* catches: a range accepted where Xray has an int64 */
    check("xmux keepalive 1-2: refused", -1, parse("xmux.hKeepAlivePeriod=1-2\n", "", "", 0, &o));
    check_why("xmux keepalive 1-2: reason", "xhttp: unsupported xmux.hKeepAlivePeriod: 1-2");
    check("xmux keepalive 30s: refused", -1, parse("xmux.hKeepAlivePeriod=30s\n", "", "", 0, &o));
    check("xmux keepalive 45: parse", 0, parse("xmux.hKeepAlivePeriod=45\n", "", "", 0, &o));
    check("xmux keepalive 45: kept", 45, (long)o.xmux.keepalive_s);
}

static void t_xmux_defaults(void) {
    struct xh_opts o;
    struct xm_cfg e;
    /* catches: defaults applied over a set field, or not applied to an all-zero struct */
    check("xmux defaults none: parse", 0, parse("", "", "", 0, &o));
    xm_cfg_effective(&o.xmux, &e);
    check("xmux defaults none: maxConnections from", 3, e.max_conns.from);
    check("xmux defaults none: maxConnections to", 3, e.max_conns.to);
    check("xmux defaults none: hMaxRequestTimes from", 600, e.h_reqs.from);
    check("xmux defaults none: hMaxRequestTimes to", 900, e.h_reqs.to);
    check("xmux defaults none: hMaxReusableSecs from", 1800, e.h_secs.from);
    check("xmux defaults none: hMaxReusableSecs to", 3000, e.h_secs.to);
    check("xmux defaults none: maxConcurrency from", 0, e.max_conc.from);
    check("xmux defaults none: maxConcurrency to", 0, e.max_conc.to);
    check("xmux defaults none: cMaxReuseTimes from", 0, e.c_reuse.from);
    check("xmux defaults none: cMaxReuseTimes to", 0, e.c_reuse.to);
    check("xmux defaults none: keepalive", 0, (long)e.keepalive_s);
    check("xmux defaults reuse: parse", 0, parse("xmux.cMaxReuseTimes=5\n", "", "", 0, &o));
    xm_cfg_effective(&o.xmux, &e);
    check("xmux defaults reuse: maxConnections from", 0, e.max_conns.from);
    check("xmux defaults reuse: maxConnections to", 0, e.max_conns.to);
    check("xmux defaults reuse: hMaxRequestTimes from", 0, e.h_reqs.from);
    check("xmux defaults reuse: hMaxRequestTimes to", 0, e.h_reqs.to);
    check("xmux defaults reuse: hMaxReusableSecs to", 0, e.h_secs.to);
    check("xmux defaults reuse: cMaxReuseTimes from", 5, e.c_reuse.from);
    check("xmux defaults reuse: cMaxReuseTimes to", 5, e.c_reuse.to);
    check("xmux defaults keepalive: parse", 0, parse("xmux.hKeepAlivePeriod=30\n", "", "", 0, &o));
    xm_cfg_effective(&o.xmux, &e);
    check("xmux defaults keepalive: maxConnections to", 0, e.max_conns.to);
    check("xmux defaults keepalive: hMaxRequestTimes to", 0, e.h_reqs.to);
    check("xmux defaults keepalive: kept", 30, (long)e.keepalive_s);
    check("xmux defaults zero: parse", 0, parse("xmux.maxConnections=0\n", "", "", 0, &o));
    check("xmux defaults zero: set", 1, o.xmux.set);
    xm_cfg_effective(&o.xmux, &e);
    check("xmux defaults zero: maxConnections from", 3, e.max_conns.from);
    check("xmux defaults zero: maxConnections to", 3, e.max_conns.to);
    check("xmux defaults zero: hMaxRequestTimes from", 600, e.h_reqs.from);
    check("xmux defaults zero: hMaxReusableSecs to", 3000, e.h_secs.to);
}

int main(void) {
    t_defaults_differ_from_xray();
    t_header_keys_swapped_per_placement();
    t_old_session_names_ignored_or_winning();
    t_data_placement_outside_packet_up();
    t_get_outside_packet_up();
    t_chunk_floor_missing();
    t_table_room_and_alphabet();
    t_uuid_id_shape();
    t_padding_length_or_charset();
    t_huff_len_table_or_rounding();
    t_truncated_unsafe_or_unswapped();
    t_ua_profile_we_lack();
    t_ua_profile_case_folded();
    t_length_limit_without_table();
    t_id_length_draw_stuck();
    t_header_key_not_a_token();
    t_unknown_values_accepted();
    t_query_padding_overflows_path();
    t_buffered_posts_read_or_refused();
    t_no_grpc_header_read_or_refused();
    t_server_max_header_bytes_read_or_refused();
    t_min_posts_interval_accepted_or_refused();
    t_min_posts_interval_values();
    t_xmux_parse();
    t_xmux_swap();
    t_xmux_both_refused();
    t_xmux_cap();
    t_xmux_keepalive_one_number();
    t_xmux_defaults();
    return unit_done("xhoptsmatch");
}
