#define _DEFAULT_SOURCE

#include "greatest.h"

#include <stddef.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_tcpudp.h>

#include "../../src/xtables/abi.h"

#define KERNEL_ALIGN(s) (((s) + __alignof__(struct _xt_align) - 1) & ~((size_t)__alignof__(struct _xt_align) - 1))

/* Catches: firc's ipt_entry drifting from the kernel's (a field moved, the counters not 8-aligned). */
_Static_assert((sizeof(struct ipt_ip)) == (sizeof(xt_ipt_ip_t)), "abi mismatch");
_Static_assert((offsetof(struct ipt_ip, dst)) == (offsetof(xt_ipt_ip_t, dst)), "abi mismatch");
_Static_assert((offsetof(struct ipt_ip, dmsk)) == (offsetof(xt_ipt_ip_t, dmsk)), "abi mismatch");
_Static_assert((offsetof(struct ipt_ip, iniface)) == (offsetof(xt_ipt_ip_t, iniface)), "abi mismatch");
_Static_assert((offsetof(struct ipt_ip, outiface)) == (offsetof(xt_ipt_ip_t, outiface)), "abi mismatch");
_Static_assert((offsetof(struct ipt_ip, iniface_mask)) == (offsetof(xt_ipt_ip_t, iniface_mask)), "abi mismatch");
_Static_assert((offsetof(struct ipt_ip, outiface_mask)) == (offsetof(xt_ipt_ip_t, outiface_mask)), "abi mismatch");
_Static_assert((offsetof(struct ipt_ip, proto)) == (offsetof(xt_ipt_ip_t, proto)), "abi mismatch");
_Static_assert((offsetof(struct ipt_ip, flags)) == (offsetof(xt_ipt_ip_t, flags)), "abi mismatch");
_Static_assert((offsetof(struct ipt_ip, invflags)) == (offsetof(xt_ipt_ip_t, invflags)), "abi mismatch");
_Static_assert((sizeof(struct ipt_entry)) == (sizeof(xt_ipt_entry_t)), "abi mismatch");
_Static_assert((offsetof(struct ipt_entry, nfcache)) == (offsetof(xt_ipt_entry_t, nfcache)), "abi mismatch");
_Static_assert((offsetof(struct ipt_entry, target_offset)) == (offsetof(xt_ipt_entry_t, target_offset)), "abi mismatch");
_Static_assert((offsetof(struct ipt_entry, next_offset)) == (offsetof(xt_ipt_entry_t, next_offset)), "abi mismatch");
_Static_assert((offsetof(struct ipt_entry, comefrom)) == (offsetof(xt_ipt_entry_t, comefrom)), "abi mismatch");
_Static_assert((offsetof(struct ipt_entry, counters)) == (offsetof(xt_ipt_entry_t, counters)), "abi mismatch");
/* Catches: firc's ip6t_entry drifting from the kernel's (the in6_addr alignment lost, so the entry shrinks). */
_Static_assert((sizeof(struct ip6t_ip6)) == (sizeof(xt_ip6t_ip6_t)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_ip6, dst)) == (offsetof(xt_ip6t_ip6_t, dst)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_ip6, iniface)) == (offsetof(xt_ip6t_ip6_t, iniface)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_ip6, outiface)) == (offsetof(xt_ip6t_ip6_t, outiface)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_ip6, outiface_mask)) == (offsetof(xt_ip6t_ip6_t, outiface_mask)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_ip6, proto)) == (offsetof(xt_ip6t_ip6_t, proto)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_ip6, tos)) == (offsetof(xt_ip6t_ip6_t, tos)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_ip6, flags)) == (offsetof(xt_ip6t_ip6_t, flags)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_ip6, invflags)) == (offsetof(xt_ip6t_ip6_t, invflags)), "abi mismatch");
_Static_assert((sizeof(struct ip6t_entry)) == (sizeof(xt_ip6t_entry_t)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_entry, nfcache)) == (offsetof(xt_ip6t_entry_t, nfcache)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_entry, target_offset)) == (offsetof(xt_ip6t_entry_t, target_offset)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_entry, next_offset)) == (offsetof(xt_ip6t_entry_t, next_offset)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_entry, comefrom)) == (offsetof(xt_ip6t_entry_t, comefrom)), "abi mismatch");
_Static_assert((offsetof(struct ip6t_entry, counters)) == (offsetof(xt_ip6t_entry_t, counters)), "abi mismatch");
/* Catches: a header the sockopts read at the wrong offset (num_counters, the counters pointer, the entries). */
_Static_assert((sizeof(struct ipt_getinfo)) == (sizeof(xt_getinfo_t)), "abi mismatch");
_Static_assert((sizeof(struct ipt_getinfo)) == ((size_t)XT_GETINFO_LEN), "abi mismatch");
_Static_assert((offsetof(struct ipt_getinfo, hook_entry)) == (offsetof(xt_getinfo_t, hook_entry)), "abi mismatch");
_Static_assert((offsetof(struct ipt_getinfo, underflow)) == (offsetof(xt_getinfo_t, underflow)), "abi mismatch");
_Static_assert((offsetof(struct ipt_getinfo, num_entries)) == (offsetof(xt_getinfo_t, num_entries)), "abi mismatch");
_Static_assert((offsetof(struct ipt_getinfo, size)) == (offsetof(xt_getinfo_t, size)), "abi mismatch");
_Static_assert((sizeof(struct ip6t_getinfo)) == (sizeof(xt_getinfo_t)), "abi mismatch");
_Static_assert((offsetof(struct ipt_get_entries, size)) == (offsetof(xt_get_entries_hdr_t, size)), "abi mismatch");
_Static_assert((offsetof(struct ipt_get_entries, entrytable)) == ((size_t)XT_GET_ENTRIES_HDR_LEN), "abi mismatch");
_Static_assert((offsetof(struct ip6t_get_entries, entrytable)) == ((size_t)XT_GET_ENTRIES_HDR_LEN), "abi mismatch");
_Static_assert((offsetof(struct ipt_replace, valid_hooks)) == (offsetof(xt_replace_hdr_t, valid_hooks)), "abi mismatch");
_Static_assert((offsetof(struct ipt_replace, num_entries)) == (offsetof(xt_replace_hdr_t, num_entries)), "abi mismatch");
_Static_assert((offsetof(struct ipt_replace, size)) == (offsetof(xt_replace_hdr_t, size)), "abi mismatch");
_Static_assert((offsetof(struct ipt_replace, hook_entry)) == (offsetof(xt_replace_hdr_t, hook_entry)), "abi mismatch");
_Static_assert((offsetof(struct ipt_replace, underflow)) == (offsetof(xt_replace_hdr_t, underflow)), "abi mismatch");
_Static_assert((offsetof(struct ipt_replace, num_counters)) == (offsetof(xt_replace_hdr_t, num_counters)), "abi mismatch");
_Static_assert((offsetof(struct ipt_replace, counters)) == (offsetof(xt_replace_hdr_t, counters)), "abi mismatch");
_Static_assert((offsetof(struct ipt_replace, entries)) == ((size_t)XT_REPLACE_HDR_LEN), "abi mismatch");
_Static_assert((offsetof(struct ip6t_replace, entries)) == ((size_t)XT_REPLACE_HDR_LEN), "abi mismatch");
_Static_assert((offsetof(struct xt_counters_info, num_counters)) == (offsetof(xt_counters_info_hdr_t, num_counters)), "abi mismatch");
_Static_assert((offsetof(struct xt_counters_info, counters)) == ((size_t)XT_COUNTERS_INFO_HDR_LEN), "abi mismatch");
_Static_assert((sizeof(struct xt_counters)) == (sizeof(xt_counters_t)), "abi mismatch");
_Static_assert((sizeof(struct xt_get_revision)) == (sizeof(xt_get_revision_t)), "abi mismatch");
/* Catches: an extension payload of the wrong size, which the kernel refuses with EINVAL at checkentry. */
_Static_assert((sizeof(struct xt_entry_match)) == ((size_t)XT_MATCH_HDR_LEN), "abi mismatch");
_Static_assert((sizeof(struct xt_entry_target)) == (sizeof(xt_ext_hdr_t)), "abi mismatch");
_Static_assert((KERNEL_ALIGN(sizeof(struct xt_standard_target))) == ((size_t)XT_STANDARD_TARGET_LEN), "abi mismatch");
_Static_assert((KERNEL_ALIGN(sizeof(struct xt_error_target))) == ((size_t)XT_ERROR_TARGET_LEN), "abi mismatch");
_Static_assert((offsetof(struct xt_standard_target, verdict)) == (offsetof(xt_standard_target_t, verdict)), "abi mismatch");
_Static_assert((offsetof(struct xt_error_target, errorname)) == (offsetof(xt_error_target_t, errorname)), "abi mismatch");
_Static_assert((sizeof(struct xt_mark_mtinfo1)) == (sizeof(xt_mark_mtinfo1_t)), "abi mismatch");
_Static_assert((sizeof(struct xt_tcp)) == (sizeof(xt_tcp_t)), "abi mismatch");
_Static_assert((sizeof(struct xt_udp)) == (sizeof(xt_udp_t)), "abi mismatch");
_Static_assert((sizeof(struct nf_nat_ipv4_multi_range_compat)) == (sizeof(xt_nat_ipv4_compat_t)), "abi mismatch");
_Static_assert((offsetof(struct nf_nat_ipv4_range, min_ip)) == (offsetof(xt_nat_ipv4_range_t, min_ip)), "abi mismatch");
_Static_assert((offsetof(struct nf_nat_ipv4_range, min)) == (offsetof(xt_nat_ipv4_range_t, min_port)), "abi mismatch");
#ifdef NF_NAT_RANGE_PROTO_RANDOM_FULLY
_Static_assert((sizeof(struct nf_nat_range)) == (sizeof(xt_nat_range_t)), "abi mismatch");
_Static_assert((offsetof(struct nf_nat_range, min_addr)) == (offsetof(xt_nat_range_t, min_addr)), "abi mismatch");
_Static_assert((offsetof(struct nf_nat_range, min_proto)) == (offsetof(xt_nat_range_t, min_proto)), "abi mismatch");
#endif
/* Catches: a sockopt number, verdict or flag copied wrong (a GET_REVISION asked as a match, ACCEPT as DROP). */
_Static_assert((IPT_SO_SET_REPLACE) == (XT_SO_SET_REPLACE), "abi mismatch");
_Static_assert((IPT_SO_SET_ADD_COUNTERS) == (XT_SO_SET_ADD_COUNTERS), "abi mismatch");
_Static_assert((IPT_SO_GET_INFO) == (XT_SO_GET_INFO), "abi mismatch");
_Static_assert((IPT_SO_GET_ENTRIES) == (XT_SO_GET_ENTRIES), "abi mismatch");
_Static_assert((IPT_SO_GET_REVISION_MATCH) == (XT_SO_GET_REVISION_MATCH4), "abi mismatch");
_Static_assert((IPT_SO_GET_REVISION_TARGET) == (XT_SO_GET_REVISION_TARGET4), "abi mismatch");
_Static_assert((IP6T_SO_SET_REPLACE) == (XT_SO_SET_REPLACE), "abi mismatch");
_Static_assert((IP6T_SO_SET_ADD_COUNTERS) == (XT_SO_SET_ADD_COUNTERS), "abi mismatch");
_Static_assert((IP6T_SO_GET_INFO) == (XT_SO_GET_INFO), "abi mismatch");
_Static_assert((IP6T_SO_GET_ENTRIES) == (XT_SO_GET_ENTRIES), "abi mismatch");
_Static_assert((IP6T_SO_GET_REVISION_MATCH) == (XT_SO_GET_REVISION_MATCH6), "abi mismatch");
_Static_assert((IP6T_SO_GET_REVISION_TARGET) == (XT_SO_GET_REVISION_TARGET6), "abi mismatch");
_Static_assert((SOL_IP) == (XT_SOL_IP), "abi mismatch");
_Static_assert((SOL_IPV6) == (XT_SOL_IPV6), "abi mismatch");
_Static_assert((-NF_DROP - 1) == (XT_VERDICT_DROP), "abi mismatch");
_Static_assert((-NF_ACCEPT - 1) == (XT_VERDICT_ACCEPT), "abi mismatch");
_Static_assert((XT_RETURN) == (XT_VERDICT_RETURN), "abi mismatch");
_Static_assert((IPT_F_GOTO) == (XT_IPT_F_GOTO), "abi mismatch");
_Static_assert((IP6T_F_PROTO) == (XT_IP6T_F_PROTO), "abi mismatch");
_Static_assert((IP6T_F_GOTO) == (XT_IP6T_F_GOTO), "abi mismatch");
_Static_assert((NF_NAT_RANGE_MAP_IPS) == (XT_NAT_MAP_IPS), "abi mismatch");
_Static_assert((NF_NAT_RANGE_PROTO_SPECIFIED) == (XT_NAT_PROTO_SPECIFIED), "abi mismatch");
_Static_assert((XT_EXTENSION_MAXNAMELEN) == (XT_NAME_LEN), "abi mismatch");
_Static_assert((XT_TABLE_MAXNAMELEN) == (XT_TABLE_LEN), "abi mismatch");
_Static_assert((XT_FUNCTION_MAXNAMELEN) == (XT_ERRORNAME_LEN), "abi mismatch");

_Static_assert(offsetof(struct xt_entry_match, u.user.revision) == offsetof(xt_ext_hdr_t, revision), "abi mismatch");
_Static_assert(offsetof(struct xt_entry_target, u.user.revision) == offsetof(xt_ext_hdr_t, revision), "abi mismatch");
_Static_assert(offsetof(struct xt_entry_match, u.user.name) == offsetof(xt_ext_hdr_t, name), "abi mismatch");
_Static_assert(offsetof(struct xt_entry_match, u.user.match_size) == offsetof(xt_ext_hdr_t, size), "abi mismatch");
_Static_assert(offsetof(struct xt_entry_target, u.user.target_size) == offsetof(xt_ext_hdr_t, size), "abi mismatch");
_Static_assert(offsetof(struct xt_standard_target, verdict) == 32, "abi mismatch");
_Static_assert(offsetof(struct xt_get_revision, name) == offsetof(xt_get_revision_t, name), "abi mismatch");
_Static_assert(offsetof(struct xt_get_revision, revision) == offsetof(xt_get_revision_t, revision), "abi mismatch");
_Static_assert(offsetof(struct xt_mark_mtinfo1, mark) == offsetof(xt_mark_mtinfo1_t, mark), "abi mismatch");
_Static_assert(offsetof(struct xt_mark_mtinfo1, mask) == offsetof(xt_mark_mtinfo1_t, mask), "abi mismatch");
_Static_assert(offsetof(struct xt_mark_mtinfo1, invert) == offsetof(xt_mark_mtinfo1_t, invert), "abi mismatch");
_Static_assert(offsetof(struct xt_tcp, spts) == offsetof(xt_tcp_t, spts), "abi mismatch");
_Static_assert(offsetof(struct xt_tcp, dpts) == offsetof(xt_tcp_t, dpts), "abi mismatch");
_Static_assert(offsetof(struct xt_tcp, option) == offsetof(xt_tcp_t, option), "abi mismatch");
_Static_assert(offsetof(struct xt_tcp, flg_mask) == offsetof(xt_tcp_t, flg_mask), "abi mismatch");
_Static_assert(offsetof(struct xt_tcp, flg_cmp) == offsetof(xt_tcp_t, flg_cmp), "abi mismatch");
_Static_assert(offsetof(struct xt_tcp, invflags) == offsetof(xt_tcp_t, invflags), "abi mismatch");
_Static_assert(offsetof(struct xt_udp, spts) == offsetof(xt_udp_t, spts), "abi mismatch");
_Static_assert(offsetof(struct xt_udp, dpts) == offsetof(xt_udp_t, dpts), "abi mismatch");
_Static_assert(offsetof(struct xt_udp, invflags) == offsetof(xt_udp_t, invflags), "abi mismatch");
_Static_assert(offsetof(struct ip6t_ip6, src) == offsetof(xt_ip6t_ip6_t, src), "abi mismatch");
_Static_assert(offsetof(struct ip6t_ip6, smsk) == offsetof(xt_ip6t_ip6_t, smsk), "abi mismatch");
_Static_assert(offsetof(struct ip6t_ip6, dmsk) == offsetof(xt_ip6t_ip6_t, dmsk), "abi mismatch");
_Static_assert(offsetof(struct ip6t_ip6, iniface_mask) == offsetof(xt_ip6t_ip6_t, iniface_mask), "abi mismatch");
_Static_assert(offsetof(struct ipt_ip, src) == offsetof(xt_ipt_ip_t, src), "abi mismatch");
_Static_assert(offsetof(struct ipt_ip, smsk) == offsetof(xt_ipt_ip_t, smsk), "abi mismatch");
_Static_assert(offsetof(struct xt_counters, pcnt) == offsetof(xt_counters_t, pcnt), "abi mismatch");
_Static_assert(offsetof(struct xt_counters, bcnt) == offsetof(xt_counters_t, bcnt), "abi mismatch");
_Static_assert(offsetof(struct ipt_getinfo, name) == offsetof(xt_getinfo_t, name), "abi mismatch");
_Static_assert(offsetof(struct ipt_getinfo, valid_hooks) == offsetof(xt_getinfo_t, valid_hooks), "abi mismatch");
_Static_assert(offsetof(struct ipt_get_entries, name) == offsetof(xt_get_entries_hdr_t, name), "abi mismatch");
_Static_assert(offsetof(struct ipt_replace, name) == offsetof(xt_replace_hdr_t, name), "abi mismatch");
_Static_assert(offsetof(struct ipt_entry, ip) == offsetof(xt_ipt_entry_t, ip), "abi mismatch");
_Static_assert(offsetof(struct ip6t_entry, ipv6) == offsetof(xt_ip6t_entry_t, ipv6), "abi mismatch");

/* Catches: the file-scope layout asserts being compiled out of the harness. */
TEST the_layout_asserts_compiled(void) {
    ASSERT_EQ(32u, (unsigned)offsetof(xt_standard_target_t, verdict));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_layout_asserts_compiled);
    GREATEST_MAIN_END();
}
