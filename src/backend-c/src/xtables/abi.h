#ifndef FIRC_XTABLES_ABI_H
#define FIRC_XTABLES_ABI_H

#include <stddef.h>
#include <stdint.h>

#define XT_ALIGN8(n) (((n) + 7u) & ~7u)
#define XT_NAME_LEN 29
#define XT_TABLE_LEN 32
#define XT_CHAIN_LEN 32
#define XT_ERRORNAME_LEN 30
#define XT_NUMHOOKS 5

#define XT_SO_SET_REPLACE 64
#define XT_SO_SET_ADD_COUNTERS 65
#define XT_SO_GET_INFO 64
#define XT_SO_GET_ENTRIES 65
#define XT_SO_GET_REVISION_MATCH4 66
#define XT_SO_GET_REVISION_TARGET4 67
#define XT_SO_GET_REVISION_MATCH6 68
#define XT_SO_GET_REVISION_TARGET6 69
#define XT_SOL_IP 0
#define XT_SOL_IPV6 41

#define XT_VERDICT_DROP (-1)
#define XT_VERDICT_ACCEPT (-2)
#define XT_VERDICT_RETURN (-5)

#define XT_IPT_F_GOTO 0x02u
#define XT_IP6T_F_PROTO 0x01u
#define XT_IP6T_F_GOTO 0x04u

#define XT_NAT_MAP_IPS 0x1u
#define XT_NAT_PROTO_SPECIFIED 0x2u

#define XT_MATCH_HDR_LEN 32u
#define XT_STANDARD_TARGET_LEN 40u
#define XT_ERROR_TARGET_LEN 64u
#define XT_REPLACE_HDR_LEN 96u
#define XT_GET_ENTRIES_HDR_LEN 40u
#define XT_COUNTERS_INFO_HDR_LEN 40u
#define XT_GETINFO_LEN 84u

typedef struct firc_xt_counters {
    uint64_t pcnt, bcnt;
} xt_counters_t;

typedef struct firc_xt_ipt_ip {
    uint8_t src[4], dst[4], smsk[4], dmsk[4];
    char iniface[16], outiface[16];
    uint8_t iniface_mask[16], outiface_mask[16];
    uint16_t proto;
    uint8_t flags, invflags;
} xt_ipt_ip_t;

typedef struct firc_xt_ipt_entry {
    xt_ipt_ip_t ip;
    uint32_t nfcache;
    uint16_t target_offset, next_offset;
    uint32_t comefrom;
    _Alignas(8) xt_counters_t counters;
} xt_ipt_entry_t;

typedef struct firc_xt_ip6t_ip6 {
    _Alignas(4) uint8_t src[16];
    uint8_t dst[16], smsk[16], dmsk[16];
    char iniface[16], outiface[16];
    uint8_t iniface_mask[16], outiface_mask[16];
    uint16_t proto;
    uint8_t tos, flags, invflags;
} xt_ip6t_ip6_t;

typedef struct firc_xt_ip6t_entry {
    xt_ip6t_ip6_t ipv6;
    uint32_t nfcache;
    uint16_t target_offset, next_offset;
    uint32_t comefrom;
    _Alignas(8) xt_counters_t counters;
} xt_ip6t_entry_t;

typedef struct firc_xt_ext_hdr {
    uint16_t size;
    char name[XT_NAME_LEN];
    uint8_t revision;
} xt_ext_hdr_t;

typedef struct firc_xt_standard_target {
    xt_ext_hdr_t hdr;
    int32_t verdict;
} xt_standard_target_t;

typedef struct firc_xt_error_target {
    xt_ext_hdr_t hdr;
    char errorname[XT_ERRORNAME_LEN];
} xt_error_target_t;

typedef struct firc_xt_getinfo {
    char name[XT_TABLE_LEN];
    uint32_t valid_hooks;
    uint32_t hook_entry[XT_NUMHOOKS];
    uint32_t underflow[XT_NUMHOOKS];
    uint32_t num_entries;
    uint32_t size;
} xt_getinfo_t;

typedef struct firc_xt_get_entries_hdr {
    char name[XT_TABLE_LEN];
    uint32_t size;
} xt_get_entries_hdr_t;

typedef struct firc_xt_replace_hdr {
    char name[XT_TABLE_LEN];
    uint32_t valid_hooks;
    uint32_t num_entries;
    uint32_t size;
    uint32_t hook_entry[XT_NUMHOOKS];
    uint32_t underflow[XT_NUMHOOKS];
    uint32_t num_counters;
    xt_counters_t *counters;
} xt_replace_hdr_t;

typedef struct firc_xt_counters_info_hdr {
    char name[XT_TABLE_LEN];
    uint32_t num_counters;
} xt_counters_info_hdr_t;

typedef struct firc_xt_get_revision {
    char name[XT_NAME_LEN];
    uint8_t revision;
} xt_get_revision_t;

typedef struct firc_xt_mark_mtinfo1 {
    uint32_t mark, mask;
    uint8_t invert;
} xt_mark_mtinfo1_t;

typedef struct firc_xt_tcp {
    uint16_t spts[2], dpts[2];
    uint8_t option, flg_mask, flg_cmp, invflags;
} xt_tcp_t;

typedef struct firc_xt_udp {
    uint16_t spts[2], dpts[2];
    uint8_t invflags;
} xt_udp_t;

typedef struct firc_xt_nat_ipv4_range {
    uint32_t flags;
    uint8_t min_ip[4], max_ip[4];
    uint16_t min_port, max_port;
} xt_nat_ipv4_range_t;

typedef struct firc_xt_nat_ipv4_compat {
    uint32_t rangesize;
    xt_nat_ipv4_range_t range[1];
} xt_nat_ipv4_compat_t;

typedef struct firc_xt_nat_range {
    uint32_t flags;
    _Alignas(4) uint8_t min_addr[16];
    uint8_t max_addr[16];
    uint16_t min_proto, max_proto;
} xt_nat_range_t;

_Static_assert(sizeof(xt_ipt_ip_t) == 84, "ipt_ip is 84 bytes");
_Static_assert(offsetof(xt_ipt_ip_t, proto) == 80, "ipt_ip.proto at 80");
_Static_assert(sizeof(xt_ipt_entry_t) == 112, "ipt_entry is 112 bytes");
_Static_assert(offsetof(xt_ipt_entry_t, nfcache) == 84, "ipt_entry.nfcache at 84");
_Static_assert(offsetof(xt_ipt_entry_t, target_offset) == 88, "ipt_entry.target_offset at 88");
_Static_assert(offsetof(xt_ipt_entry_t, next_offset) == 90, "ipt_entry.next_offset at 90");
_Static_assert(offsetof(xt_ipt_entry_t, comefrom) == 92, "ipt_entry.comefrom at 92");
_Static_assert(offsetof(xt_ipt_entry_t, counters) == 96, "ipt_entry.counters at 96");
_Static_assert(sizeof(xt_ip6t_ip6_t) == 136, "ip6t_ip6 is 136 bytes");
_Static_assert(offsetof(xt_ip6t_ip6_t, proto) == 128, "ip6t_ip6.proto at 128");
_Static_assert(offsetof(xt_ip6t_ip6_t, flags) == 131, "ip6t_ip6.flags at 131");
_Static_assert(sizeof(xt_ip6t_entry_t) == 168, "ip6t_entry is 168 bytes");
_Static_assert(offsetof(xt_ip6t_entry_t, target_offset) == 140, "ip6t_entry.target_offset at 140");
_Static_assert(offsetof(xt_ip6t_entry_t, next_offset) == 142, "ip6t_entry.next_offset at 142");
_Static_assert(offsetof(xt_ip6t_entry_t, comefrom) == 144, "ip6t_entry.comefrom at 144");
_Static_assert(offsetof(xt_ip6t_entry_t, counters) == 152, "ip6t_entry.counters at 152");
_Static_assert(sizeof(xt_counters_t) == 16, "xt_counters is 16 bytes");
_Static_assert(sizeof(xt_ext_hdr_t) == 32, "xt_entry_match/target header is 32 bytes");
_Static_assert(XT_ALIGN8(sizeof(xt_standard_target_t)) == XT_STANDARD_TARGET_LEN, "standard target is 40");
_Static_assert(XT_ALIGN8(sizeof(xt_error_target_t)) == XT_ERROR_TARGET_LEN, "error target is 64");
_Static_assert(sizeof(xt_getinfo_t) == XT_GETINFO_LEN, "ipt_getinfo is 84 bytes");
_Static_assert(offsetof(xt_get_entries_hdr_t, size) == 32, "ipt_get_entries.size at 32");
_Static_assert(offsetof(xt_replace_hdr_t, num_counters) == 84, "ipt_replace.num_counters at 84");
_Static_assert(offsetof(xt_replace_hdr_t, counters) == 88, "ipt_replace.counters at 88");
_Static_assert(sizeof(xt_replace_hdr_t) <= XT_REPLACE_HDR_LEN, "ipt_replace header fits in 96");
_Static_assert(offsetof(xt_counters_info_hdr_t, num_counters) == 32, "xt_counters_info.num_counters at 32");
_Static_assert(sizeof(xt_get_revision_t) == 30, "xt_get_revision is 30 bytes");
_Static_assert(sizeof(xt_mark_mtinfo1_t) == 12, "xt_mark_mtinfo1 is 12 bytes");
_Static_assert(sizeof(xt_tcp_t) == 12, "xt_tcp is 12 bytes");
_Static_assert(sizeof(xt_udp_t) == 10, "xt_udp is 10 bytes");
_Static_assert(sizeof(xt_nat_ipv4_compat_t) == 20, "nf_nat_ipv4_multi_range_compat is 20 bytes");
_Static_assert(sizeof(xt_nat_range_t) == 40, "nf_nat_range is 40 bytes");

_Static_assert(offsetof(xt_standard_target_t, verdict) == 32, "standard target verdict at 32");
_Static_assert(offsetof(xt_replace_hdr_t, valid_hooks) == 32, "ipt_replace.valid_hooks at 32");
_Static_assert(offsetof(xt_replace_hdr_t, hook_entry) == 44, "ipt_replace.hook_entry at 44");
_Static_assert(offsetof(xt_replace_hdr_t, underflow) == 64, "ipt_replace.underflow at 64");
_Static_assert(offsetof(xt_getinfo_t, hook_entry) == 36, "ipt_getinfo.hook_entry at 36");
_Static_assert(offsetof(xt_getinfo_t, underflow) == 56, "ipt_getinfo.underflow at 56");
_Static_assert(offsetof(xt_getinfo_t, size) == 80, "ipt_getinfo.size at 80");

#endif
