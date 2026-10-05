#include "greatest.h"

#include <string.h>

#include "firc/ifacename.h"

/* Catches: an interface name with a newline accepted into the iptables transcript. */
TEST a_name_that_could_write_a_line_of_its_own_is_not_a_name(void) {
    ASSERT_FALSEm("a newline ends the rule and starts a command",
                  firc_is_interface_name("eth0\n-F FORWARD"));
    ASSERT_FALSEm("a carriage return does the same to some parsers",
                  firc_is_interface_name("eth0\r-F FORWARD"));
    ASSERT_FALSEm("a space splits one argument into two",
                  firc_is_interface_name("eth0 -j ACCEPT"));
    ASSERT_FALSEm("a tab is a space to the parser", firc_is_interface_name("eth0\t-j"));
    ASSERT_FALSEm("a quote is not punctuation an interface has",
                  firc_is_interface_name("eth0\"x"));
    ASSERT_FALSE(firc_is_interface_name("eth0;reboot"));
    ASSERT_FALSE(firc_is_interface_name("eth0$(id)"));
    ASSERT_FALSE(firc_is_interface_name("eth0\x01"));
    PASS();
}

TEST the_names_real_interfaces_have_are_names(void) {
    ASSERT(firc_is_interface_name("eth0"));
    ASSERT(firc_is_interface_name("ppp0"));
    ASSERT(firc_is_interface_name("br0"));
    ASSERT(firc_is_interface_name("opkgtun10"));
    ASSERT(firc_is_interface_name("eth0.100"));
    ASSERT(firc_is_interface_name("wg-home"));
    ASSERT(firc_is_interface_name("z2ktun0"));
    ASSERT(firc_is_interface_name("bond_0"));
    ASSERT(firc_is_interface_name("veth@if3"));
    ASSERT_FALSEm("an alias label is not an interface name",
                  firc_is_interface_name("eth0:1"));
    PASS();
}

/* Catches: a name of IFNAMSIZ bytes or more, ".", or ".." accepted. */
TEST the_kernels_own_edges(void) {
    ASSERT_FALSEm("empty is not a name", firc_is_interface_name(""));
    ASSERT_FALSE(firc_is_interface_name(NULL));
    ASSERT_FALSEm("sysfs has a directory by that name", firc_is_interface_name("."));
    ASSERT_FALSE(firc_is_interface_name(".."));

    char fifteen[16];
    memset(fifteen, 'e', 15);
    fifteen[15] = '\0';
    ASSERTm("fifteen bytes and a terminator is what IFNAMSIZ allows",
            firc_is_interface_name(fifteen));

    char sixteen[17];
    memset(sixteen, 'e', 16);
    sixteen[16] = '\0';
    ASSERT_FALSEm("sixteen is one too many", firc_is_interface_name(sixteen));
    PASS();
}

/* Catches: a refused name logged raw, splitting the log line in two. */
TEST a_refused_name_cannot_forge_a_log_line(void) {
    char out[32];

    firc_interface_name_for_log("eth0\n-A FORWARD -j ACCEPT", out, sizeof(out));
    ASSERT_STR_EQm("the newline is the whole point", "eth0?-A FORWARD -j ACCEPT", out);

    firc_interface_name_for_log("a\rb\tc\033[2J", out, sizeof(out));
    ASSERT_STR_EQm("a carriage return, a tab and an escape are lines too", "a?b?c?[2J", out);

    char big[80];
    memset(big, 'e', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    firc_interface_name_for_log(big, out, sizeof(out));
    ASSERT_EQ_FMTm("truncated to cap-1", (size_t)31, strlen(out), "%zu");

    out[0] = 'x';
    firc_interface_name_for_log(NULL, out, sizeof(out));
    ASSERT_STR_EQm("no name is the empty one", "", out);
    char one[1] = {'x'};
    firc_interface_name_for_log("abc", one, sizeof(one));
    ASSERT_EQ_FMTm("a buffer with room for nothing gets the terminator", '\0', one[0], "%d");
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_name_that_could_write_a_line_of_its_own_is_not_a_name);
    RUN_TEST(the_names_real_interfaces_have_are_names);
    RUN_TEST(the_kernels_own_edges);
    RUN_TEST(a_refused_name_cannot_forge_a_log_line);
    GREATEST_MAIN_END();
}
