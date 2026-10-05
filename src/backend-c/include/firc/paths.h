#ifndef FIRC_PATHS_H
#define FIRC_PATHS_H

#if defined(FIRC_PLATFORM_ENTWARE)

#ifndef FIRC_APP_SHARE_DIR
#define FIRC_APP_SHARE_DIR "/opt/usr/share/firc"
#endif
#ifndef FIRC_APP_CONF_DIR
#define FIRC_APP_CONF_DIR "/opt/etc/firc"
#endif
/* Run dir (tmpfs): pool file, instance lock, API socket; the netfilter.d hook and S99firc repeat the socket path. */
#ifndef FIRC_APP_RUN_DIR
#define FIRC_APP_RUN_DIR "/tmp/firc"
#endif
#ifndef FIRC_SOCK_PATH
#define FIRC_SOCK_PATH FIRC_APP_RUN_DIR "/firc.sock"
#endif
#ifndef FIRC_PASSWD_FILE
#define FIRC_PASSWD_FILE "/opt/etc/passwd"
#endif
#ifndef FIRC_SHADOW_FILE
#define FIRC_SHADOW_FILE "/opt/etc/shadow"
#endif
/* Run by POST /api/v1/system/restart; its boot loop watches the daemon only in the first five minutes of uptime. */
#ifndef FIRC_INIT_SCRIPT
#define FIRC_INIT_SCRIPT "/opt/etc/init.d/S99firc"
#endif

#else

#ifndef FIRC_APP_SHARE_DIR
#define FIRC_APP_SHARE_DIR "/usr/share/firc"
#endif
#ifndef FIRC_APP_CONF_DIR
#define FIRC_APP_CONF_DIR "/etc/firc"
#endif
#ifndef FIRC_APP_RUN_DIR
#define FIRC_APP_RUN_DIR "/run/firc"
#endif
#ifndef FIRC_SOCK_PATH
#define FIRC_SOCK_PATH FIRC_APP_RUN_DIR "/firc.sock"
#endif
#ifndef FIRC_PASSWD_FILE
#define FIRC_PASSWD_FILE "/etc/passwd"
#endif
#ifndef FIRC_SHADOW_FILE
#define FIRC_SHADOW_FILE "/etc/shadow"
#endif
#ifndef FIRC_INIT_SCRIPT
#define FIRC_INIT_SCRIPT "/opt/etc/init.d/S99firc"
#endif

#endif

#ifndef FIRC_CONFIG_PATH
#define FIRC_CONFIG_PATH FIRC_APP_CONF_DIR "/firc.conf"
#endif
#ifndef FIRC_FAKEIP_V6_PREFIX_FILE
#define FIRC_FAKEIP_V6_PREFIX_FILE FIRC_APP_CONF_DIR "/v6-pool-prefix"
#endif

#endif
