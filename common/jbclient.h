#ifndef JBCLIENT_H
#define JBCLIENT_H

#include <xpc/xpc.h>
#include <stdint.h>

#define JBS_DOMAIN_ROOTHIDE 5

enum {
    JBS_ROOTHIDE_JAILBROKEN_CHECK=1,
    JBS_ROOTHIDE_PALEHIDE_PRESENT,
    JBS_ROOTHIDE_BLACKLIST_CHECK,
    JBS_ROOTHIDE_JAILBREAKD_LOOKUP,
    JBS_ROOTHIDE_JAILBREAKD_CHECKIN,
};

void jbclient_xpc_set_custom_port(mach_port_t serverPort);

bool jbclient_palehide_present();
bool jbclient_roothide_jailbroken();
mach_port_t jbclient_jailbreakd_lookup();
mach_port_t jbclient_jailbreakd_checkin();
bool jbclient_blacklist_check_pid(pid_t pid);
bool jbclient_blacklist_check_path(const char* path);
bool jbclient_blacklist_check_bundle(const char* bundle);

#endif
