#include "commlib.h"


bool isBlacklistedApp(const char* identifier);
bool isBlacklistedPath(const char* path);

bool isBlacklistedToken(audit_token_t* token);
bool isBlacklistedPid(pid_t pid);

pid_t* allocBlacklistProcessId();
void commitBlacklistProcessId(pid_t* pidp);
