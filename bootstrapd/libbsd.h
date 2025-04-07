
int bsd_enableJIT();
int bsd_enableJIT2(pid_t pid);

const char* bsd_getsbtoken();

int bsd_opensshcheck();
int bsd_opensshctl(bool run);

int bsd_checkServer();
int bsd_stopServer();

int bsd_varClean();
