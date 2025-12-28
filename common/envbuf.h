int envbuf_len(char*const envp[]);
char **envbuf_mutcopy(char*const envp[]);
void envbuf_free(char *envp[]);
int envbuf_find(char*const envp[], const char *name);
const char *envbuf_getenv(char*const envp[], const char *name);
void envbuf_setenv(char **envpp[], const char *name, const char *value, int overwrite);
void envbuf_unsetenv(char **envpp[], const char *name);