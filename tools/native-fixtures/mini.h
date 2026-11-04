typedef unsigned long size_t;
void *malloc(size_t);
void free(void *);
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
size_t strlen(const char *);
int snprintf(char *, size_t, const char *, ...);
int __android_log_print(int, const char *, const char *, ...);
