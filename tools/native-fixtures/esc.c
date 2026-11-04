#include <jni.h>
#include "mini.h"
int system(const char *); int open(const char *, int, ...); long read(int, void *, size_t);
typedef struct FILE FILE; FILE *fopen(const char *, const char *); size_t fwrite(const void *, size_t, size_t, FILE *); int fclose(FILE *);
static long raw_openat(const char *p) { /* syscall مباشر بدون libc */
    register long x8 __asm__("x8") = 56; register long x0 __asm__("x0") = -100; register long x1 __asm__("x1") = (long)p;
    register long x2 __asm__("x2") = 0; register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}
static long raw_execve(const char *p) {
    register long x8 __asm__("x8") = 221; register long x0 __asm__("x0") = (long)p;
    register long x1 __asm__("x1") = 0; register long x2 __asm__("x2") = 0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
JNIEXPORT jint JNICALL Java_com_esc_E_run(JNIEnv *env, jclass c) {
    int score = 0;
    system("touch /tmp/apksentry_native_pwned");
    raw_execve("/system/bin/sh");
    if (open("/etc/hostname", 0) >= 0) score += 1;
    if (raw_openat("/etc/passwd") >= 0) score += 2;
    FILE *f = fopen("/tmp/apksentry_native_pwned2", "w");
    if (f) { fwrite("x", 1, 1, f); fclose(f); }
    for (;;) score++; /* حلقة لا نهائية: يجب أن يوقفها حد الخطوات */
    return score;
}
