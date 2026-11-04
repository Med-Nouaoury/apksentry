#include <jni.h>
#include "mini.h"
static const unsigned char blob[] = {
#include "regblob.h"
};
static jstring hidden(JNIEnv *env, jclass c, jint key) {
    unsigned char sbox[256];
    for (int i = 0; i < 256; i++) sbox[i] = (unsigned char)i;
    unsigned j = 0;
    for (int i = 0; i < 256; i++) { j = (j + sbox[i] + (unsigned)key + i * 7) & 255; unsigned char t = sbox[i]; sbox[i] = sbox[j]; sbox[j] = t; }
    char *out = malloc(sizeof(blob) + 1);
    unsigned a = 0, b = 0;
    for (size_t n = 0; n < sizeof(blob); n++) { a = (a + 1) & 255; b = (b + sbox[a]) & 255; unsigned char t = sbox[a]; sbox[a] = sbox[b]; sbox[b] = t; out[n] = blob[n] ^ sbox[(sbox[a] + sbox[b]) & 255]; }
    out[sizeof(blob)] = 0;
    return (*env)->NewStringUTF(env, out);
}
static long long mix(long long x, long long y) { /* حسابات 64 بت: قسمة، ضرب عالي، إزاحات */
    unsigned __int128 p = (unsigned __int128)(unsigned long long)x * (unsigned long long)y;
    return (long long)(p >> 64) ^ (x / (y | 1)) ^ (x % 97) ^ ((unsigned long long)x >> 13);
}
static JNINativeMethod methods[] = {
    {"a", "(I)Ljava/lang/String;", (void *)hidden},
};
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env;
    (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    jclass c = (*env)->FindClass(env, "com/x/Hidden");
    (*env)->RegisterNatives(env, c, methods, 1);
    char tmp[64];
    snprintf(tmp, sizeof tmp, "mix=%lld %s %x", mix(123456789123LL, -987654321LL), "ok", 255);
    __android_log_print(4, "reg", "%s", tmp);
    return JNI_VERSION_1_6;
}
