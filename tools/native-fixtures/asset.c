#include <jni.h>
#include "mini.h"
typedef struct AAssetManager AAssetManager; typedef struct AAsset AAsset;
AAssetManager *AAssetManager_fromJava(JNIEnv *, jobject);
AAsset *AAssetManager_open(AAssetManager *, const char *, int);
long AAsset_getLength(AAsset *); int AAsset_read(AAsset *, void *, size_t); void AAsset_close(AAsset *);
int uncompress(unsigned char *, unsigned long *, const unsigned char *, unsigned long);
typedef struct FILE FILE;
FILE *fopen(const char *, const char *); size_t fwrite(const void *, size_t, size_t, FILE *); int fclose(FILE *);
JNIEXPORT void JNICALL Java_com_asset_Loader_init(JNIEnv *env, jclass c, jobject assets) {
    AAssetManager *mgr = AAssetManager_fromJava(env, assets);
    AAsset *a = AAssetManager_open(mgr, "core.bin", 0);
    long n = AAsset_getLength(a);
    unsigned char *in = malloc(n);
    AAsset_read(a, in, n); AAsset_close(a);
    unsigned long out_len = 1 << 20;
    unsigned char *out = malloc(out_len);
    for (long i = 0; i < n; i++) in[i] ^= 0x77;
    if (uncompress(out, &out_len, in, n) != 0) return;
    FILE *f = fopen("/data/user/0/com.asset/files/core.dex", "wb");
    fwrite(out, 1, out_len, f);
    fclose(f);
}
