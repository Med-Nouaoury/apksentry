.class public Lemu/Esc;
.super Ljava/lang/Object;

.method public static exec()V
    .registers 2
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v0
    const-string v1, "touch /tmp/apksentry_pwned"
    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    return-void
.end method

.method public static readEtc()I
    .registers 2
    new-instance v0, Ljava/io/FileInputStream;
    const-string v1, "/etc/hostname"
    invoke-direct {v0, v1}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/io/FileInputStream;->read()I
    move-result v0
    return v0
.end method

.method public static refl()V
    .registers 6
    const-string v0, "java.lang.Runtime"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v0
    const-string v1, "getRuntime"
    const/4 v2, 0x0
    new-array v2, v2, [Ljava/lang/Class;
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    move-result-object v1
    const/4 v3, 0x0
    const/4 v4, 0x0
    new-array v4, v4, [Ljava/lang/Object;
    invoke-virtual {v1, v3, v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v3
    const-string v1, "exec"
    const/4 v2, 0x1
    new-array v2, v2, [Ljava/lang/Class;
    const-class v4, Ljava/lang/String;
    const/4 v5, 0x0
    aput-object v4, v2, v5
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    move-result-object v1
    const/4 v2, 0x1
    new-array v2, v2, [Ljava/lang/Object;
    const-string v4, "touch /tmp/apksentry_pwned2"
    aput-object v4, v2, v5
    invoke-virtual {v1, v3, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    return-void
.end method

.method public static loop()V
    .registers 1
    :l
    goto :l
.end method

.method public static bomb()[B
    .registers 2
    const v0, 0x7fffffff
    new-array v0, v0, [B
    return-object v0
.end method

.method public static cl()Ljava/lang/Object;
    .registers 2
    const-string v0, "x"
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;
    move-result-object v0
    return-object v0
.end method

.method public static net()V
    .registers 2
    new-instance v0, Ljava/net/URL;
    const-string v1, "http://example.com/"
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v0
    invoke-virtual {v0}, Ljava/net/URLConnection;->connect()V
    return-void
.end method

.method public static recurse()V
    .registers 0
    invoke-static {}, Lemu/Esc;->recurse()V
    return-void
.end method
