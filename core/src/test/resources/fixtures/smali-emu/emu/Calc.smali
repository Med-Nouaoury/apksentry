.class public Lemu/Calc;
.super Ljava/lang/Object;

.method public static mix(IJ)J
    .registers 10
    int-to-long v0, p0
    const-wide/16 v2, 0x1f
    mul-long v4, p1, v2
    add-long/2addr v4, v0
    const/4 v2, 0x7
    ushr-long v0, v4, v2
    xor-long/2addr v4, v0
    const/4 v2, 0x3
    shr-long v0, v4, v2
    long-to-int v0, v0
    mul-int/lit8 v0, v0, -0x7
    div-int/lit8 v1, v0, 0x3
    rem-int/lit8 v0, v0, 0x5
    add-int/2addr v0, v1
    shl-int/lit8 v0, v0, 0x2
    int-to-long v0, v0
    add-long/2addr v4, v0
    int-to-long v0, p0
    const/16 v2, 0x28
    shl-long v0, v0, v2
    sub-long/2addr v4, v0
    const/16 v2, 0xd
    shl-long v0, v4, v2
    xor-long/2addr v4, v0
    return-wide v4
.end method

.method public static sw(I)I
    .registers 3
    packed-switch p0, :ps
    sparse-switch p0, :ss
    const/4 v0, -0x1
    return v0
    :c1
    const/16 v0, 0x64
    return v0
    :c2
    const/16 v0, 0xc8
    return v0
    :s1
    const/16 v0, 0x3e8
    return v0
    :ps
    .packed-switch 0x5
        :c1
        :c2
    .end packed-switch
    :ss
    .sparse-switch
        -0x64 -> :s1
        0x7fff0000 -> :c2
    .end sparse-switch
.end method

.method public static div0()I
    .registers 3
    const/4 v0, 0x0
    :try_start
    const/16 v1, 0xa
    div-int v1, v1, v0
    :try_end
    .catch Ljava/lang/ArithmeticException; {:try_start .. :try_end} :h
    return v1
    :h
    move-exception v2
    const/4 v1, -0x1
    return v1
.end method

.method public static str()Ljava/lang/String;
    .registers 3
    new-instance v0, Ljava/lang/StringBuilder;
    const-string v1, "ab"
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    const/16 v1, 0x2a
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    const/16 v1, 0x7a
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/String;->toUpperCase()Ljava/lang/String;
    move-result-object v0
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method

.method public static fl(FD)D
    .registers 8
    float-to-double v0, p0
    mul-double/2addr v0, p1
    const-wide/high16 v2, 0x4000000000000000L
    div-double/2addr v0, v2
    double-to-int v2, v0
    int-to-float v2, v2
    float-to-double v2, v2
    add-double/2addr v0, v2
    return-wide v0
.end method

.method public static chars()I
    .registers 4
    const/4 v0, -0x1
    int-to-char v0, v0
    int-to-byte v1, v0
    int-to-short v2, v0
    add-int/2addr v0, v1
    add-int/2addr v0, v2
    const-wide v2, -0x123456789abcdefL
    const-wide/16 v0, 0x5
    cmp-long v0, v2, v0
    return v0
.end method
