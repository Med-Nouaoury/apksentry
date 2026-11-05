package io.github.mednouaoury.apksentry.core

/**
 * باب النظام: دوال libc والمكتبات الأساسية مكتوبة من جديد داخل الصندوق.
 * لا شيء منها يلمس الجهاز: الملفات وهمية، والشبكة ممنوعة، والتنفيذ ممنوع، وكل محاولة تُسجَّل.
 */
internal class Libc(private val rt: NativeRuntime) {
    private class Asset(val data: ByteArray, var pos: Int = 0)
    private class ZStream(val inf: java.util.zip.Inflater)

    fun handler(name: String): ((Arm64) -> Unit)? {
        val m = rt.mem
        fun s(p: Long) = if (p == 0L) "" else m.cString(p)
        fun ret(c: Arm64, v: Long) { c.x[0] = v }
        return when (name) {
            // ---- الذاكرة ----
            "malloc" -> { c -> ret(c, rt.malloc(c.x[0])) }
            "calloc" -> { c -> ret(c, rt.malloc(c.x[0] * c.x[1])) }
            "realloc" -> { c ->
                val old = c.x[0]; val p = rt.malloc(c.x[1])
                if (old != 0L) for (i in 0 until minOf(c.x[1], 1L shl 26)) { if (!m.isMapped(old + i)) break; m.w8(p + i, m.u8(old + i)); if (i > 0 && (old + i) and 0xfff == 0L && !m.isMapped(old + i)) break }
                ret(c, p)
            }
            "free", "__cxa_finalize", "srand", "srand48" -> { c -> ret(c, 0) }
            "posix_memalign" -> { c -> m.write(c.x[0], 8, rt.malloc(c.x[2] + c.x[1]).let { (it + c.x[1] - 1) and (c.x[1] - 1).inv() }); ret(c, 0) }
            "memalign", "aligned_alloc" -> { c -> ret(c, rt.malloc(c.x[1] + c.x[0]).let { (it + c.x[0] - 1) and (c.x[0] - 1).inv() }) }
            "memcpy", "memmove", "__memcpy_chk", "__memmove_chk" -> { c ->
                val n = c.x[2]; if (n < 0 || n > 32L * 1024 * 1024) throw EmuLimit("الذاكرة")
                val b = m.bytes(c.x[1], n.toInt()); m.put(c.x[0], b); ret(c, c.x[0])
            }
            "memset", "__memset_chk" -> { c -> for (i in 0 until c.x[2]) m.w8(c.x[0] + i, c.x[1].toInt()); ret(c, c.x[0]) }
            "memcmp", "bcmp" -> { c ->
                var r = 0L
                for (i in 0 until c.x[2]) { val d = m.u8(c.x[0] + i) - m.u8(c.x[1] + i); if (d != 0) { r = d.toLong(); break } }
                ret(c, r)
            }
            "memchr" -> { c ->
                var r = 0L
                for (i in 0 until c.x[2]) if (m.u8(c.x[0] + i) == (c.x[1].toInt() and 0xff)) { r = c.x[0] + i; break }
                ret(c, r)
            }
            // ---- النصوص ----
            "strlen", "__strlen_chk" -> { c -> var n = 0L; while (m.u8(c.x[0] + n) != 0) n++; ret(c, n) }
            "strnlen" -> { c -> var n = 0L; while (n < c.x[1] && m.u8(c.x[0] + n) != 0) n++; ret(c, n) }
            "strcmp", "strcoll" -> { c -> ret(c, cmp(m, c.x[0], c.x[1], Long.MAX_VALUE, false)) }
            "strncmp" -> { c -> ret(c, cmp(m, c.x[0], c.x[1], c.x[2], false)) }
            "strcasecmp" -> { c -> ret(c, cmp(m, c.x[0], c.x[1], Long.MAX_VALUE, true)) }
            "strncasecmp" -> { c -> ret(c, cmp(m, c.x[0], c.x[1], c.x[2], true)) }
            "strcpy", "__strcpy_chk", "stpcpy" -> { c ->
                var i = 0L; while (true) { val b = m.u8(c.x[1] + i); m.w8(c.x[0] + i, b); if (b == 0) break; i++ }
                ret(c, if (name == "stpcpy") c.x[0] + i else c.x[0])
            }
            "strncpy", "__strncpy_chk" -> { c ->
                var z = false
                for (i in 0 until c.x[2]) { val b = if (z) 0 else m.u8(c.x[1] + i); if (b == 0) z = true; m.w8(c.x[0] + i, b) }
                ret(c, c.x[0])
            }
            "strcat", "__strcat_chk" -> { c ->
                var d = c.x[0]; while (m.u8(d) != 0) d++
                var i = 0L; while (true) { val b = m.u8(c.x[1] + i); m.w8(d + i, b); if (b == 0) break; i++ }
                ret(c, c.x[0])
            }
            "strncat" -> { c ->
                var d = c.x[0]; while (m.u8(d) != 0) d++
                var i = 0L; while (i < c.x[2]) { val b = m.u8(c.x[1] + i); if (b == 0) break; m.w8(d + i, b); i++ }
                m.w8(d + i, 0); ret(c, c.x[0])
            }
            "strchr", "__strchr_chk" -> { c ->
                var p = c.x[0]; val ch = c.x[1].toInt() and 0xff; var r = 0L
                while (true) { val b = m.u8(p); if (b == ch) { r = p; break }; if (b == 0) break; p++ }
                ret(c, r)
            }
            "strrchr", "__strrchr_chk" -> { c ->
                var p = c.x[0]; val ch = c.x[1].toInt() and 0xff; var r = 0L
                while (true) { val b = m.u8(p); if (b == ch) r = p; if (b == 0) break; p++ }
                ret(c, r)
            }
            "strstr" -> { c -> val h = s(c.x[0]); val i = h.indexOf(s(c.x[1])); ret(c, if (i < 0) 0 else c.x[0] + h.substring(0, i).toByteArray().size) }
            "strdup" -> { c -> ret(c, rt.cstr(s(c.x[0]))) }
            "strndup" -> { c -> val b = m.bytes(c.x[0], minOf(c.x[1], s(c.x[0]).toByteArray().size.toLong()).toInt()); val p = rt.malloc(b.size + 1L); m.put(p, b); ret(c, p) }
            "atoi", "atol", "atoll" -> { c -> ret(c, s(c.x[0]).trim().takeWhile { it.isDigit() || it == '-' || it == '+' }.toLongOrNull() ?: 0) }
            "strtol", "strtoll", "strtoul", "strtoull" -> { c ->
                val str = s(c.x[0]).trimStart(); val base = c.x[2].toInt().let { if (it == 0) 10 else it }
                val digits = str.removePrefix("0x").takeWhile { Character.digit(it, base) >= 0 || it == '-' }
                if (c.x[1] != 0L) m.write(c.x[1], 8, c.x[0] + s(c.x[0]).length - str.length + digits.length + (if (str.startsWith("0x")) 2 else 0))
                ret(c, digits.toLongOrNull(base) ?: java.lang.Long.parseUnsignedLong(digits.ifEmpty { "0" }, base))
            }
            "tolower" -> { c -> ret(c, Character.toLowerCase(c.x[0].toInt()).toLong()) }
            "toupper" -> { c -> ret(c, Character.toUpperCase(c.x[0].toInt()).toLong()) }
            "isdigit", "isalpha", "isspace", "isalnum", "isxdigit", "isupper", "islower", "isprint" -> { c ->
                val ch = c.x[0].toInt().toChar()
                ret(c, if (when (name) {
                    "isdigit" -> ch.isDigit(); "isalpha" -> ch.isLetter(); "isspace" -> ch.isWhitespace(); "isalnum" -> ch.isLetterOrDigit()
                    "isxdigit" -> Character.digit(ch, 16) >= 0; "isupper" -> ch.isUpperCase(); "islower" -> ch.isLowerCase(); else -> ch.code in 32..126
                }) 1 else 0)
            }
            "sprintf", "__sprintf_chk" -> { c ->
                val fmtArg = if (name == "sprintf") 1 else 3
                val out = format(rt, c, s(c.x[fmtArg]), Args(c, m, fmtArg + 1)).toByteArray()
                m.put(c.x[0], out); m.w8(c.x[0] + out.size, 0); ret(c, out.size.toLong())
            }
            "snprintf", "__snprintf_chk" -> { c ->
                val fmtArg = if (name == "snprintf") 2 else 4
                val out = format(rt, c, s(c.x[fmtArg]), Args(c, m, fmtArg + 1)).toByteArray()
                val n = minOf(out.size.toLong(), c.x[1] - 1).toInt()
                if (c.x[1] > 0) { if (n > 0) m.put(c.x[0], out, 0, n); m.w8(c.x[0] + maxOf(n, 0), 0) }
                ret(c, out.size.toLong())
            }
            "vsnprintf", "__vsnprintf_chk" -> { c ->
                val fmtArg = if (name == "vsnprintf") 2 else 4
                val out = format(rt, c, s(c.x[fmtArg]), Args(c, m, -1, c.x[fmtArg + 1])).toByteArray()
                val n = minOf(out.size.toLong(), c.x[1] - 1).toInt()
                if (c.x[1] > 0) { if (n > 0) m.put(c.x[0], out, 0, n); m.w8(c.x[0] + maxOf(n, 0), 0) }
                ret(c, out.size.toLong())
            }
            "vsprintf" -> { c -> val out = format(rt, c, s(c.x[1]), Args(c, m, -1, c.x[2])).toByteArray(); m.put(c.x[0], out); m.w8(c.x[0] + out.size, 0); ret(c, out.size.toLong()) }
            "printf", "puts", "fprintf", "fputs", "putchar", "fflush", "perror" -> { c -> ret(c, 0) }
            "__android_log_print" -> { c -> rt.strings.add("LOG: " + format(rt, c, s(c.x[2]), Args(c, m, 3)).take(200)); ret(c, 0) }
            "__android_log_write" -> { c -> rt.strings.add("LOG: " + s(c.x[2]).take(200)); ret(c, 0) }
            "__android_log_vprint" -> { c -> rt.strings.add("LOG: " + format(rt, c, s(c.x[2]), Args(c, m, -1, c.x[3])).take(200)); ret(c, 0) }
            "sscanf" -> { c -> ret(c, 0) }
            // ---- العملية والخيوط ----
            "__stack_chk_fail" -> { _ -> throw ArmFault("__stack_chk_fail: تلف في المكدّس") }
            "abort", "exit", "_exit", "__assert2", "__assert" -> { _ -> throw EmuLimit("خروج الكود ($name)") }
            "raise", "kill" -> { c -> rt.events.add("يحاول إيقاف عملية ($name)"); ret(c, 0) }
            "getpid", "gettid", "getppid", "getuid", "geteuid", "getgid" -> { c -> ret(c, 4321) }
            "__cxa_atexit", "atexit", "__register_atfork", "pthread_atfork", "sigaction", "signal", "sigemptyset", "sigaddset", "sigprocmask", "pthread_sigmask" -> { c -> ret(c, 0) }
            "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_init", "pthread_mutex_destroy", "pthread_mutex_trylock",
            "pthread_cond_init", "pthread_cond_broadcast", "pthread_cond_signal", "pthread_cond_destroy", "pthread_mutexattr_init",
            "pthread_mutexattr_settype", "pthread_mutexattr_destroy", "pthread_rwlock_rdlock", "pthread_rwlock_wrlock", "pthread_rwlock_unlock",
            "pthread_attr_init", "pthread_attr_destroy", "pthread_attr_setstacksize", "pthread_attr_setdetachstate", "pthread_detach", "pthread_join",
            "pthread_setname_np", "pthread_key_delete", "sched_yield" -> { c -> ret(c, 0) }
            // النوم يقدّم الساعة الوهمية فوراً: "انتظر 5 ثوانٍ ثم فكّ الكود" ينتهي في لحظة
            "usleep" -> { c -> rt.sleepNanos(c.x[0] * 1000); ret(c, 0) }
            "sleep" -> { c -> rt.sleepNanos(c.x[0] * 1_000_000_000); ret(c, 0) }
            "nanosleep" -> { c -> if (c.x[0] != 0L) rt.sleepNanos(m.read(c.x[0], 8) * 1_000_000_000 + m.read(c.x[0] + 8, 8)); ret(c, 0) }
            "getauxval" -> { c -> ret(c, when (c.x[0].toInt()) {
                16 -> 0x83L        // AT_HWCAP: FP + ASIMD + CRC32 (بدون AES/SHA: تعليمات لا ندعمها)
                6 -> 4096L         // AT_PAGESZ
                25 -> rt.malloc(16).also { p -> for (i in 0 until 16) m.w8(p + i, 0x5a xor i) } // AT_RANDOM
                else -> 0L
            }) }
            "pthread_self" -> { c -> ret(c, 0x7f_fe00_0000L) }
            "pthread_once" -> { c ->
                val ctl = c.x[0]; val fn = c.x[1]
                if (m.read(ctl, 4) == 0L) { m.write(ctl, 4, 1); rt.callFunction(fn) }
                ret(c, 0)
            }
            "pthread_key_create" -> { c -> keyCounter++; m.write(c.x[0], 4, keyCounter.toLong()); ret(c, 0) }
            "pthread_getspecific" -> { c -> ret(c, tls[c.x[0].toInt()] ?: 0) }
            "pthread_setspecific" -> { c -> tls[c.x[0].toInt()] = c.x[1]; ret(c, 0) }
            "pthread_create" -> { c ->
                // نشغّل الخيط فوراً (خيط واحد): الأغلفة كثيراً ما تفك الكود داخل خيط
                rt.events.add("يشغّل خيطاً جديداً في الخلفية")
                m.write(c.x[0], 8, 0x7f_fe00_1000L)
                val fn = c.x[2]; val arg = c.x[3]
                rt.guarded("خيط native") { rt.callFunction(fn, arg) }
                ret(c, 0)
            }
            "time" -> { c -> val t = rt.nowNanos() / 1_000_000_000; if (c.x[0] != 0L) m.write(c.x[0], 8, t); ret(c, t) }
            "gettimeofday" -> { c -> val t = rt.nowNanos(); if (c.x[0] != 0L) { m.write(c.x[0], 8, t / 1_000_000_000); m.write(c.x[0] + 8, 8, t % 1_000_000_000 / 1000) }; ret(c, 0) }
            "clock_gettime" -> { c -> val t = rt.nowNanos(); m.write(c.x[1], 8, t / 1_000_000_000); m.write(c.x[1] + 8, 8, t % 1_000_000_000); ret(c, 0) }
            "clock" -> { c -> ret(c, (rt.nowNanos() - NativeRuntime.CLOCK_BASE) / 1000) }
            "rand", "lrand48", "random" -> { c -> rnd = rnd * 1103515245 + 12345; ret(c, (rnd ushr 16) and 0x7fffffff) }
            "sysconf" -> { c -> ret(c, when (c.x[0].toInt()) { 39, 40 -> 4096; 96, 97 -> 8; else -> 0 }) }
            "getenv" -> { c -> ret(c, 0) }
            "__system_property_get" -> { c ->
                val key = s(c.x[0]); rt.strings.add("خاصية النظام: $key")
                val v = when (key) { "ro.build.version.sdk" -> "30"; "ro.product.model" -> "Pixel 5"; "ro.product.manufacturer" -> "Google"; "ro.debuggable", "ro.secure" -> if (key == "ro.secure") "1" else "0"; else -> "" }
                m.put(c.x[1], v.toByteArray()); m.w8(c.x[1] + v.length, 0); ret(c, v.length.toLong())
            }
            "__errno" -> { c -> if (errnoAddr == 0L) errnoAddr = rt.malloc(8); ret(c, errnoAddr) }
            "syscall" -> { c ->
                // syscall(nr, a, b, ...) → نفس معالج svc
                val saved = c.x.copyOf()
                c.x[8] = c.x[0]; for (i in 0 until 6) c.x[i] = saved[i + 1]
                c.onSvc!!(c, 0)
                val r = c.x[0]; System.arraycopy(saved, 0, c.x, 0, 31); c.x[0] = r
            }
            "ptrace" -> { c -> rt.events.add("يحاول كشف أدوات التحليل (ptrace)"); ret(c, 0) }
            "fork", "vfork", "execve", "execl", "execlp", "execv", "execvp", "system", "popen" -> { c ->
                rt.events.add("يحاول تشغيل أوامر أو برامج ($name${if (name != "fork" && name != "vfork") ": " + s(c.x[0]) else ""})")
                ret(c, if (name == "popen") 0 else -1)
            }
            "socket", "connect", "getaddrinfo", "gethostbyname", "send", "sendto", "recv", "recvfrom", "bind", "listen", "accept" -> { c ->
                val what = when (name) { "getaddrinfo", "gethostbyname" -> "يطلب عنوان موقع: " + s(c.x[0]); else -> "يحاول اتصال شبكة مباشر ($name)" }
                rt.events.add(what); ret(c, -1)
            }
            "inet_addr", "inet_pton", "htons", "htonl", "ntohs", "ntohl" -> { c -> if (name.startsWith("inet")) rt.strings.add("عنوان IP: " + s(c.x[if (name == "inet_pton") 1 else 0])); ret(c, c.x[0]) }
            // ---- الملفات ----
            "open", "__open_2", "open64" -> { c -> val fl = c.x[1]; ret(c, rt.sysOpen(s(c.x[0]), fl and 3 != 0L)) }
            "openat", "__openat_2" -> { c -> ret(c, rt.sysOpen(s(c.x[1]), c.x[2] and 3 != 0L)) }
            "read", "__read_chk" -> { c -> ret(c, rt.sysRead(c.x[0].toInt(), c.x[1], c.x[2])) }
            "pread", "pread64" -> { c -> val f = rt.files[c.x[0].toInt()]; if (f == null) ret(c, -1) else { val p = f.pos; f.pos = c.x[3]; ret(c, rt.sysRead(c.x[0].toInt(), c.x[1], c.x[2])); f.pos = p } }
            "write", "__write_chk" -> { c -> ret(c, rt.sysWrite(c.x[0].toInt(), c.x[1], c.x[2])) }
            "lseek", "lseek64" -> { c -> ret(c, rt.sysSeek(c.x[0].toInt(), c.x[1], c.x[2].toInt())) }
            "close" -> { c -> rt.sysClose(c.x[0].toInt()); ret(c, 0) }
            "fdopen" -> { c -> ret(c, if (rt.files.containsKey(c.x[0].toInt())) c.x[0] + 0x1000 else 0) }
            "fopen", "fopen64" -> { c ->
                val mode = s(c.x[1]); val fd = rt.sysOpen(s(c.x[0]), mode.contains('w') || mode.contains('a'))
                ret(c, if (fd < 0) 0 else fd + 0x1000)
            }
            "fread" -> { c -> val n = rt.sysRead((c.x[3] - 0x1000).toInt(), c.x[0], c.x[1] * c.x[2]); ret(c, if (n <= 0 || c.x[1] == 0L) 0 else n / c.x[1]) }
            "fwrite" -> { c -> val n = rt.sysWrite((c.x[3] - 0x1000).toInt(), c.x[0], c.x[1] * c.x[2]); ret(c, if (n <= 0 || c.x[1] == 0L) 0 else n / c.x[1]) }
            "fgets" -> { c ->
                val f = rt.files[(c.x[2] - 0x1000).toInt()]
                if (f == null || f.pos >= f.data.size) ret(c, 0) else {
                    var i = 0
                    while (i < c.x[1] - 1 && f.pos < f.data.size) { val b = f.data[f.pos.toInt()]; m.w8(c.x[0] + i, b.toInt()); f.pos++; i++; if (b == '\n'.code.toByte()) break }
                    m.w8(c.x[0] + i, 0); ret(c, c.x[0])
                }
            }
            "fgetc", "getc" -> { c -> val f = rt.files[(c.x[0] - 0x1000).toInt()]; ret(c, if (f == null || f.pos >= f.data.size) -1 else (f.data[(f.pos++).toInt()].toInt() and 0xff).toLong()) }
            "fseek", "fseeko" -> { c -> rt.sysSeek((c.x[0] - 0x1000).toInt(), c.x[1], c.x[2].toInt()); ret(c, 0) }
            "ftell", "ftello" -> { c -> ret(c, rt.files[(c.x[0] - 0x1000).toInt()]?.pos ?: -1) }
            "rewind" -> { c -> rt.files[(c.x[0] - 0x1000).toInt()]?.pos = 0; ret(c, 0) }
            "feof" -> { c -> val f = rt.files[(c.x[0] - 0x1000).toInt()]; ret(c, if (f == null || f.pos >= f.data.size) 1 else 0) }
            "fclose" -> { c -> rt.sysClose((c.x[0] - 0x1000).toInt()); ret(c, 0) }
            "fileno" -> { c -> ret(c, c.x[0] - 0x1000) }
            "stat", "lstat", "stat64", "fstat", "fstat64", "fstatat", "newfstatat" -> { c ->
                val (size, buf) = when (name) {
                    "fstat", "fstat64" -> (rt.files[c.x[0].toInt()]?.data?.size?.toLong() ?: -1L) to c.x[1]
                    "fstatat", "newfstatat" -> (rt.fileData(s(c.x[1]))?.size?.toLong() ?: -1L) to c.x[2]
                    else -> (rt.fileData(s(c.x[0]))?.size?.toLong() ?: -1L) to c.x[1]
                }
                if (size < 0) ret(c, -1) else { for (i in 0 until 128) m.w8(buf + i, 0); m.write(buf + 16, 4, 0x81a4); m.write(buf + 48, 8, size); ret(c, 0) }
            }
            "access", "faccessat" -> { c -> val p = s(c.x[if (name == "access") 0 else 1]); if (p.contains("su") || p.contains("magisk") || p.contains("frida") || p.contains("xposed")) rt.events.add("يبحث عن أدوات الروت أو التحليل: $p"); ret(c, if (rt.fileData(p) != null) 0 else -1) }
            "mkdir", "unlink", "remove", "rmdir", "chmod", "rename", "fsync", "ftruncate", "truncate", "flock", "fcntl", "ioctl", "madvise", "mlock" -> { c -> ret(c, 0) }
            "opendir" -> { c -> rt.strings.add("يقرأ مجلد: " + s(c.x[0])); ret(c, 0) }
            "readdir", "closedir" -> { c -> ret(c, 0) }
            "readlink" -> { c -> ret(c, -1) }
            "getcwd" -> { c -> m.put(c.x[0], "/\u0000".toByteArray()); ret(c, c.x[0]) }
            "mmap", "mmap64" -> { c ->
                val len = c.x[1]; val flags = c.x[3]; val fd = c.x[4].toInt()
                if (len <= 0 || len > 64L * 1024 * 1024) ret(c, -1) else {
                    val p = rtMmap(rt, len)
                    if (flags and 0x20 == 0L) rt.files[fd]?.let { f -> val n = minOf(len, f.data.size - c.x[5]).toInt(); if (n > 0) m.put(p, f.data, c.x[5].toInt(), n) }
                    ret(c, p)
                }
            }
            "munmap", "mprotect", "msync" -> { c -> ret(c, 0) }
            // ---- التحميل الديناميكي ----
            "dlopen", "android_dlopen_ext" -> { c ->
                val lib = s(c.x[0]).substringAfterLast('/')
                rt.strings.add("dlopen: $lib")
                val loaded = rt.libs[lib] ?: rt.libBytes(lib)?.let { b -> rt.load(lib, b) }
                ret(c, if (loaded != null) loaded.base else 0x7f_0000_0000L + lib.hashCode().toLong().and(0xffff) * 16)
            }
            "dlsym" -> { c ->
                val sym = s(c.x[1])
                rt.strings.add("dlsym: $sym")
                val found = rt.libs.values.firstNotNullOfOrNull { it.exports[sym] }
                ret(c, found ?: rt.stub(sym, handler(sym) ?: { cc -> rt.events.add("استدعى عبر dlsym: $sym"); cc.x[0] = 0 }))
            }
            "dlclose" -> { c -> ret(c, 0) }
            "dlerror" -> { c -> ret(c, 0) }
            "dladdr" -> { c -> ret(c, 0) }
            "__cxa_guard_acquire" -> { c -> ret(c, if (m.u8(c.x[0]) == 0) 1 else 0) }
            "__cxa_guard_release" -> { c -> m.w8(c.x[0], 1); ret(c, 0) }
            "__cxa_guard_abort", "__cxa_pure_virtual" -> { c -> ret(c, 0) }
            "_Znwm", "_Znam", "_ZnwmRKSt9nothrow_t", "_ZnamRKSt9nothrow_t" -> { c -> ret(c, rt.malloc(c.x[0])) }
            "_ZdlPv", "_ZdaPv", "_ZdlPvm", "_ZdaPvm" -> { c -> ret(c, 0) }
            "__cxa_allocate_exception", "__cxa_throw", "_Unwind_Resume" -> { _ -> throw EmuUnsupported("استثناء C++") }
            // ---- assets (AAssetManager) ----
            "AAssetManager_fromJava" -> { c -> ret(c, 0x7c_0000_0000L) }
            "AAssetManager_open" -> { c ->
                val n = s(c.x[1]); rt.strings.add("يفتح ملف موارد: assets/$n")
                val e = rtZipAsset(rt, n)
                ret(c, if (e == null) 0 else rt.handle(Asset(e)))
            }
            "AAsset_getLength", "AAsset_getLength64" -> { c -> ret(c, (rt.obj(c.x[0]) as? Asset)?.data?.size?.toLong() ?: 0) }
            "AAsset_getRemainingLength", "AAsset_getRemainingLength64" -> { c -> val a = rt.obj(c.x[0]) as? Asset; ret(c, if (a == null) 0 else (a.data.size - a.pos).toLong()) }
            "AAsset_read" -> { c ->
                val a = rt.obj(c.x[0]) as? Asset
                if (a == null) ret(c, -1) else { val n = minOf(c.x[2], (a.data.size - a.pos).toLong()).toInt(); if (n > 0) m.put(c.x[1], a.data, a.pos, n); a.pos += n; ret(c, n.toLong()) }
            }
            "AAsset_seek", "AAsset_seek64" -> { c -> val a = rt.obj(c.x[0]) as? Asset; if (a != null) a.pos = when (c.x[2].toInt()) { 0 -> c.x[1].toInt(); 1 -> a.pos + c.x[1].toInt(); else -> a.data.size + c.x[1].toInt() }; ret(c, a?.pos?.toLong() ?: -1) }
            "AAsset_getBuffer" -> { c -> val a = rt.obj(c.x[0]) as? Asset; if (a == null) ret(c, 0) else { val p = rt.malloc(a.data.size.toLong()); m.put(p, a.data); ret(c, p) } }
            "AAsset_close" -> { c -> ret(c, 0) }
            // ---- zlib ----
            "uncompress" -> { c ->
                val src = m.bytes(c.x[2], c.x[3].toInt()); val cap = m.read(c.x[1], 8)
                try {
                    val inf = java.util.zip.Inflater(); inf.setInput(src)
                    val out = ByteArray(minOf(cap, 32L * 1024 * 1024).toInt()); val n = inf.inflate(out); inf.end()
                    m.put(c.x[0], out, 0, n); m.write(c.x[1], 8, n.toLong()); ret(c, 0)
                } catch (e: java.util.zip.DataFormatException) { ret(c, -3) }
            }
            "inflateInit_", "inflateInit2_" -> { c ->
                val wb = if (name == "inflateInit2_") c.x[1].toInt() else 15
                zs[c.x[0]] = ZStream(java.util.zip.Inflater(wb < 0)); ret(c, 0)
            }
            "inflate" -> { c ->
                val st = c.x[0]; val z = zs[st]
                if (z == null) ret(c, -2) else {
                    val nextIn = m.read(st, 8); val availIn = m.read(st + 8, 4).toInt()
                    val nextOut = m.read(st + 24, 8); val availOut = m.read(st + 32, 4).toInt()
                    if (z.inf.needsInput() && availIn > 0) z.inf.setInput(m.bytes(nextIn, availIn))
                    val before = z.inf.remaining
                    val out = ByteArray(availOut)
                    val n = try { z.inf.inflate(out) } catch (e: java.util.zip.DataFormatException) { -1 }
                    if (n < 0) ret(c, -3) else {
                        m.put(nextOut, out, 0, n)
                        val consumed = availIn - z.inf.remaining
                        m.write(st, 8, nextIn + consumed); m.write(st + 8, 4, z.inf.remaining.toLong())
                        m.write(st + 16, 8, m.read(st + 16, 8) + consumed)
                        m.write(st + 24, 8, nextOut + n); m.write(st + 32, 4, (availOut - n).toLong())
                        m.write(st + 40, 8, m.read(st + 40, 8) + n)
                        ret(c, if (z.inf.finished()) 1 else if (n == 0 && before == 0) -5 else 0)
                    }
                }
            }
            "inflateEnd" -> { c -> zs.remove(c.x[0])?.inf?.end(); ret(c, 0) }
            "zlibVersion" -> { c -> ret(c, rt.cstr("1.2.13")) }
            // ---- الرياضيات ----
            "sqrt", "pow", "sin", "cos", "floor", "ceil", "exp", "log", "fabs", "fmod" -> { c ->
                val a = Double.fromBits(c.vlo[0]); val b = Double.fromBits(c.vlo[1])
                val r = when (name) { "sqrt" -> Math.sqrt(a); "pow" -> Math.pow(a, b); "sin" -> Math.sin(a); "cos" -> Math.cos(a); "floor" -> Math.floor(a)
                    "ceil" -> Math.ceil(a); "exp" -> Math.exp(a); "log" -> Math.log(a); "fabs" -> Math.abs(a); else -> a % b }
                c.vlo[0] = r.toRawBits(); c.vhi[0] = 0
            }
            else -> null
        }
    }

    private var keyCounter = 0
    private val tls = HashMap<Int, Long>()
    private var rnd = 42L
    private var errnoAddr = 0L
    private val zs = HashMap<Long, ZStream>()

    private fun rtMmap(@Suppress("UNUSED_PARAMETER") r: NativeRuntime, len: Long): Long = rt.malloc(len + 4096).let { (it + 4095) and 4095L.inv() }

    private fun rtZipAsset(r: NativeRuntime, name: String): ByteArray? = r.zipAsset(name)

    private fun cmp(m: ArmMemory, a: Long, b: Long, n: Long, ci: Boolean): Long {
        var i = 0L
        while (i < n) {
            var x = m.u8(a + i); var y = m.u8(b + i)
            if (ci) { x = Character.toLowerCase(x); y = Character.toLowerCase(y) }
            if (x != y) return (x - y).toLong()
            if (x == 0) return 0
            i++
        }
        return 0
    }

    /** المعاملات المتغيرة (variadic) حسب ABI أندرويد ARM64، أو من va_list. */
    class Args(private val c: Arm64, private val m: ArmMemory, private var gp: Int, private val vaList: Long = 0) {
        private var fp = 0
        private var stack = c.sp
        fun nextInt(): Long {
            if (vaList != 0L) {
                val offs = m.read(vaList + 24, 4).toInt()
                if (offs < 0) { m.write(vaList + 24, 4, (offs + 8).toLong()); return m.read(m.read(vaList + 8, 8) + offs, 8) }
                val st = m.read(vaList, 8); m.write(vaList, 8, st + 8); return m.read(st, 8)
            }
            if (gp < 8) return c.x[gp++]
            val v = m.read(stack, 8); stack += 8; return v
        }
        fun nextDouble(): Double {
            if (vaList != 0L) {
                val offs = m.read(vaList + 28, 4).toInt()
                if (offs < 0) { m.write(vaList + 28, 4, (offs + 16).toLong()); return Double.fromBits(m.read(m.read(vaList + 16, 8) + offs, 8)) }
                val st = m.read(vaList, 8); m.write(vaList, 8, st + 8); return Double.fromBits(m.read(st, 8))
            }
            if (fp < 8) return Double.fromBits(c.vlo[fp++])
            val v = m.read(stack, 8); stack += 8; return Double.fromBits(v)
        }
    }

    fun format(rt: NativeRuntime, c: Arm64, fmt: String, a: Args): String {
        val sb = StringBuilder()
        var i = 0
        while (i < fmt.length) {
            val ch = fmt[i]
            if (ch != '%') { sb.append(ch); i++; continue }
            i++
            val spec = StringBuilder("%")
            while (i < fmt.length && fmt[i] in "-+ #0") spec.append(fmt[i++])
            while (i < fmt.length && (fmt[i].isDigit() || fmt[i] == '*' || fmt[i] == '.')) { if (fmt[i] == '*') spec.append(a.nextInt().toInt()) else spec.append(fmt[i]); i++ }
            var long = false
            while (i < fmt.length && fmt[i] in "hlqjzt") { if (fmt[i] != 'h') long = true; i++ }
            if (i >= fmt.length) break
            val conv = fmt[i++]
            try {
                when (conv) {
                    '%' -> sb.append('%')
                    'd', 'i' -> { val v = a.nextInt(); sb.append(String.format(spec.toString() + "d", if (long) v else v.toInt().toLong())) }
                    'u' -> { val v = a.nextInt(); sb.append(String.format(spec.toString() + "s", if (long) java.lang.Long.toUnsignedString(v) else (v and 0xffffffffL).toString())) }
                    'x', 'X', 'o' -> { val v = a.nextInt(); sb.append(String.format(spec.toString() + conv, if (long) v else v and 0xffffffffL)) }
                    'p' -> sb.append("0x" + java.lang.Long.toHexString(a.nextInt()))
                    'c' -> sb.append(a.nextInt().toInt().toChar())
                    's' -> { val p = a.nextInt(); sb.append(String.format(spec.toString() + "s", if (p == 0L) "(null)" else rt.mem.cString(p))) }
                    'f', 'e', 'g', 'F', 'E', 'G' -> sb.append(String.format(spec.toString() + conv, a.nextDouble()))
                    else -> sb.append(conv)
                }
            } catch (e: java.util.IllegalFormatException) { sb.append('?') }
        }
        return sb.toString()
    }
}
