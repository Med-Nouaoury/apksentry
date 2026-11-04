package io.github.mednouaoury.apksentry.core

/**
 * باب أندرويد: جدول JNI كاملاً (233 دالة) مكتوب داخل الصندوق.
 * كل طلب من الكود native إلى أندرويد يمر من هنا باسمه الصريح، فنسجّله،
 * ثم ننفّذه في محاكي Dalvik (نفس الصندوق) إن وُجد، أو نرجع قيمة فارغة.
 */
internal object Jni {
    private val TYPES = listOf("L", "Z", "B", "C", "S", "I", "J", "F", "D", "V")
    private val PRIMS = listOf("Z", "B", "C", "S", "I", "J", "F", "D")

    private class DirectBuf(val addr: Long, val cap: Long)
    private class Pinned(val array: Any, val addr: Long)

    fun makeVm(rt: NativeRuntime): Long {
        val table = rt.malloc(8 * 8)
        val names = listOf("r0", "r1", "r2", "DestroyJavaVM", "AttachCurrentThread", "DetachCurrentThread", "GetEnv", "AttachCurrentThreadAsDaemon")
        for ((i, n) in names.withIndex()) rt.mem.write(table + 8L * i, 8, rt.stub("jvm:$n") { c ->
            when (n) {
                "AttachCurrentThread", "AttachCurrentThreadAsDaemon", "GetEnv" -> { rt.mem.write(c.x[1], 8, rt.env); c.x[0] = 0 }
                else -> c.x[0] = 0
            }
        })
        val vm = rt.malloc(8)
        rt.mem.write(vm, 8, table)
        return vm
    }

    fun makeEnv(rt: NativeRuntime): Long {
        val n = 233
        val table = rt.malloc(8L * n)
        val pinned = HashMap<Long, Pinned>()
        val directs = java.util.IdentityHashMap<java.nio.ByteBuffer, DirectBuf>()
        val m = rt.mem
        fun h(o: Any?) = rt.handle(o)
        fun o(x: Long) = rt.obj(x)
        fun s(p: Long) = if (p == 0L) "" else m.cString(p)
        fun record(cls: String, name: String) { if (rt.jniCalls.size < 2000) rt.jniCalls.add("$cls->$name") }

        fun descOf(x: Any?): String = when (x) {
            is EObj -> x.cls
            is String -> "Ljava/lang/String;"
            is ByteArray -> "[B"; is IntArray -> "[I"; is LongArray -> "[J"; is CharArray -> "[C"
            is EClass -> "Ljava/lang/Class;"
            else -> "Ljava/lang/Object;"
        }

        /** يقرأ المعاملات حسب توقيع الوظيفة: variadic، أو va_list، أو مصفوفة jvalue. */
        fun readArgs(c: Arm64, params: List<String>, firstReg: Int, mode: Int, ptr: Long): List<Any?> {
            val out = ArrayList<Any?>()
            when (mode) {
                0, 1 -> {
                    val a = if (mode == 0) Libc.Args(c, m, firstReg) else Libc.Args(c, m, -1, ptr)
                    for (p in params) out.add(when (p) {
                        "F" -> a.nextDouble().toFloat().toRawBits()
                        "D" -> a.nextDouble().toRawBits()
                        "J" -> a.nextInt()
                        "Z", "B", "C", "S", "I" -> a.nextInt().toInt()
                        else -> o(a.nextInt())
                    })
                }
                else -> for ((i, p) in params.withIndex()) {
                    val v = m.read(ptr + 8L * i, 8)
                    out.add(when (p) {
                        "Z", "B" -> (v and 0xff).toInt().let { if (p == "B") it.toByte().toInt() else it }
                        "C" -> (v and 0xffff).toInt(); "S" -> v.toInt().toShort().toInt()
                        "I", "F" -> v.toInt()
                        "J", "D" -> v
                        else -> o(v)
                    })
                }
            }
            return out
        }

        fun setRet(c: Arm64, ret: String, r: Any?) {
            when (ret) {
                "V" -> c.x[0] = 0
                "F" -> { c.vlo[0] = ((r as? Number)?.toInt() ?: 0).toLong() and 0xffffffffL; c.vhi[0] = 0 }
                "D" -> { c.vlo[0] = (r as? Number)?.toLong() ?: 0; c.vhi[0] = 0 }
                "J" -> c.x[0] = (r as? Number)?.toLong() ?: 0
                "Z", "B", "C", "S", "I" -> c.x[0] = when (r) { is Boolean -> if (r) 1 else 0; is Number -> r.toLong() and 0xffffffffL; else -> 0 }
                else -> c.x[0] = h(r)
            }
        }

        fun default(ret: String): Any? = when (ret) { "V" -> null; "J", "D" -> 0L; "Z", "B", "C", "S", "I", "F" -> 0; else -> null }

        fun invoke(c: Arm64, recv: Any?, mid: JMethodId?, isStatic: Boolean, args: List<Any?>): Any? {
            if (mid == null) return null
            record(mid.cls, mid.name)
            // الدليل الأقوى: محتوى الطلب نفسه (الرقم ونص الرسالة كانا مشفّرين في الملف)
            if (mid.cls == "Landroid/telephony/SmsManager;" && mid.name.startsWith("send") && args.isNotEmpty())
                rt.events.add("يرسل رسالة SMS إلى ${args[0]}" + ((args.getOrNull(2) as? String)?.let { ": \"${it.take(80)}\"" } ?: ""))
            val b = rt.bridge ?: return default(mid.ret)
            return try {
                b.call(mid.cls, mid.name, mid.params, mid.ret, recv, args, isStatic)
            } catch (e: EmuThrow) {
                rt.events.add("استثناء Java أثناء ${mid.name}"); default(mid.ret)
            } catch (e: EmuUnsupported) {
                rt.stops.add("JNI ${mid.cls.trim('L', ';').substringAfterLast('/')}.${mid.name}: ${e.message}"); default(mid.ret)
            }
        }

        fun arrLen(a: Any?): Int = when (a) {
            is ByteArray -> a.size; is IntArray -> a.size; is LongArray -> a.size; is CharArray -> a.size; is ShortArray -> a.size
            is BooleanArray -> a.size; is FloatArray -> a.size; is DoubleArray -> a.size; is Array<*> -> a.size; else -> 0
        }

        fun esize(a: Any?): Int = when (a) { is LongArray, is DoubleArray -> 8; is IntArray, is FloatArray -> 4; is CharArray, is ShortArray -> 2; else -> 1 }

        fun copyOut(a: Any?, start: Int, len: Int, buf: Long) {
            for (i in 0 until len) {
                val k = start + i
                when (a) {
                    is ByteArray -> m.w8(buf + i, a[k].toInt())
                    is BooleanArray -> m.w8(buf + i, if (a[k]) 1 else 0)
                    is CharArray -> m.write(buf + 2L * i, 2, a[k].code.toLong())
                    is ShortArray -> m.write(buf + 2L * i, 2, a[k].toLong())
                    is IntArray -> m.write(buf + 4L * i, 4, a[k].toLong())
                    is FloatArray -> m.write(buf + 4L * i, 4, a[k].toRawBits().toLong())
                    is LongArray -> m.write(buf + 8L * i, 8, a[k])
                    is DoubleArray -> m.write(buf + 8L * i, 8, a[k].toRawBits())
                }
            }
        }

        fun copyIn(a: Any?, start: Int, len: Int, buf: Long) {
            for (i in 0 until len) {
                val k = start + i
                when (a) {
                    is ByteArray -> a[k] = m.u8(buf + i).toByte()
                    is BooleanArray -> a[k] = m.u8(buf + i) != 0
                    is CharArray -> a[k] = m.read(buf + 2L * i, 2).toInt().toChar()
                    is ShortArray -> a[k] = m.read(buf + 2L * i, 2).toShort()
                    is IntArray -> a[k] = m.read(buf + 4L * i, 4).toInt()
                    is FloatArray -> a[k] = Float.fromBits(m.read(buf + 4L * i, 4).toInt())
                    is LongArray -> a[k] = m.read(buf + 8L * i, 8)
                    is DoubleArray -> a[k] = Double.fromBits(m.read(buf + 8L * i, 8))
                }
            }
            if (a is ByteArray && start == 0 && len == a.size) rt.inspect(a, "native → Java (مصفوفة bytes)")
        }

        fun newPrim(t: String, len: Int): Any = when (t) {
            "Z" -> BooleanArray(len); "B" -> ByteArray(len); "C" -> CharArray(len); "S" -> ShortArray(len)
            "I" -> IntArray(len); "J" -> LongArray(len); "F" -> FloatArray(len); else -> DoubleArray(len)
        }

        fun handler(i: Int): (Arm64) -> Unit = when {
            i == 4 -> { c -> c.x[0] = 0x10006 }
            i == 5 -> { c -> rt.events.add("يعرّف كلاساً من bytes (DefineClass)"); c.x[0] = 0 }
            i == 6 -> { c -> val nm = s(c.x[1]); rt.strings.add("FindClass: $nm"); c.x[0] = h(EClass(if (nm.startsWith("[")) nm else "L$nm;")) }
            i == 7 || i == 8 || i == 9 || i == 12 -> { c -> c.x[0] = c.x[1] }
            i == 10 -> { c -> c.x[0] = h(EClass("Ljava/lang/Object;")) }
            i == 11 -> { c -> c.x[0] = 1 }
            i == 13 || i == 14 -> { c -> if (i == 14) rt.strings.add("ThrowNew: " + s(c.x[2])); c.x[0] = 0 }
            i == 15 -> { c -> c.x[0] = 0 }
            i == 16 || i == 17 -> { c -> c.x[0] = 0 }
            i == 18 -> { c -> throw EmuLimit("FatalError: " + s(c.x[1])) }
            i == 19 || i == 26 -> { c -> c.x[0] = 0 }
            i == 20 -> { c -> c.x[0] = c.x[1] }
            i == 21 || i == 25 || i == 226 -> { c -> c.x[0] = c.x[1] }
            i == 22 || i == 23 || i == 227 -> { c -> c.x[0] = 0 }
            i == 24 -> { c -> c.x[0] = if (c.x[1] == c.x[2]) 1 else 0 }
            i == 27 -> { c -> val cls = (o(c.x[1]) as? EClass)?.desc ?: ""; c.x[0] = h(if (rt.bridge?.isApp(cls) == true) EObj(cls) else Opaque) }
            i in 28..30 -> { c -> // NewObject
                val cls = (o(c.x[1]) as? EClass)?.desc ?: ""; val mid = o(c.x[2]) as? JMethodId
                val params = mid?.params ?: emptyList()
                val args = readArgs(c, params, 3, i - 28, c.x[3])
                record(cls, "<init>")
                val r = rt.bridge?.let { b -> try { b.newObject(cls, params, args) } catch (e: EmuUnsupported) { rt.stops.add("JNI new $cls: ${e.message}"); Opaque } catch (e: EmuThrow) { null } } ?: Opaque
                c.x[0] = h(r)
            }
            i == 31 -> { c -> c.x[0] = h(EClass(descOf(o(c.x[1])))) }
            i == 32 -> { c -> val cls = (o(c.x[2]) as? EClass)?.desc; val x = o(c.x[1]); c.x[0] = if (x != null && (cls == null || cls == "Ljava/lang/Object;" || descOf(x) == cls || x is Opaque)) 1 else 0 }
            i == 33 || i == 113 -> { c ->
                val cls = (o(c.x[1]) as? EClass)?.desc ?: "?"; val nm = s(c.x[2]); val sig = s(c.x[3])
                rt.strings.add("${cls.trim('L', ';')}.$nm$sig")
                c.x[0] = h(JMethodId(cls, nm, sig, i == 113))
            }
            i in 34..63 -> { c -> // Call<Type>Method{,V,A}
                val mid = o(c.x[2]) as? JMethodId; val ret = TYPES[(i - 34) / 3]
                val args = readArgs(c, mid?.params ?: emptyList(), 3, (i - 34) % 3, c.x[3])
                setRet(c, mid?.ret ?: ret, invoke(c, o(c.x[1]), mid, false, args))
            }
            i in 64..93 -> { c -> // CallNonvirtual
                val mid = o(c.x[3]) as? JMethodId; val ret = TYPES[(i - 64) / 3]
                val args = readArgs(c, mid?.params ?: emptyList(), 4, (i - 64) % 3, c.x[4])
                setRet(c, mid?.ret ?: ret, invoke(c, o(c.x[1]), mid, false, args))
            }
            i in 114..143 -> { c -> // CallStatic
                val mid = o(c.x[2]) as? JMethodId; val ret = TYPES[(i - 114) / 3]
                val args = readArgs(c, mid?.params ?: emptyList(), 3, (i - 114) % 3, c.x[3])
                setRet(c, mid?.ret ?: ret, invoke(c, null, mid, true, args))
            }
            i == 94 || i == 144 -> { c ->
                val cls = (o(c.x[1]) as? EClass)?.desc ?: "?"; val nm = s(c.x[2]); val sig = s(c.x[3])
                rt.strings.add("${cls.trim('L', ';')}.$nm:$sig")
                c.x[0] = h(JFieldId(cls, nm, sig, i == 144))
            }
            i in 95..103 || i in 145..153 -> { c -> // Get(Static)Field
                val st = i >= 145; val f = o(c.x[2]) as? JFieldId
                val t = f?.type ?: "I"
                if (f != null) record(f.cls, f.name)
                val r = try {
                    if (st) rt.bridge?.getStatic(f?.cls ?: "", f?.name ?: "", t) else rt.bridge?.getField(o(c.x[1]), f?.cls ?: "", f?.name ?: "", t)
                } catch (e: RuntimeException) { null } ?: default(t)
                setRet(c, if (t.length == 1) t else "L", r)
            }
            i in 104..112 || i in 154..162 -> { c -> // Set(Static)Field
                val f = o(c.x[2]) as? JFieldId
                val t = f?.type ?: "I"
                val v: Any? = when (t) { "F" -> c.vlo[0].toInt(); "D" -> c.vlo[0]; "J" -> c.x[3]; "Z", "B", "C", "S", "I" -> c.x[3].toInt(); else -> o(c.x[3]) }
                if (f != null) { record(f.cls, f.name + "=") ; try { rt.bridge?.setField(if (i >= 154) null else o(c.x[1]), f.cls, f.name, v) } catch (e: RuntimeException) {} }
                c.x[0] = 0
            }
            i == 163 -> { c -> val len = c.x[2].toInt().coerceIn(0, 1 shl 20); c.x[0] = h(String(CharArray(len) { k -> m.read(c.x[1] + 2L * k, 2).toInt().toChar() })) }
            i == 164 -> { c -> c.x[0] = ((o(c.x[1]) as? String)?.length ?: 0).toLong() }
            i == 165 || i == 224 -> { c ->
                val str = o(c.x[1]) as? String ?: ""; val p = rt.malloc(2L * str.length + 2)
                for ((k, ch) in str.withIndex()) m.write(p + 2L * k, 2, ch.code.toLong())
                if (c.x[2] != 0L) m.w8(c.x[2], 1)
                c.x[0] = p
            }
            i == 166 || i == 170 || i == 225 -> { c -> c.x[0] = 0 }
            i == 167 -> { c -> val str = s(c.x[1]); rt.strings.add(str.take(300)); c.x[0] = h(str) }
            i == 168 -> { c -> c.x[0] = ((o(c.x[1]) as? String)?.toByteArray()?.size ?: 0).toLong() }
            i == 169 -> { c -> if (c.x[2] != 0L) m.w8(c.x[2], 1); c.x[0] = rt.cstr(o(c.x[1]) as? String ?: "") }
            i == 171 -> { c -> c.x[0] = arrLen(o(c.x[1])).toLong() }
            i == 172 -> { c -> val len = c.x[1].toInt().coerceIn(0, 1 shl 20); val init = o(c.x[3]); c.x[0] = h(arrayOfNulls<Any?>(len).also { a -> if (init != null) a.fill(init) }) }
            i == 173 -> { c -> c.x[0] = h((o(c.x[1]) as? Array<*>)?.getOrNull(c.x[2].toInt())) }
            i == 174 -> { c -> @Suppress("UNCHECKED_CAST") (o(c.x[1]) as? Array<Any?>)?.let { a -> val k = c.x[2].toInt(); if (k in a.indices) a[k] = o(c.x[3]) }; c.x[0] = 0 }
            i in 175..182 -> { c -> val len = c.x[1].toInt().coerceIn(0, 64 shl 20); c.x[0] = h(newPrim(PRIMS[i - 175], len)) }
            i in 183..190 || i == 222 -> { c -> // Get<Prim>ArrayElements / GetPrimitiveArrayCritical
                val a = o(c.x[1]); val len = arrLen(a)
                val p = rt.malloc(maxOf(1L, len.toLong() * esize(a)))
                if (a != null) { copyOut(a, 0, len, p); pinned[p] = Pinned(a, p) }
                if (c.x[2] != 0L) m.w8(c.x[2], 1)
                c.x[0] = p
            }
            i in 191..198 || i == 223 -> { c -> // Release
                val p = pinned[c.x[2]]
                if (p != null && c.x[3] != 2L) copyIn(p.array, 0, arrLen(p.array), p.addr)
                if (c.x[3] != 1L) pinned.remove(c.x[2])
                c.x[0] = 0
            }
            i in 199..206 -> { c -> val a = o(c.x[1]); val st = c.x[2].toInt(); val len = c.x[3].toInt(); if (a != null && st >= 0 && st + len <= arrLen(a)) copyOut(a, st, len, c.x[4]); c.x[0] = 0 }
            i in 207..214 -> { c -> val a = o(c.x[1]); val st = c.x[2].toInt(); val len = c.x[3].toInt(); if (a != null && st >= 0 && st + len <= arrLen(a)) copyIn(a, st, len, c.x[4]); c.x[0] = 0 }
            i == 215 -> { c -> // RegisterNatives
                val cls = (o(c.x[1]) as? EClass)?.desc ?: "?"; val cnt = c.x[3].toInt().coerceIn(0, 4096)
                for (k in 0 until cnt) {
                    val e = c.x[2] + 24L * k
                    val nm = s(m.read(e, 8)); val sig = s(m.read(e + 8, 8)); val fn = m.read(e + 16, 8)
                    rt.registered["$cls->$nm$sig"] = fn
                }
                if (cnt > 0) rt.events.add("سجّل $cnt وظيفة native مخفية الاسم لـ ${cls.trim('L', ';').replace('/', '.')}")
                c.x[0] = 0
            }
            i == 216 || i == 217 || i == 218 -> { c -> c.x[0] = 0 }
            i == 219 -> { c -> m.write(c.x[1], 8, rt.vm); c.x[0] = 0 }
            i == 220 -> { c -> val str = o(c.x[1]) as? String ?: ""; val st = c.x[2].toInt(); val len = c.x[3].toInt(); for (k in 0 until len) m.write(c.x[4] + 2L * k, 2, str.getOrNull(st + k)?.code?.toLong() ?: 0); c.x[0] = 0 }
            i == 221 -> { c -> val str = o(c.x[1]) as? String ?: ""; val b = str.substring(c.x[2].toInt().coerceIn(0, str.length), (c.x[2] + c.x[3]).toInt().coerceIn(0, str.length)).toByteArray(); m.put(c.x[4], b); m.w8(c.x[4] + b.size, 0); c.x[0] = 0 }
            i == 228 -> { c -> c.x[0] = 0 }
            i == 229 -> { c -> // NewDirectByteBuffer: الأغلفة تمرر بها الكود المفكوك إلى InMemoryDexClassLoader
                val cap = c.x[2].coerceIn(0, 128L * 1024 * 1024)
                val bytes = m.bytes(c.x[1], cap.toInt())
                rt.inspect(bytes, "native → ByteBuffer")
                val bb = java.nio.ByteBuffer.wrap(bytes)
                directs[bb] = DirectBuf(c.x[1], cap)
                c.x[0] = h(bb)
            }
            i == 230 -> { c -> c.x[0] = (o(c.x[1]) as? java.nio.ByteBuffer)?.let { directs[it]?.addr } ?: 0 }
            i == 231 -> { c -> c.x[0] = (o(c.x[1]) as? java.nio.ByteBuffer)?.capacity()?.toLong() ?: -1 }
            i == 232 -> { c -> c.x[0] = 1 }
            else -> { c -> c.x[0] = 0 }
        }

        for (i in 0 until n) m.write(table + 8L * i, 8, rt.stub("jni:$i", handler(i)))
        val env = rt.malloc(8)
        m.write(env, 8, table)
        return env
    }

}
