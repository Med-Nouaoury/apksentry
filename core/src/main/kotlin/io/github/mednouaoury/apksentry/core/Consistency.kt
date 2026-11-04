package io.github.mednouaoury.apksentry.core

/**
 * يتحقق أن التقرير لا يناقض نفسه. هذه الأخطاء رآها المستخدم بعينه في تطبيقات حقيقية
 * (ARMSX3، GTA III، WhatsApp، TikTok)، فصارت قواعد يفحصها الكود على كل نتيجة:
 * في الاختبارات وفي القياس، قبل أن تصل إلى أي هاتف.
 */
object Consistency {
    fun check(r: ScanResult): List<String> {
        val out = ArrayList<String>()
        val bad = r.summary.filter { it.tone == Tone.BAD }
        val ok = r.summary.filter { it.tone == Tone.OK }
        val texts = r.summary.map { it.text }

        // 1) سطر أحمر "فيروس" مع حكم مطمئن
        if (bad.any { it.text.startsWith("يتصرّف مثل الفيروسات") } && r.level < RiskLevel.MEDIUM)
            out.add("الخلاصة تقول 'يتصرّف مثل الفيروسات' والحكم ${r.level.label}")
        // 2) أي سطر أحمر مع خطر منخفض جداً
        if (bad.isNotEmpty() && r.level == RiskLevel.LOW)
            out.add("سطر أحمر في الخلاصة والحكم منخفض: ${bad.first().text.take(60)}")
        // 3) حكم مرتفع بدون أي سبب أحمر في الخلاصة
        if (r.level == RiskLevel.HIGH && bad.isEmpty() && r.summary.isNotEmpty())
            out.add("الحكم مرتفع ولا يوجد سبب واضح في الخلاصة")
        // 4) وعد بالسلامة مع كود مخفي لم نره
        if (ok.any { it.text.startsWith("لم نجد سلوك فيروس: لا يسرق") } && texts.any { "مخفي" in it && "فككناه" !in it })
            out.add("الخلاصة تعد بالسلامة وتقول إن جزءاً من الكود مخفي")
        // 5) نفس الفكرة مرتين
        if (texts.size != texts.distinct().size) out.add("سطر مكرر في الخلاصة")
        if (texts.count { "مخفي" in it } > 1 && texts.none { "فككناه" in it }) out.add("فكرة 'الكود المخفي' مكررة في الخلاصة")
        // 6) توقيع المطوّر الرسمي مع "معدّل"
        if (r.trustedSource != null && r.modScore >= 10)
            out.add("موقّع من المصدر الرسمي (${r.trustedSource}) ودرجة التعديل ${r.modScore}")
        if (r.trustedSource != null && r.thirdPartySigned) out.add("موقّع من المصدر الرسمي ومن طرف آخر في نفس الوقت")
        // 7) توقيع سليم وملف تغيّر بعد التوقيع
        if (r.integrityVerified && r.dangers.any { "عُدِّل بعد توقيعه" in it.message })
            out.add("التوقيع سليم والملف تغيّر بعد توقيعه")
        // 8) النصيحة تناقض الحكم
        if (r.level == RiskLevel.HIGH && !r.action.startsWith("لا تثبّته")) out.add("حكم مرتفع والنصيحة: ${r.action}")
        if (r.level <= RiskLevel.LOW_MEDIUM && r.action.startsWith("لا تثبّته")) out.add("حكم منخفض والنصيحة: لا تثبّته")
        // 9) "شهادات مختلفة" مع شهادة واحدة
        if (r.dangers.any { "شهادات مختلفة" in it.message } && r.signers.size < 2) out.add("'شهادات مختلفة' مع شهادة واحدة")
        // 10) قدرة مزدوجة (لها سياق 'عادي في') تُعرض كدليل فيروس
        if (bad.any { it.text.startsWith("يتصرّف مثل الفيروسات") } && r.behaviors.all { "(عادي" in it.message } && r.behaviors.isNotEmpty())
            out.add("قدرة مزدوجة الاستعمال معروضة كسلوك فيروس")
        // 11) "لم نجد سلوك فيروس" مع حكم متوسط أو مرتفع
        if (ok.any { it.text.startsWith("لم نجد سلوك فيروس") } && r.level >= RiskLevel.MEDIUM)
            out.add("الخلاصة تقول 'لم نجد سلوك فيروس' والحكم ${r.level.label}")
        return out
    }
}
