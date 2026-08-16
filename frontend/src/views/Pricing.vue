<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useSEO } from '../composables/useSEO'
import { getPublicPricing } from '../api'

useSEO({
  title: 'الأسعار — Pricing',
  description: 'سيكو: الفحص الأمني الخفيف مجاني بالكامل. الفحص العميق (فحص شامل بأكثر من 40 فئة، CVEs، زحف، اختبارات نشطة) مدفوع لكل نطاق عبر حوالة داخلية.',
  keywords: 'أسعار سيكو, فحص أمني مجاني, فحص عميق, vulnerability scanner pricing',
})

const router = useRouter()
const deepPrice = ref(25000)

onMounted(async () => {
  try {
    const { data } = await getPublicPricing()
    if (data?.deep_scan_price_iqd) deepPrice.value = data.deep_scan_price_iqd
  } catch { /* keep default */ }
})

const priceLabel = computed(() => new Intl.NumberFormat('en-US').format(deepPrice.value) + ' د.ع')

const plans = computed(() => [
  {
    name: 'الفحص الخفيف',
    nameEn: 'Free',
    priceText: 'مجاناً',
    period: 'للأبد',
    description: 'فحص أمني أساسي لموقعك بعد توثيق الملكية.',
    highlighted: false,
    cta: 'ابدأ مجاناً',
    features: [
      { text: 'تسجيل مجاني وتوثيق ملكية النطاق (TXT أو ملف)', included: true },
      { text: 'رؤوس الأمان و HTTPS/TLS', included: true },
      { text: 'كشف الإعدادات المكشوفة الأساسية', included: true },
      { text: 'تقرير بالنتائج والدرجة', included: true },
      { text: 'حتى 25 نطاقاً · 100 فحص خفيف/شهر', included: true },
      { text: 'الفحص العميق (CVEs، زحف، اختبارات نشطة)', included: false },
    ],
  },
  {
    name: 'الفحص العميق',
    nameEn: 'Deep',
    priceText: priceLabel.value,
    period: 'لكل فحص · لكل نطاق',
    description: 'فحص شامل مدفوع لكل نطاق، يُدفع عبر حوالة داخلية.',
    highlighted: true,
    badge: 'الأقوى',
    cta: 'اطلب فحصاً عميقاً',
    features: [
      { text: 'كل مزايا الفحص الخفيف', included: true },
      { text: 'أكثر من 40 فئة فحص', included: true },
      { text: 'فحص ثغرات CVE عبر nuclei', included: true },
      { text: 'زحف الموقع واكتشاف المسارات (crawl/ffuf)', included: true },
      { text: 'اختبارات XSS متقدمة و OOB/SSRF', included: true },
      { text: 'اختبار قفل تسجيل الدخول (brute-force مضبوط)', included: true },
      { text: 'دفع لمرة واحدة — بلا اشتراك', included: true },
    ],
  },
])

const steps = [
  { n: '١', title: 'سجّل مجاناً', text: 'أنشئ حساباً وأضف نطاقك.' },
  { n: '٢', title: 'وثّق الملكية', text: 'أضف سجل TXT أو ارفع ملفاً على موقعك.' },
  { n: '٣', title: 'ادفع بالحوالة', text: 'اطلب فحصاً عميقاً وحوّل المبلغ ثم أدخل رقم الإشعار.' },
  { n: '٤', title: 'استلم النتائج', text: 'بعد تأكيد المشرف يبدأ الفحص العميق ويصلك التقرير.' },
]

const faqs = ref([
  { question: 'هل الفحص الخفيف مجاني فعلاً؟', answer: 'نعم، مجاني بالكامل وللأبد بعد توثيق ملكية النطاق. لا يحتاج بطاقة ائتمان.', open: false },
  { question: 'كيف أثبت ملكية موقعي؟', answer: 'بطريقتين: إضافة سجل DNS TXT، أو رفع ملف تحقق على المسار /.well-known/seku-verify.txt. أي طريقة تكفي.', open: false },
  { question: 'كيف أدفع مقابل الفحص العميق؟', answer: 'عبر حوالة داخلية. تطلب الفحص، تحوّل المبلغ إلى الحساب المعروض، ثم تُدخل رقم إشعار الحوالة. يؤكّده المشرف فيُفعّل فحصك.', open: false },
  { question: 'هل الفحص العميق اشتراك شهري؟', answer: 'لا. الدفع لمرة واحدة لكل فحص عميق ولكل نطاق. بلا التزام شهري.', open: false },
  { question: 'هل يمكنكم فحص أنظمة لا أملكها؟', answer: 'لا. لا يُسمح بالفحص إلا بعد توثيق ملكيتك للنطاق، حفاظاً على الالتزام القانوني والأخلاقي.', open: false },
])
</script>

<template>
  <div class="public-shell" dir="rtl">
    <!-- Hero -->
    <section class="relative pt-20 pb-24 text-center px-4 ring-grid">
      <h1 class="text-3xl sm:text-5xl font-extrabold text-white">أسعار <span class="text-gradient">بسيطة وواضحة</span></h1>
      <p class="mt-4 text-lg sm:text-xl text-slate-300 max-w-2xl mx-auto">
        الفحص الخفيف مجاني للأبد. الفحص العميق مدفوع لكل نطاق عبر حوالة داخلية — بلا اشتراكات.
      </p>
    </section>

    <!-- Pricing Cards -->
    <section class="relative -mt-14 pb-16 px-4">
      <div class="max-w-3xl mx-auto grid grid-cols-1 sm:grid-cols-2 gap-6">
        <div v-for="plan in plans" :key="plan.nameEn"
          :class="['card card-hover p-6 flex flex-col',
                   plan.highlighted ? 'ring-2 ring-emerald-400 glow-accent' : '']">
          <div v-if="plan.badge" class="absolute -top-3.5 right-4 bg-accent-grad glow-accent text-white text-xs font-bold px-4 py-1.5 rounded-full shadow-md">
            {{ plan.badge }}
          </div>
          <div class="mb-4">
            <div class="flex items-center gap-2 mb-1">
              <h3 class="text-lg font-bold text-slate-900 dark:text-white">{{ plan.name }}</h3>
              <span class="text-xs text-slate-500 dark:text-slate-400 font-mono">{{ plan.nameEn }}</span>
            </div>
            <p class="text-sm text-slate-500 dark:text-slate-400">{{ plan.description }}</p>
          </div>
          <div class="mb-6 min-h-[64px]">
            <div class="flex items-baseline gap-2">
              <span class="text-3xl font-extrabold font-mono text-slate-900 dark:text-white">{{ plan.priceText }}</span>
            </div>
            <p class="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">{{ plan.period }}</p>
          </div>
          <ul class="flex-1 space-y-3 mb-6">
            <li v-for="(f, idx) in plan.features" :key="idx" class="flex items-start gap-2.5">
              <svg v-if="f.included" class="w-5 h-5 text-emerald-500 dark:text-emerald-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/>
              </svg>
              <svg v-else class="w-5 h-5 text-slate-400 dark:text-slate-600 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
              </svg>
              <span :class="f.included ? 'text-slate-700 dark:text-slate-300 text-sm' : 'text-slate-400 dark:text-slate-500 text-sm'">{{ f.text }}</span>
            </li>
          </ul>
          <button @click="router.push('/register')"
            :class="['w-full py-3 px-4 rounded-xl font-semibold text-sm transition-all',
                     plan.highlighted ? 'bg-accent-grad glow-accent text-white hover:opacity-90' : 'bg-white/10 text-white border border-white/10 hover:bg-white/15']">
            {{ plan.cta }}
          </button>
        </div>
      </div>
    </section>

    <!-- How it works -->
    <section class="py-16 px-4">
      <div class="max-w-5xl mx-auto">
        <h2 class="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white text-center mb-10">كيف يعمل؟</h2>
        <div class="grid grid-cols-1 sm:grid-cols-4 gap-6">
          <div v-for="s in steps" :key="s.n" class="card card-hover p-5 text-center">
            <div class="w-10 h-10 mx-auto mb-3 rounded-full bg-accent-grad glow-accent text-white flex items-center justify-center font-bold font-mono">{{ s.n }}</div>
            <h3 class="font-semibold text-slate-900 dark:text-white mb-1">{{ s.title }}</h3>
            <p class="text-sm text-slate-500 dark:text-slate-400">{{ s.text }}</p>
          </div>
        </div>
      </div>
    </section>

    <!-- FAQ -->
    <section class="py-16 px-4">
      <div class="max-w-3xl mx-auto">
        <h2 class="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white text-center mb-10">أسئلة شائعة</h2>
        <div class="space-y-3">
          <div v-for="(faq, i) in faqs" :key="i" class="card overflow-hidden">
            <button @click="faq.open = !faq.open" class="w-full flex items-center justify-between p-4 text-right hover:bg-gray-50 dark:hover:bg-white/5 transition-colors">
              <span class="font-medium text-slate-900 dark:text-white">{{ faq.question }}</span>
              <svg :class="['w-5 h-5 text-slate-400 transition-transform', faq.open ? 'rotate-180' : '']" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
              </svg>
            </button>
            <div v-if="faq.open" class="px-4 pb-4 text-sm text-slate-700 dark:text-slate-300 leading-relaxed">{{ faq.answer }}</div>
          </div>
        </div>
      </div>
    </section>

    <!-- CTA -->
    <section class="py-16 text-center px-4">
      <h2 class="text-2xl sm:text-3xl font-bold text-white mb-3">جاهز تبدأ؟</h2>
      <p class="text-slate-300 mb-6">افحص موقعك مجاناً خلال دقائق.</p>
      <button @click="router.push('/register')" class="px-8 py-3 bg-accent-grad glow-accent text-white rounded-xl font-semibold hover:opacity-90 transition-all">
        أنشئ حساباً مجانياً
      </button>
    </section>
  </div>
</template>
