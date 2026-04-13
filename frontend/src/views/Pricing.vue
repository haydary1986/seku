<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useSEO } from '../composables/useSEO'

useSEO({
  title: 'الأسعار والخطط — Pricing',
  description: 'خطط أسعار سيكو: مجاني للأبد، ابتدائي $49، أساسي $149، احترافي $499، أعمال $1,499. خصم 17% للاشتراك السنوي. خصم خاص للجامعات.',
  keywords: 'أسعار سيكو, خطط Seku, vulnerability scanner pricing, security audit cost',
})

const router = useRouter()
const billingCycle = ref('monthly') // 'monthly' or 'yearly'

const plansData = [
  {
    name: 'مجاني',
    nameEn: 'Free',
    monthlyPrice: 0,
    yearlyPrice: 0,
    description: 'جرّب سيكو لموقع واحد',
    audience: 'للأفراد والتجربة',
    cta: 'ابدأ مجاناً',
    ctaStyle: 'bg-gray-900 text-white hover:bg-gray-800',
    highlighted: false,
    features: [
      { text: 'موقع واحد', included: true },
      { text: '5 فحوصات شهرياً', included: true },
      { text: '5 فئات أمان أساسية', included: true },
      { text: 'سجل الفحوصات لـ 7 أيام', included: true },
      { text: 'تقارير PDF', included: false },
      { text: 'تحليل AI', included: false },
      { text: 'دعم مجتمعي', included: true },
    ],
  },
  {
    name: 'ابتدائي',
    nameEn: 'Starter',
    monthlyPrice: 49,
    yearlyPrice: 490,
    description: 'للمطورين والمواقع التجارية الصغيرة',
    audience: 'مواقع شخصية وشركات صغيرة',
    cta: 'اشترك الآن',
    ctaStyle: 'bg-gray-900 text-white hover:bg-gray-800',
    highlighted: false,
    features: [
      { text: '5 مواقع', included: true },
      { text: '25 فحص شهرياً', included: true },
      { text: '13 فئة أمان', included: true },
      { text: 'تقارير PDF', included: true },
      { text: 'تحليل AI (10 شهرياً)', included: true },
      { text: 'فحص أسبوعي مجدول', included: true },
      { text: 'تنبيهات البريد', included: true },
      { text: 'سجل لـ 30 يوم', included: true },
    ],
  },
  {
    name: 'أساسي',
    nameEn: 'Basic',
    monthlyPrice: 149,
    yearlyPrice: 1490,
    description: 'للكليات الأهلية والمؤسسات التعليمية الصغيرة',
    audience: 'كلية أهلية صغيرة',
    cta: 'اشترك الآن',
    ctaStyle: 'bg-gray-900 text-white hover:bg-gray-800',
    highlighted: false,
    features: [
      { text: '15 موقعاً', included: true },
      { text: '100 فحص شهرياً', included: true },
      { text: '22 فئة أمان', included: true },
      { text: 'تقارير PDF بشعارك', included: true },
      { text: 'تحليل AI غير محدود', included: true },
      { text: 'فحص يومي مجدول', included: true },
      { text: 'Webhooks (Slack/Telegram)', included: true },
      { text: 'وصول API للقراءة', included: true },
      { text: 'سجل لـ 180 يوم', included: true },
      { text: 'دعم سريع (24 ساعة)', included: true },
    ],
  },
  {
    name: 'احترافي',
    nameEn: 'Pro',
    monthlyPrice: 499,
    yearlyPrice: 4990,
    description: 'للجامعات الأهلية المتوسطة',
    audience: 'جامعة أهلية متوسطة',
    cta: 'ابدأ تجربة 14 يوم',
    ctaStyle: 'bg-indigo-600 text-white hover:bg-indigo-700 shadow-lg shadow-indigo-200',
    highlighted: true,
    badge: 'الأكثر شعبية',
    features: [
      { text: '50 موقعاً', included: true },
      { text: '500 فحص شهرياً', included: true },
      { text: '28 فئة أمان متقدمة', included: true },
      { text: 'تحليل AI غير محدود', included: true },
      { text: 'فحص يومي مجدول', included: true },
      { text: 'API كامل + جميع Webhooks', included: true },
      { text: 'اكتشاف النطاقات (Discovery)', included: true },
      { text: 'فحص تسريب البيانات', included: true },
      { text: 'لوحة WAF متكاملة', included: true },
      { text: 'إنشاء تذاكر GitHub/Jira', included: true },
      { text: 'سجل لسنة كاملة', included: true },
      { text: 'دعم سريع (8 ساعات)', included: true },
    ],
  },
  {
    name: 'أعمال',
    nameEn: 'Business',
    monthlyPrice: 1499,
    yearlyPrice: 14990,
    description: 'للجامعات الكبرى والشركات',
    audience: 'جامعة كبرى أو شركة',
    cta: 'اطلب عرضاً',
    ctaStyle: 'bg-amber-600 text-white hover:bg-amber-700 shadow-lg shadow-amber-200',
    highlighted: false,
    badge: 'للجامعات الكبرى',
    features: [
      { text: '200 موقع', included: true },
      { text: '2,000 فحص شهرياً', included: true },
      { text: 'جميع الـ 32 فئة أمنية', included: true },
      { text: 'فحص كل ساعة', included: true },
      { text: 'مولّد الأوامر الإدارية', included: true },
      { text: 'إدارة منظمات متعددة', included: true },
      { text: 'علامة تجارية مخصصة', included: true },
      { text: 'تقارير الامتثال (GDPR/ISO)', included: true },
      { text: 'سجل لسنتين', included: true },
      { text: 'مدير نجاح عملاء مخصص', included: true },
      { text: 'استجابة خلال 4 ساعات', included: true },
      { text: 'جلسة تأهيل وتدريب', included: true },
    ],
  },
  {
    name: 'مؤسسي',
    nameEn: 'Enterprise',
    monthlyPrice: null,
    yearlyPrice: null,
    description: 'للوزارات والجهات الحكومية',
    audience: 'وزارة أو جهة حكومية',
    cta: 'اتصل بنا',
    ctaStyle: 'bg-gray-900 text-white hover:bg-gray-800',
    highlighted: false,
    fromPrice: 'من $3,000/شهرياً',
    features: [
      { text: 'مواقع وفحوصات غير محدودة', included: true },
      { text: 'جميع الميزات', included: true },
      { text: 'نشر محلي (On-premise)', included: true },
      { text: 'تنصيب معزول (Air-gapped)', included: true },
      { text: 'SAML/SSO/LDAP', included: true },
      { text: 'تطوير ماسحات مخصصة', included: true },
      { text: 'الوصول للسورس كود', included: true },
      { text: 'مراجعة أمنية ربع سنوية', included: true },
      { text: 'دعم 24/7 هاتفياً', included: true },
      { text: 'SLA 99.9% + غرامات', included: true },
      { text: 'تدريب في موقعكم', included: true },
    ],
  },
]

const plans = computed(() => plansData.map(p => ({
  ...p,
  price: p.monthlyPrice === null ? null : (billingCycle.value === 'yearly' ? p.yearlyPrice : p.monthlyPrice),
  period: p.monthlyPrice === null ? '' : (billingCycle.value === 'yearly' ? '/سنوياً' : '/شهرياً'),
  yearlyDiscount: p.monthlyPrice && p.yearlyPrice ? Math.round((1 - p.yearlyPrice / (p.monthlyPrice * 12)) * 100) : 0,
})))

const faqs = ref([
  {
    question: 'هل الخطة المجانية تنتهي؟',
    answer: 'لا — الخطة المجانية مجانية للأبد. تشمل موقعاً واحداً و5 فحوصات شهرياً. لا تحتاج بطاقة ائتمان.',
    open: false,
  },
  {
    question: 'هل يمكنني تغيير خطتي في أي وقت؟',
    answer: 'نعم، يمكنك الترقية أو تخفيض خطتك في أي وقت. عند الترقية يُحتسب الفرق تناسبياً، وعند التخفيض يبدأ التخفيض من الدورة الفوترية التالية.',
    open: false,
  },
  {
    question: 'ما الفرق بين الفوترة الشهرية والسنوية؟',
    answer: 'الفوترة السنوية توفّر لك حوالي 17% (شهران مجاناً). يمكنك التبديل بين النظامين في أي وقت.',
    open: false,
  },
  {
    question: 'هل تقدمون خصومات للمؤسسات التعليمية؟',
    answer: 'نعم، نقدم خصماً خاصاً بنسبة 30% للجامعات والكليات والمدارس. تواصل معنا عبر sales@irtikaz.tech لتفعيل الخصم.',
    open: false,
  },
  {
    question: 'هل يمكنني تجربة الخطة الاحترافية قبل الشراء؟',
    answer: 'نعم، نقدم تجربة مجانية لمدة 14 يوماً على الخطة الاحترافية بكامل ميزاتها — بدون الحاجة لبطاقة ائتمان.',
    open: false,
  },
  {
    question: 'ما هي طرق الدفع المتاحة؟',
    answer: 'نقبل بطاقات الائتمان (Visa, Mastercard, Mada)، التحويل البنكي، والدفع الإلكتروني. للخطة المؤسسية يمكن الدفع عبر أمر شراء رسمي وفاتورة.',
    open: false,
  },
  {
    question: 'ماذا يحدث إذا تجاوزت حد الفحوصات الشهرية؟',
    answer: 'سيتم إيقاف الفحوصات الجديدة مؤقتاً حتى بداية الشهر التالي. تستمر بالوصول لكامل النتائج السابقة. يمكنك الترقية في أي لحظة لاستئناف الفحص.',
    open: false,
  },
  {
    question: 'هل بياناتي آمنة؟',
    answer: 'نعم — جميع البيانات مشفرة أثناء النقل (TLS 1.3) والتخزين (AES-256). نلتزم بمعايير ISO 27001 ولا نشارك بياناتك مع أي طرف ثالث. يمكنك حذف بياناتك بالكامل في أي وقت.',
    open: false,
  },
  {
    question: 'هل تقدمون خيار النشر المحلي (On-premise)؟',
    answer: 'نعم — متاح في الخطة المؤسسية. يمكن نشر سيكو على سيرفراتك الخاصة أو في مركز بيانات الجامعة بدون أي اتصال خارجي.',
    open: false,
  },
])

function toggleFaq(index) {
  faqs.value[index].open = !faqs.value[index].open
}
</script>

<template>
  <div class="min-h-screen bg-white" dir="rtl">

    <!-- Navbar -->
    <nav class="bg-white/80 backdrop-blur-md border-b border-gray-100 sticky top-0 z-50">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex items-center justify-between h-16">
          <div class="flex items-center gap-3">
            <router-link to="/" class="flex items-center gap-3">
              <div class="w-9 h-9 bg-indigo-600 rounded-lg flex items-center justify-center">
                <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                </svg>
              </div>
              <span class="text-xl font-bold text-gray-900">Seku</span>
            </router-link>
          </div>
          <div class="flex items-center gap-4">
            <router-link to="/methodology-ar" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">معايير التقييم</router-link>
            <router-link to="/pricing" class="text-sm text-indigo-600 font-medium">الأسعار</router-link>
            <router-link to="/login" class="px-5 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 transition-colors">
              تسجيل الدخول
            </router-link>
          </div>
        </div>
      </div>
    </nav>

    <!-- Gradient Header -->
    <section class="relative overflow-hidden">
      <div class="absolute inset-0 bg-gradient-to-br from-indigo-600 via-indigo-700 to-purple-800"></div>
      <div class="absolute top-0 left-0 w-96 h-96 bg-white/10 rounded-full blur-3xl -translate-x-1/2 -translate-y-1/2"></div>
      <div class="absolute bottom-0 right-0 w-96 h-96 bg-purple-400/20 rounded-full blur-3xl translate-x-1/2 translate-y-1/2"></div>

      <div class="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 sm:py-20 text-center">
        <h1 class="text-4xl sm:text-5xl font-extrabold text-white tracking-tight">
          خطط الأسعار
        </h1>
        <p class="mt-4 text-lg sm:text-xl text-indigo-100 max-w-2xl mx-auto">
          ابدأ مجاناً بفحص موقع واحد، وارقِ متى احتجت ميزات أكثر.
        </p>

        <!-- Billing Toggle -->
        <div class="mt-8 inline-flex items-center bg-white/10 backdrop-blur-sm rounded-full p-1 border border-white/20">
          <button @click="billingCycle = 'monthly'"
            :class="billingCycle === 'monthly' ? 'bg-white text-indigo-700 shadow' : 'text-white'"
            class="px-6 py-2 rounded-full text-sm font-semibold transition-all">
            شهرياً
          </button>
          <button @click="billingCycle = 'yearly'"
            :class="billingCycle === 'yearly' ? 'bg-white text-indigo-700 shadow' : 'text-white'"
            class="px-6 py-2 rounded-full text-sm font-semibold transition-all flex items-center gap-2">
            سنوياً
            <span class="bg-green-400 text-green-900 text-[10px] font-bold px-2 py-0.5 rounded-full">وفّر 17%</span>
          </button>
        </div>
      </div>
    </section>

    <!-- Pricing Cards -->
    <section class="relative -mt-10 pb-20">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">

          <div
            v-for="plan in plans"
            :key="plan.nameEn"
            :class="[
              'relative bg-white rounded-2xl border-2 p-6 flex flex-col transition-all hover:shadow-xl',
              plan.highlighted
                ? 'border-indigo-500 shadow-xl shadow-indigo-100 scale-[1.02]'
                : 'border-gray-200 shadow-sm'
            ]"
          >
            <!-- Badge -->
            <div v-if="plan.badge" :class="plan.highlighted ? 'bg-indigo-600' : 'bg-amber-600'"
              class="absolute -top-3.5 right-4 text-white text-xs font-bold px-4 py-1.5 rounded-full shadow-md">
              {{ plan.badge }}
            </div>

            <!-- Plan Name -->
            <div class="mb-4">
              <div class="flex items-center gap-2 mb-1">
                <h3 class="text-lg font-bold text-gray-900">{{ plan.name }}</h3>
                <span class="text-xs text-gray-400">{{ plan.nameEn }}</span>
              </div>
              <p class="text-sm text-gray-500">{{ plan.description }}</p>
              <p v-if="plan.audience" class="text-xs text-indigo-500 mt-1 font-medium">{{ plan.audience }}</p>
            </div>

            <!-- Price -->
            <div class="mb-6 min-h-[60px]">
              <div v-if="plan.price !== null && plan.price !== 0" class="flex items-baseline gap-1">
                <span class="text-3xl font-extrabold text-gray-900">${{ plan.price.toLocaleString() }}</span>
                <span v-if="plan.period" class="text-sm text-gray-500">{{ plan.period }}</span>
              </div>
              <div v-else-if="plan.price === 0" class="text-3xl font-extrabold text-gray-900">$0</div>
              <div v-else-if="plan.fromPrice" class="text-xl font-bold text-gray-900">{{ plan.fromPrice }}</div>
              <div v-else class="text-xl font-bold text-gray-900">اتصل بنا</div>
              <p v-if="billingCycle === 'yearly' && plan.yearlyDiscount > 0" class="text-xs text-green-600 font-semibold mt-1">
                وفّر {{ plan.yearlyDiscount }}%
              </p>
              <p v-else-if="billingCycle === 'monthly' && plan.monthlyPrice === 0" class="text-xs text-gray-500 mt-1">
                مجاناً للأبد
              </p>
            </div>

            <!-- Features List -->
            <ul class="flex-1 space-y-3 mb-6">
              <li v-for="(feature, idx) in plan.features" :key="idx" class="flex items-start gap-2.5">
                <!-- Checkmark -->
                <svg v-if="feature.included" class="w-5 h-5 text-green-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/>
                </svg>
                <!-- X mark -->
                <svg v-else class="w-5 h-5 text-gray-300 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
                <span :class="feature.included ? 'text-gray-700 text-sm' : 'text-gray-400 text-sm'">
                  {{ feature.text }}
                </span>
              </li>
            </ul>

            <!-- CTA Button -->
            <button
              :class="['w-full py-3 px-4 rounded-xl font-semibold text-sm transition-all', plan.ctaStyle]"
              @click="plan.price === null ? null : router.push('/login')"
            >
              {{ plan.cta }}
            </button>
          </div>

        </div>
      </div>
    </section>

    <!-- Comparison Table (Desktop) -->
    <section class="py-16 bg-gray-50">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 class="text-2xl sm:text-3xl font-bold text-gray-900 text-center mb-10">مقارنة تفصيلية بين الخطط</h2>

        <div class="overflow-x-auto">
          <table class="w-full text-sm min-w-[800px]">
            <thead>
              <tr class="border-b-2 border-gray-200">
                <th class="py-4 px-3 text-right font-semibold text-gray-600">الميزة</th>
                <th class="py-4 px-3 text-center font-semibold text-gray-600">مجاني</th>
                <th class="py-4 px-3 text-center font-semibold text-gray-600">ابتدائي</th>
                <th class="py-4 px-3 text-center font-semibold text-gray-600">أساسي</th>
                <th class="py-4 px-3 text-center font-semibold text-indigo-600 bg-indigo-50 rounded-t-lg">احترافي</th>
                <th class="py-4 px-3 text-center font-semibold text-amber-700 bg-amber-50">أعمال</th>
                <th class="py-4 px-3 text-center font-semibold text-gray-600">مؤسسي</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">السعر الشهري</td>
                <td class="py-3 px-3 text-center text-gray-600">$0</td>
                <td class="py-3 px-3 text-center text-gray-600">$49</td>
                <td class="py-3 px-3 text-center text-gray-600">$149</td>
                <td class="py-3 px-3 text-center text-gray-900 font-bold bg-indigo-50/50">$499</td>
                <td class="py-3 px-3 text-center text-amber-700 font-bold bg-amber-50/50">$1,499</td>
                <td class="py-3 px-3 text-center text-gray-600">من $3,000</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">عدد المواقع</td>
                <td class="py-3 px-3 text-center text-gray-600">1</td>
                <td class="py-3 px-3 text-center text-gray-600">5</td>
                <td class="py-3 px-3 text-center text-gray-600">15</td>
                <td class="py-3 px-3 text-center text-gray-900 font-semibold bg-indigo-50/50">50</td>
                <td class="py-3 px-3 text-center text-gray-700 font-semibold bg-amber-50/50">200</td>
                <td class="py-3 px-3 text-center text-gray-600">غير محدود</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">الفحوصات شهرياً</td>
                <td class="py-3 px-3 text-center text-gray-600">5</td>
                <td class="py-3 px-3 text-center text-gray-600">25</td>
                <td class="py-3 px-3 text-center text-gray-600">100</td>
                <td class="py-3 px-3 text-center text-gray-900 font-semibold bg-indigo-50/50">500</td>
                <td class="py-3 px-3 text-center text-gray-700 font-semibold bg-amber-50/50">2,000</td>
                <td class="py-3 px-3 text-center text-gray-600">غير محدود</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">عدد المستخدمين</td>
                <td class="py-3 px-3 text-center text-gray-600">1</td>
                <td class="py-3 px-3 text-center text-gray-600">2</td>
                <td class="py-3 px-3 text-center text-gray-600">5</td>
                <td class="py-3 px-3 text-center text-gray-900 font-semibold bg-indigo-50/50">15</td>
                <td class="py-3 px-3 text-center text-gray-700 font-semibold bg-amber-50/50">50</td>
                <td class="py-3 px-3 text-center text-gray-600">غير محدود</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">فئات الأمان</td>
                <td class="py-3 px-3 text-center text-gray-600">5</td>
                <td class="py-3 px-3 text-center text-gray-600">13</td>
                <td class="py-3 px-3 text-center text-gray-600">22</td>
                <td class="py-3 px-3 text-center text-gray-900 font-semibold bg-indigo-50/50">28</td>
                <td class="py-3 px-3 text-center text-gray-700 font-semibold bg-amber-50/50">32</td>
                <td class="py-3 px-3 text-center text-gray-600">32</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">تحليل AI</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center text-gray-600">10/شهر</td>
                <td class="py-3 px-3 text-center text-gray-600">غير محدود</td>
                <td class="py-3 px-3 text-center text-gray-900 font-semibold bg-indigo-50/50">غير محدود</td>
                <td class="py-3 px-3 text-center text-gray-700 bg-amber-50/50">غير محدود</td>
                <td class="py-3 px-3 text-center text-gray-600">غير محدود</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">تقارير PDF</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center text-green-500">✓</td>
                <td class="py-3 px-3 text-center text-green-500">✓ بشعارك</td>
                <td class="py-3 px-3 text-center text-green-500 bg-indigo-50/50">✓ بشعارك</td>
                <td class="py-3 px-3 text-center text-green-500 bg-amber-50/50">✓ White-label</td>
                <td class="py-3 px-3 text-center text-green-500">✓ مخصص بالكامل</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">فحوصات مجدولة</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center text-gray-600">أسبوعية</td>
                <td class="py-3 px-3 text-center text-gray-600">يومية</td>
                <td class="py-3 px-3 text-center text-gray-900 font-semibold bg-indigo-50/50">يومية</td>
                <td class="py-3 px-3 text-center text-gray-700 bg-amber-50/50">كل ساعة</td>
                <td class="py-3 px-3 text-center text-gray-600">مخصصة</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">وصول API</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center text-gray-600">قراءة</td>
                <td class="py-3 px-3 text-center text-gray-900 font-semibold bg-indigo-50/50">كامل</td>
                <td class="py-3 px-3 text-center text-gray-700 bg-amber-50/50">كامل + SLA</td>
                <td class="py-3 px-3 text-center text-gray-600">كامل + Premium</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">Webhooks</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center text-green-500">✓</td>
                <td class="py-3 px-3 text-center text-green-500 bg-indigo-50/50">✓</td>
                <td class="py-3 px-3 text-center text-green-500 bg-amber-50/50">✓</td>
                <td class="py-3 px-3 text-center text-green-500">✓</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">اكتشاف النطاقات</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center text-green-500 bg-indigo-50/50">✓</td>
                <td class="py-3 px-3 text-center text-green-500 bg-amber-50/50">✓</td>
                <td class="py-3 px-3 text-center text-green-500">✓</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">فحص تسريب البيانات</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center text-green-500 bg-indigo-50/50">✓</td>
                <td class="py-3 px-3 text-center text-green-500 bg-amber-50/50">✓</td>
                <td class="py-3 px-3 text-center text-green-500">✓</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">مولّد الأوامر الإدارية</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center bg-indigo-50/50">—</td>
                <td class="py-3 px-3 text-center text-green-500 bg-amber-50/50">✓</td>
                <td class="py-3 px-3 text-center text-green-500">✓</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">إدارة منظمات متعددة</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center bg-indigo-50/50">—</td>
                <td class="py-3 px-3 text-center text-green-500 bg-amber-50/50">✓</td>
                <td class="py-3 px-3 text-center text-green-500">✓</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">سجل الفحوصات</td>
                <td class="py-3 px-3 text-center text-gray-600">7 أيام</td>
                <td class="py-3 px-3 text-center text-gray-600">30 يوم</td>
                <td class="py-3 px-3 text-center text-gray-600">180 يوم</td>
                <td class="py-3 px-3 text-center text-gray-900 font-semibold bg-indigo-50/50">سنة</td>
                <td class="py-3 px-3 text-center text-gray-700 bg-amber-50/50">سنتان</td>
                <td class="py-3 px-3 text-center text-gray-600">غير محدود</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">نشر محلي (On-premise)</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center bg-indigo-50/50">—</td>
                <td class="py-3 px-3 text-center bg-amber-50/50">—</td>
                <td class="py-3 px-3 text-center text-green-500">✓</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">SAML/SSO</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center">—</td>
                <td class="py-3 px-3 text-center bg-indigo-50/50">—</td>
                <td class="py-3 px-3 text-center bg-amber-50/50">—</td>
                <td class="py-3 px-3 text-center text-green-500">✓</td>
              </tr>
              <tr>
                <td class="py-3 px-3 text-gray-700 font-medium">الدعم الفني</td>
                <td class="py-3 px-3 text-center text-gray-600 text-xs">مجتمعي</td>
                <td class="py-3 px-3 text-center text-gray-600 text-xs">بريد 72س</td>
                <td class="py-3 px-3 text-center text-gray-600 text-xs">24 ساعة</td>
                <td class="py-3 px-3 text-center text-gray-900 font-semibold bg-indigo-50/50 text-xs">8 ساعات</td>
                <td class="py-3 px-3 text-center text-gray-700 bg-amber-50/50 text-xs">4 ساعات + CSM</td>
                <td class="py-3 px-3 text-center text-gray-600 text-xs">24/7 + فريق</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- FAQ Section -->
    <section class="py-16 bg-white">
      <div class="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 class="text-2xl sm:text-3xl font-bold text-gray-900 text-center mb-10">الأسئلة الشائعة</h2>

        <div class="space-y-3">
          <div
            v-for="(faq, index) in faqs"
            :key="index"
            class="border border-gray-200 rounded-xl overflow-hidden"
          >
            <button
              @click="toggleFaq(index)"
              class="w-full flex items-center justify-between p-5 text-right bg-white hover:bg-gray-50 transition-colors"
            >
              <span class="text-base font-semibold text-gray-900">{{ faq.question }}</span>
              <svg
                :class="['w-5 h-5 text-gray-400 transition-transform shrink-0 mr-4', faq.open ? 'rotate-180' : '']"
                fill="none" stroke="currentColor" viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
              </svg>
            </button>
            <div v-if="faq.open" class="px-5 pb-5 text-sm text-gray-600 leading-relaxed">
              {{ faq.answer }}
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- CTA -->
    <section class="py-16 bg-indigo-600">
      <div class="max-w-4xl mx-auto px-4 text-center">
        <h2 class="text-3xl font-bold text-white mb-4">جاهز لتأمين مواقعك؟</h2>
        <p class="text-lg text-indigo-100 mb-8">ابدأ بالخطة المجانية وقم بالترقية في أي وقت</p>
        <router-link to="/login" class="inline-block px-8 py-4 bg-white text-indigo-600 font-bold rounded-xl hover:bg-indigo-50 transition-colors shadow-lg text-lg">
          ابدأ الآن مجاناً
        </router-link>
      </div>
    </section>

    <!-- Footer -->
    <footer class="bg-slate-900 text-gray-400 py-12">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center">
              <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
              </svg>
            </div>
            <span class="text-white font-bold">Seku</span>
          </div>
          <div class="flex gap-6 text-sm">
            <router-link to="/" class="hover:text-white transition-colors">الرئيسية</router-link>
            <router-link to="/pricing" class="hover:text-white transition-colors">الأسعار</router-link>
            <router-link to="/methodology-ar" class="hover:text-white transition-colors">معايير التقييم</router-link>
            <router-link to="/login" class="hover:text-white transition-colors">تسجيل الدخول</router-link>
          </div>
          <p class="text-sm">&copy; 2026 Seku. جميع الحقوق محفوظة</p>
        </div>
      </div>
    </footer>
  </div>
</template>
