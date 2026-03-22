<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()

const plans = [
  {
    name: 'مجاني',
    nameEn: 'Free',
    price: '0',
    period: '',
    description: 'للتجربة والاستكشاف',
    cta: 'ابدأ مجاناً',
    ctaStyle: 'bg-gray-900 text-white hover:bg-gray-800',
    highlighted: false,
    features: [
      { text: '5 مواقع', included: true },
      { text: '10 فحوصات/شهر', included: true },
      { text: 'مستخدم واحد', included: true },
      { text: 'تحليل بالذكاء الاصطناعي', included: false },
      { text: 'تقارير PDF', included: false },
      { text: 'فحوصات مجدولة', included: false },
      { text: 'وصول API', included: false },
      { text: 'تنبيهات البريد الإلكتروني', included: false },
      { text: 'دعم المجتمع', included: true },
    ],
  },
  {
    name: 'أساسي',
    nameEn: 'Basic',
    price: '29',
    period: '/شهرياً',
    description: 'للفرق الصغيرة والمشاريع الناشئة',
    cta: 'اشترك الآن',
    ctaStyle: 'bg-gray-900 text-white hover:bg-gray-800',
    highlighted: false,
    features: [
      { text: '25 موقع', included: true },
      { text: '50 فحص/شهر', included: true },
      { text: '5 مستخدمين', included: true },
      { text: '10 تحليلات AI/شهر', included: true },
      { text: 'تقارير PDF', included: true },
      { text: 'فحوصات أسبوعية مجدولة', included: true },
      { text: 'وصول API للقراءة فقط', included: true },
      { text: 'تنبيهات البريد الإلكتروني', included: true },
      { text: 'دعم عبر البريد الإلكتروني', included: true },
    ],
  },
  {
    name: 'احترافي',
    nameEn: 'Pro',
    price: '99',
    period: '/شهرياً',
    description: 'للمؤسسات التعليمية والحكومية',
    cta: 'اشترك الآن',
    ctaStyle: 'bg-indigo-600 text-white hover:bg-indigo-700 shadow-lg shadow-indigo-200',
    highlighted: true,
    badge: 'الأكثر شعبية',
    features: [
      { text: '100 موقع', included: true },
      { text: '200 فحص/شهر', included: true },
      { text: '20 مستخدم', included: true },
      { text: '50 تحليل AI/شهر', included: true },
      { text: 'تقارير PDF', included: true },
      { text: 'فحوصات يومية مجدولة', included: true },
      { text: 'وصول API كامل', included: true },
      { text: 'تنبيهات البريد الإلكتروني', included: true },
      { text: 'دعم ذو أولوية', included: true },
    ],
  },
  {
    name: 'مؤسسي',
    nameEn: 'Enterprise',
    price: null,
    period: '',
    description: 'للوزارات والجهات الكبرى',
    cta: 'اتصل بنا',
    ctaStyle: 'bg-gray-900 text-white hover:bg-gray-800',
    highlighted: false,
    features: [
      { text: 'مواقع غير محدودة', included: true },
      { text: 'فحوصات غير محدودة', included: true },
      { text: 'مستخدمون غير محدودون', included: true },
      { text: 'تحليلات AI غير محدودة', included: true },
      { text: 'تقارير PDF', included: true },
      { text: 'جدولة مخصصة', included: true },
      { text: 'وصول API كامل', included: true },
      { text: 'تنبيهات البريد الإلكتروني', included: true },
      { text: 'دعم مخصص', included: true },
    ],
  },
]

const faqs = ref([
  {
    question: 'هل يمكنني تغيير خطتي في أي وقت؟',
    answer: 'نعم، يمكنك الترقية أو تخفيض خطتك في أي وقت. سيتم احتساب الفرق بشكل تناسبي.',
    open: false,
  },
  {
    question: 'هل تقدمون خصومات للمؤسسات التعليمية؟',
    answer: 'نعم، نقدم خصماً خاصاً بنسبة 30% للجامعات والمؤسسات التعليمية الحكومية. تواصل معنا للحصول على التفاصيل.',
    open: false,
  },
  {
    question: 'ما هي طرق الدفع المتاحة؟',
    answer: 'نقبل بطاقات الائتمان (Visa, Mastercard) والتحويل البنكي. للخطة المؤسسية يمكن الدفع عبر أمر شراء رسمي.',
    open: false,
  },
  {
    question: 'هل يمكنني تجربة الخطة الاحترافية مجاناً؟',
    answer: 'نعم، نقدم فترة تجريبية مجانية لمدة 14 يوماً على الخطة الاحترافية بدون الحاجة لبطاقة ائتمان.',
    open: false,
  },
  {
    question: 'ماذا يحدث إذا تجاوزت حد الفحوصات الشهرية؟',
    answer: 'سيتم إيقاف الفحوصات مؤقتاً حتى بداية الشهر التالي. يمكنك الترقية لخطة أعلى للحصول على المزيد من الفحوصات.',
    open: false,
  },
  {
    question: 'هل البيانات والتقارير آمنة؟',
    answer: 'نعم، جميع البيانات مشفرة أثناء النقل والتخزين. نلتزم بأعلى معايير أمان المعلومات ولا نشارك بياناتك مع أي طرف ثالث.',
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
              <span class="text-xl font-bold text-gray-900">VScan</span>
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
          اختر الخطة المناسبة لاحتياجاتك. جميع الخطط تشمل الوصول الكامل لمنصة الفحص الأمني.
        </p>
      </div>
    </section>

    <!-- Pricing Cards -->
    <section class="relative -mt-10 pb-20">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">

          <div
            v-for="plan in plans"
            :key="plan.nameEn"
            :class="[
              'relative bg-white rounded-2xl border-2 p-6 flex flex-col transition-all hover:shadow-xl',
              plan.highlighted
                ? 'border-indigo-500 shadow-xl shadow-indigo-100 scale-[1.02] lg:scale-105'
                : 'border-gray-200 shadow-sm'
            ]"
          >
            <!-- Badge -->
            <div v-if="plan.badge" class="absolute -top-3.5 right-4 bg-indigo-600 text-white text-xs font-bold px-4 py-1.5 rounded-full shadow-md">
              {{ plan.badge }}
            </div>

            <!-- Plan Name -->
            <div class="mb-4">
              <h3 class="text-lg font-bold text-gray-900">{{ plan.name }}</h3>
              <p class="text-sm text-gray-500 mt-1">{{ plan.description }}</p>
            </div>

            <!-- Price -->
            <div class="mb-6">
              <div v-if="plan.price !== null" class="flex items-baseline gap-1">
                <span class="text-4xl font-extrabold text-gray-900">${{ plan.price }}</span>
                <span v-if="plan.period" class="text-sm text-gray-500">{{ plan.period }}</span>
              </div>
              <div v-else class="text-2xl font-bold text-gray-900">
                اتصل بنا
              </div>
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
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b-2 border-gray-200">
                <th class="py-4 px-4 text-right font-semibold text-gray-600 w-1/5">الميزة</th>
                <th class="py-4 px-4 text-center font-semibold text-gray-600">مجاني</th>
                <th class="py-4 px-4 text-center font-semibold text-gray-600">أساسي</th>
                <th class="py-4 px-4 text-center font-semibold text-indigo-600 bg-indigo-50 rounded-t-lg">احترافي</th>
                <th class="py-4 px-4 text-center font-semibold text-gray-600">مؤسسي</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
              <tr>
                <td class="py-3 px-4 text-gray-700 font-medium">المواقع</td>
                <td class="py-3 px-4 text-center text-gray-600">5</td>
                <td class="py-3 px-4 text-center text-gray-600">25</td>
                <td class="py-3 px-4 text-center text-gray-900 font-semibold bg-indigo-50/50">100</td>
                <td class="py-3 px-4 text-center text-gray-600">غير محدود</td>
              </tr>
              <tr>
                <td class="py-3 px-4 text-gray-700 font-medium">الفحوصات/شهر</td>
                <td class="py-3 px-4 text-center text-gray-600">10</td>
                <td class="py-3 px-4 text-center text-gray-600">50</td>
                <td class="py-3 px-4 text-center text-gray-900 font-semibold bg-indigo-50/50">200</td>
                <td class="py-3 px-4 text-center text-gray-600">غير محدود</td>
              </tr>
              <tr>
                <td class="py-3 px-4 text-gray-700 font-medium">المستخدمون</td>
                <td class="py-3 px-4 text-center text-gray-600">1</td>
                <td class="py-3 px-4 text-center text-gray-600">5</td>
                <td class="py-3 px-4 text-center text-gray-900 font-semibold bg-indigo-50/50">20</td>
                <td class="py-3 px-4 text-center text-gray-600">غير محدود</td>
              </tr>
              <tr>
                <td class="py-3 px-4 text-gray-700 font-medium">تحليل AI</td>
                <td class="py-3 px-4 text-center">
                  <svg class="w-5 h-5 text-gray-300 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </td>
                <td class="py-3 px-4 text-center text-gray-600">10/شهر</td>
                <td class="py-3 px-4 text-center text-gray-900 font-semibold bg-indigo-50/50">50/شهر</td>
                <td class="py-3 px-4 text-center text-gray-600">غير محدود</td>
              </tr>
              <tr>
                <td class="py-3 px-4 text-gray-700 font-medium">تقارير PDF</td>
                <td class="py-3 px-4 text-center">
                  <svg class="w-5 h-5 text-gray-300 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </td>
                <td class="py-3 px-4 text-center">
                  <svg class="w-5 h-5 text-green-500 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                </td>
                <td class="py-3 px-4 text-center bg-indigo-50/50">
                  <svg class="w-5 h-5 text-green-500 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                </td>
                <td class="py-3 px-4 text-center">
                  <svg class="w-5 h-5 text-green-500 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                </td>
              </tr>
              <tr>
                <td class="py-3 px-4 text-gray-700 font-medium">فحوصات مجدولة</td>
                <td class="py-3 px-4 text-center">
                  <svg class="w-5 h-5 text-gray-300 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </td>
                <td class="py-3 px-4 text-center text-gray-600">أسبوعية</td>
                <td class="py-3 px-4 text-center text-gray-900 font-semibold bg-indigo-50/50">يومية</td>
                <td class="py-3 px-4 text-center text-gray-600">مخصصة</td>
              </tr>
              <tr>
                <td class="py-3 px-4 text-gray-700 font-medium">وصول API</td>
                <td class="py-3 px-4 text-center">
                  <svg class="w-5 h-5 text-gray-300 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </td>
                <td class="py-3 px-4 text-center text-gray-600">قراءة فقط</td>
                <td class="py-3 px-4 text-center text-gray-900 font-semibold bg-indigo-50/50">كامل</td>
                <td class="py-3 px-4 text-center text-gray-600">كامل</td>
              </tr>
              <tr>
                <td class="py-3 px-4 text-gray-700 font-medium">تنبيهات البريد</td>
                <td class="py-3 px-4 text-center">
                  <svg class="w-5 h-5 text-gray-300 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                </td>
                <td class="py-3 px-4 text-center">
                  <svg class="w-5 h-5 text-green-500 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                </td>
                <td class="py-3 px-4 text-center bg-indigo-50/50">
                  <svg class="w-5 h-5 text-green-500 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                </td>
                <td class="py-3 px-4 text-center">
                  <svg class="w-5 h-5 text-green-500 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
                </td>
              </tr>
              <tr>
                <td class="py-3 px-4 text-gray-700 font-medium">الدعم</td>
                <td class="py-3 px-4 text-center text-gray-600">مجتمعي</td>
                <td class="py-3 px-4 text-center text-gray-600">بريد إلكتروني</td>
                <td class="py-3 px-4 text-center text-gray-900 font-semibold bg-indigo-50/50">أولوية</td>
                <td class="py-3 px-4 text-center text-gray-600">مخصص</td>
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
            <span class="text-white font-bold">VScan-MOHESR</span>
          </div>
          <div class="flex gap-6 text-sm">
            <router-link to="/" class="hover:text-white transition-colors">الرئيسية</router-link>
            <router-link to="/pricing" class="hover:text-white transition-colors">الأسعار</router-link>
            <router-link to="/methodology-ar" class="hover:text-white transition-colors">معايير التقييم</router-link>
            <router-link to="/login" class="hover:text-white transition-colors">تسجيل الدخول</router-link>
          </div>
          <p class="text-sm">&copy; 2026 VScan-MOHESR. جميع الحقوق محفوظة</p>
        </div>
      </div>
    </footer>
  </div>
</template>
