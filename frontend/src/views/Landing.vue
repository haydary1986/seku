<script setup>
import { useRouter } from 'vue-router'
const router = useRouter()
</script>

<template>
  <div class="min-h-screen bg-white" dir="rtl">

    <!-- Navbar -->
    <nav class="bg-white/80 backdrop-blur-md border-b border-gray-100 sticky top-0 z-50">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex items-center justify-between h-16">
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 bg-indigo-600 rounded-lg flex items-center justify-center">
              <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
              </svg>
            </div>
            <span class="text-xl font-bold text-gray-900">VScan</span>
          </div>
          <div class="flex items-center gap-4">
            <router-link to="/methodology-ar" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">معايير التقييم</router-link>
            <router-link to="/methodology" class="text-sm text-gray-600 hover:text-indigo-600 transition-colors">Methodology</router-link>
            <router-link to="/login" class="px-5 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 transition-colors">
              تسجيل الدخول
            </router-link>
          </div>
        </div>
      </div>
    </nav>

    <!-- Hero Section -->
    <section class="relative overflow-hidden">
      <div class="absolute inset-0 bg-gradient-to-br from-indigo-50 via-white to-blue-50"></div>
      <div class="absolute top-0 left-0 w-96 h-96 bg-indigo-200/30 rounded-full blur-3xl -translate-x-1/2 -translate-y-1/2"></div>
      <div class="absolute bottom-0 right-0 w-96 h-96 bg-blue-200/30 rounded-full blur-3xl translate-x-1/2 translate-y-1/2"></div>

      <div class="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-28 lg:py-36">
        <div class="text-center max-w-4xl mx-auto">
          <div class="inline-flex items-center gap-2 bg-indigo-50 border border-indigo-200 rounded-full px-4 py-1.5 text-sm font-medium text-indigo-700 mb-8">
            <span class="w-2 h-2 bg-indigo-500 rounded-full animate-pulse"></span>
            منصة فحص أمان المواقع الإلكترونية
          </div>

          <h1 class="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-gray-900 leading-tight tracking-tight">
            افحص أمان موقعك
            <br/>
            <span class="bg-gradient-to-l from-indigo-600 to-blue-600 bg-clip-text text-transparent">بدقة 1000 نقطة</span>
          </h1>

          <p class="mt-6 text-lg sm:text-xl text-gray-600 leading-relaxed max-w-2xl mx-auto">
            أول منصة عربية متخصصة لفحص أمان المواقع الإلكترونية للمؤسسات التعليمية والحكومية.
            نفحص موقعك عبر <strong class="text-gray-900">12 معياراً أمنياً</strong> و <strong class="text-gray-900">أكثر من 40 فحصاً تفصيلياً</strong>
            ونقدم تقريراً شاملاً مع توصيات الإصلاح.
          </p>

          <div class="mt-10 flex flex-wrap items-center justify-center gap-4">
            <router-link to="/login" class="px-8 py-3.5 bg-indigo-600 text-white font-semibold rounded-xl hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-200 hover:shadow-xl hover:shadow-indigo-300">
              ابدأ الفحص مجاناً
            </router-link>
            <router-link to="/methodology-ar" class="px-8 py-3.5 bg-white text-gray-700 font-semibold rounded-xl border border-gray-300 hover:border-indigo-300 hover:text-indigo-600 transition-all">
              تعرّف على معايير التقييم
            </router-link>
          </div>

          <!-- Trust badges -->
          <div class="mt-12 flex flex-wrap items-center justify-center gap-6 text-sm text-gray-500">
            <div class="flex items-center gap-2">
              <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
              <span>100+ جامعة عراقية</span>
            </div>
            <div class="flex items-center gap-2">
              <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
              <span>12 معيار أمني</span>
            </div>
            <div class="flex items-center gap-2">
              <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
              <span>تحليل بالذكاء الاصطناعي</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Features Grid -->
    <section class="py-20 bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl sm:text-4xl font-bold text-gray-900">ماذا نفحص؟</h2>
          <p class="mt-4 text-lg text-gray-600 max-w-2xl mx-auto">12 فئة أمنية شاملة تغطي جميع جوانب حماية الموقع</p>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          <div v-for="feature in features" :key="feature.title"
            class="bg-white rounded-2xl border border-gray-200 p-6 hover:border-indigo-300 hover:shadow-lg transition-all group">
            <div :class="['w-12 h-12 rounded-xl flex items-center justify-center mb-4', feature.bg]">
              <svg class="w-6 h-6" :class="feature.icon_color" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="feature.icon"/>
              </svg>
            </div>
            <h3 class="text-lg font-bold text-gray-900 mb-2">{{ feature.title }}</h3>
            <p class="text-sm text-gray-600 leading-relaxed">{{ feature.desc }}</p>
            <div class="mt-3 text-xs font-medium text-indigo-600">الوزن: {{ feature.weight }}%</div>
          </div>
        </div>
      </div>
    </section>

    <!-- Scoring Section -->
    <section class="py-20 bg-gradient-to-br from-slate-900 to-indigo-950 text-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl sm:text-4xl font-bold">نظام التقييم من 1000 نقطة</h2>
          <p class="mt-4 text-lg text-indigo-200">نظام تقييم دقيق يمنح كل فحص درجة من 1000 بدلاً من 100 لنتائج أكثر تفصيلاً</p>
        </div>

        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          <div v-for="grade in grades" :key="grade.grade"
            class="text-center p-5 rounded-2xl border border-white/10 bg-white/5 backdrop-blur-sm">
            <div :class="['text-3xl font-black mb-2', grade.color]">{{ grade.grade }}</div>
            <div class="text-sm text-gray-300">{{ grade.range }}</div>
            <div class="text-xs text-gray-400 mt-1">{{ grade.label }}</div>
          </div>
        </div>

        <div class="mt-12 text-center">
          <router-link to="/methodology-ar" class="inline-flex items-center gap-2 px-6 py-3 bg-white/10 border border-white/20 rounded-xl text-white hover:bg-white/20 transition-colors">
            اطّلع على المنهجية الكاملة
            <svg class="w-4 h-4 rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
          </router-link>
        </div>
      </div>
    </section>

    <!-- How it works -->
    <section class="py-20 bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl sm:text-4xl font-bold text-gray-900">كيف يعمل؟</h2>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div v-for="(step, i) in steps" :key="i" class="text-center">
            <div class="w-14 h-14 bg-indigo-100 rounded-2xl flex items-center justify-center mx-auto mb-4 text-xl font-black text-indigo-600">
              {{ i + 1 }}
            </div>
            <h3 class="text-lg font-bold text-gray-900 mb-2">{{ step.title }}</h3>
            <p class="text-sm text-gray-600">{{ step.desc }}</p>
          </div>
        </div>
      </div>
    </section>

    <!-- CTA -->
    <section class="py-20 bg-indigo-600">
      <div class="max-w-4xl mx-auto px-4 text-center">
        <h2 class="text-3xl sm:text-4xl font-bold text-white mb-6">جاهز لفحص أمان مواقعك؟</h2>
        <p class="text-lg text-indigo-100 mb-8">ابدأ بفحص مجاني واحصل على تقرير أمني شامل خلال دقائق</p>
        <router-link to="/login" class="inline-block px-8 py-4 bg-white text-indigo-600 font-bold rounded-xl hover:bg-indigo-50 transition-colors shadow-lg text-lg">
          ابدأ الآن
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
            <router-link to="/methodology-ar" class="hover:text-white transition-colors">معايير التقييم</router-link>
            <router-link to="/methodology" class="hover:text-white transition-colors">Methodology</router-link>
            <router-link to="/login" class="hover:text-white transition-colors">تسجيل الدخول</router-link>
          </div>
          <p class="text-sm">&copy; 2026 VScan-MOHESR. جميع الحقوق محفوظة</p>
        </div>
      </div>
    </footer>
  </div>
</template>

<script>
export default {
  data() {
    return {
      features: [
        { title: 'تشفير SSL/TLS', desc: 'فحص شهادة الأمان، إصدار TLS، إعادة التوجيه من HTTP إلى HTTPS', weight: 20, icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z', bg: 'bg-green-100', icon_color: 'text-green-600' },
        { title: 'ترويسات الأمان', desc: 'فحص HSTS, CSP, X-Frame-Options, X-Content-Type-Options وغيرها', weight: 20, icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', bg: 'bg-blue-100', icon_color: 'text-blue-600' },
        { title: 'أمان الكوكيز', desc: 'فحص أعلام Secure, HttpOnly, SameSite لحماية جلسات المستخدمين', weight: 10, icon: 'M21 12a9 9 0 11-18 0 9 9 0 0118 0z', bg: 'bg-purple-100', icon_color: 'text-purple-600' },
        { title: 'معلومات السيرفر', desc: 'كشف نوع CMS، إخفاء معلومات السيرفر، منع تسريب إصدار البرمجيات', weight: 15, icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2', bg: 'bg-slate-100', icon_color: 'text-slate-600' },
        { title: 'الملفات والمجلدات', desc: 'فحص الوصول لملفات حساسة مثل .env, .git, admin, backup', weight: 10, icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z', bg: 'bg-yellow-100', icon_color: 'text-yellow-600' },
        { title: 'أداء السيرفر', desc: 'قياس زمن الاستجابة، TTFB، سرعة مصافحة TLS', weight: 15, icon: 'M13 10V3L4 14h7v7l9-11h-7z', bg: 'bg-amber-100', icon_color: 'text-amber-600' },
        { title: 'حماية DDoS', desc: 'كشف CDN، جدار حماية WAF، تحديد معدل الطلبات', weight: 10, icon: 'M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', bg: 'bg-red-100', icon_color: 'text-red-600' },
        { title: 'إعدادات CORS', desc: 'فحص مشاركة الموارد عبر المواقع ومنع تسريب البيانات', weight: 10, icon: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z', bg: 'bg-teal-100', icon_color: 'text-teal-600' },
        { title: 'طرق HTTP', desc: 'تعطيل الطرق الخطرة مثل TRACE, DELETE, PUT, PATCH', weight: 8, icon: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z', bg: 'bg-indigo-100', icon_color: 'text-indigo-600' },
        { title: 'أمان DNS', desc: 'فحص سجلات SPF, DMARC, CAA لحماية البريد والنطاق', weight: 8, icon: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9', bg: 'bg-cyan-100', icon_color: 'text-cyan-600' },
        { title: 'المحتوى المختلط', desc: 'كشف تحميل موارد HTTP داخل صفحات HTTPS المشفرة', weight: 7, icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z', bg: 'bg-orange-100', icon_color: 'text-orange-600' },
        { title: 'تسريب المعلومات', desc: 'كشف رسائل الخطأ، التعليقات الحساسة، إصدارات التقنيات', weight: 7, icon: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z', bg: 'bg-pink-100', icon_color: 'text-pink-600' },
      ],
      grades: [
        { grade: 'A+', range: '900-1000', label: 'ممتاز', color: 'text-emerald-400' },
        { grade: 'A', range: '800-899', label: 'جيد جداً', color: 'text-green-400' },
        { grade: 'B', range: '700-799', label: 'جيد', color: 'text-blue-400' },
        { grade: 'C', range: '600-699', label: 'متوسط', color: 'text-yellow-400' },
        { grade: 'D', range: '500-599', label: 'ضعيف', color: 'text-orange-400' },
        { grade: 'F', range: '0-499', label: 'راسب', color: 'text-red-400' },
      ],
      steps: [
        { title: 'أضف المواقع', desc: 'أدخل عناوين المواقع التي تريد فحصها - فردياً أو بالجملة' },
        { title: 'ابدأ الفحص', desc: 'النظام يفحص جميع المواقع بالتوازي عبر 12 معياراً أمنياً' },
        { title: 'استعرض النتائج', desc: 'تقرير تفصيلي لكل موقع مع درجة من 1000 وشرح كل ثغرة' },
        { title: 'تحليل AI', desc: 'الذكاء الاصطناعي يحلل النتائج ويقترح خطوات الإصلاح للوصول لـ 1000' },
      ],
    }
  }
}
</script>
