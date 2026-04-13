<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useSEO } from '../composables/useSEO'

useSEO({
  title: 'فاحص أمان المواقع الإلكترونية',
  description: 'سيكو منصة فحص أمان المواقع الإلكترونية الأقوى في العراق. 32 فئة فحص أمني، تقييم من 1000 نقطة، تحليل بالذكاء الاصطناعي. ابدأ مجاناً.',
  keywords: 'فحص أمان المواقع, فاحص ثغرات, أمن المواقع العراقية, سيكو, Seku, vulnerability scanner',
})

const router = useRouter()
const showSignupInfo = ref(false)
const mobileMenuOpen = ref(false)
const scrolled = ref(false)

const lang = ref(localStorage.getItem('vscan_lang') || 'ar')
const isRTL = computed(() => lang.value === 'ar')

function toggleLang() {
  lang.value = lang.value === 'ar' ? 'en' : 'ar'
  localStorage.setItem('vscan_lang', lang.value)
  mobileMenuOpen.value = false
}

function t(ar, en) {
  return lang.value === 'ar' ? ar : en
}

function handleScroll() {
  scrolled.value = window.scrollY > 10
}

onMounted(() => {
  window.addEventListener('scroll', handleScroll)
})

onUnmounted(() => {
  window.removeEventListener('scroll', handleScroll)
})

function openSignup() {
  showSignupInfo.value = true
  mobileMenuOpen.value = false
}

function closeSignup() {
  showSignupInfo.value = false
}

function goRegister() {
  showSignupInfo.value = false
  router.push('/register')
}

function goPricing() {
  showSignupInfo.value = false
  router.push('/pricing')
}

const features = computed(() => [
  { title: t('تشفير SSL/TLS', 'SSL/TLS Encryption'), desc: t('فحص شهادة الأمان، إصدار TLS، إعادة التوجيه من HTTP إلى HTTPS', 'Security certificate, TLS version, HTTP to HTTPS redirect'), weight: 20, icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z', bg: 'bg-green-100', icon_color: 'text-green-600' },
  { title: t('ترويسات الأمان', 'Security Headers'), desc: t('فحص HSTS, CSP, X-Frame-Options, X-Content-Type-Options وغيرها', 'HSTS, CSP, X-Frame-Options, X-Content-Type-Options and more'), weight: 20, icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', bg: 'bg-blue-100', icon_color: 'text-blue-600' },
  { title: t('أمان الكوكيز', 'Cookie Security'), desc: t('فحص أعلام Secure, HttpOnly, SameSite لحماية جلسات المستخدمين', 'Secure, HttpOnly, SameSite flags for session protection'), weight: 10, icon: 'M21 12a9 9 0 11-18 0 9 9 0 0118 0z', bg: 'bg-purple-100', icon_color: 'text-purple-600' },
  { title: t('معلومات السيرفر', 'Server Information'), desc: t('كشف نوع CMS، إخفاء معلومات السيرفر، منع تسريب إصدار البرمجيات', 'CMS detection, server header hiding, version exposure prevention'), weight: 15, icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2', bg: 'bg-slate-100', icon_color: 'text-slate-600' },
  { title: t('الملفات والمجلدات', 'Directory & Files'), desc: t('فحص الوصول لملفات حساسة مثل .env, .git, admin, backup', 'Sensitive file exposure (.env, .git, admin, backup)'), weight: 10, icon: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z', bg: 'bg-yellow-100', icon_color: 'text-yellow-600' },
  { title: t('أداء السيرفر', 'Server Performance'), desc: t('قياس زمن الاستجابة، TTFB، سرعة مصافحة TLS', 'Response time, TTFB, TLS handshake speed'), weight: 15, icon: 'M13 10V3L4 14h7v7l9-11h-7z', bg: 'bg-amber-100', icon_color: 'text-amber-600' },
  { title: t('حماية DDoS', 'DDoS Protection'), desc: t('كشف CDN، جدار حماية WAF، تحديد معدل الطلبات', 'CDN detection, WAF firewall, rate limiting'), weight: 10, icon: 'M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', bg: 'bg-red-100', icon_color: 'text-red-600' },
  { title: t('إعدادات CORS', 'CORS Configuration'), desc: t('فحص مشاركة الموارد عبر المواقع ومنع تسريب البيانات', 'Cross-origin resource sharing and data leak prevention'), weight: 10, icon: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z', bg: 'bg-teal-100', icon_color: 'text-teal-600' },
  { title: t('طرق HTTP', 'HTTP Methods'), desc: t('تعطيل الطرق الخطرة مثل TRACE, DELETE, PUT, PATCH', 'Block dangerous methods (TRACE, DELETE, PUT, PATCH)'), weight: 8, icon: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z', bg: 'bg-indigo-100', icon_color: 'text-indigo-600' },
  { title: t('أمان DNS', 'DNS Security'), desc: t('فحص سجلات SPF, DMARC, CAA لحماية البريد والنطاق', 'SPF, DMARC, CAA records for domain and email protection'), weight: 8, icon: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9', bg: 'bg-cyan-100', icon_color: 'text-cyan-600' },
  { title: t('المحتوى المختلط', 'Mixed Content'), desc: t('كشف تحميل موارد HTTP داخل صفحات HTTPS المشفرة', 'HTTP resources loaded on encrypted HTTPS pages'), weight: 7, icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z', bg: 'bg-orange-100', icon_color: 'text-orange-600' },
  { title: t('تسريب المعلومات', 'Information Disclosure'), desc: t('كشف رسائل الخطأ، التعليقات الحساسة، إصدارات التقنيات', 'Error messages, sensitive comments, technology versions'), weight: 7, icon: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z', bg: 'bg-pink-100', icon_color: 'text-pink-600' },
  { title: t('جودة الاستضافة', 'Hosting Quality'), desc: t('HTTP/2, HTTP/3 QUIC, ضغط Brotli, دعم IPv6, سرعة DNS', 'HTTP/2, HTTP/3 QUIC, Brotli compression, IPv6, DNS speed'), weight: 12, icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01', bg: 'bg-emerald-100', icon_color: 'text-emerald-600' },
  { title: t('تحسين المحتوى', 'Content Optimization'), desc: t('ترويسات التخزين المؤقت، حجم الصفحة، نسبة الضغط', 'Cache headers, page size, compression ratio'), weight: 8, icon: 'M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z', bg: 'bg-sky-100', icon_color: 'text-sky-600' },
  { title: t('الأمان المتقدم', 'Advanced Security'), desc: t('عزل المصادر المتقاطعة COEP/COOP/CORP, تدبيس OCSP', 'Cross-origin isolation COEP/COOP/CORP, OCSP Stapling'), weight: 5, icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', bg: 'bg-violet-100', icon_color: 'text-violet-600' },
  { title: t('الفايروسات والتهديدات', 'Malware & Threats'), desc: t('فحص JavaScript خبيث، iframes مخفية، تعدين العملات، توقيعات Malware', 'Malicious JavaScript, hidden iframes, crypto miners, malware signatures'), weight: 10, icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z', bg: 'bg-rose-100', icon_color: 'text-rose-600' },
  { title: t('استخبارات التهديدات', 'Threat Intelligence'), desc: t('كشف Cryptojacking، اتصال بخوادم C2، فحص القوائم السوداء، عمر النطاق WHOIS', 'Cryptojacking detection, C2 callbacks, DNS blacklist check, domain age WHOIS'), weight: 8, icon: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z', bg: 'bg-gray-800', icon_color: 'text-gray-100' },
  { title: t('تحسين محركات البحث', 'SEO & Technical Health'), desc: t('فحص Meta Tags، Open Graph، Sitemap، Robots.txt، البيانات المنظمة، التوافق مع الجوال', 'Meta tags, Open Graph, Sitemap, Robots.txt, structured data, mobile-friendliness'), weight: 7, icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01', bg: 'bg-lime-100', icon_color: 'text-lime-600' },
  { title: t('مخاطر السكربتات الخارجية', 'Third-Party Script Risk'), desc: t('عدد السكربتات الخارجية، سلامة الموارد SRI، مصادر موثوقة، CSS خارجي', 'External script count, SRI integrity, trusted sources, external CSS'), weight: 6, icon: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1', bg: 'bg-fuchsia-100', icon_color: 'text-fuchsia-600' },
  { title: t('ثغرات مكتبات JavaScript', 'JS Library Vulnerabilities'), desc: t('كشف jQuery قديم، مكتبات معروفة بالثغرات CVE، تحليل السكربتات المضمّنة', 'Outdated jQuery, known CVE libraries, inline script analysis'), weight: 6, icon: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4', bg: 'bg-amber-100', icon_color: 'text-amber-700' },
])

const grades = computed(() => [
  { grade: 'A+', range: '900-1000', label: t('ممتاز', 'Excellent'), color: 'text-emerald-400' },
  { grade: 'A', range: '800-899', label: t('جيد جداً', 'Very Good'), color: 'text-green-400' },
  { grade: 'B', range: '700-799', label: t('جيد', 'Good'), color: 'text-blue-400' },
  { grade: 'C', range: '600-699', label: t('متوسط', 'Average'), color: 'text-yellow-400' },
  { grade: 'D', range: '500-599', label: t('ضعيف', 'Poor'), color: 'text-orange-400' },
  { grade: 'F', range: '0-499', label: t('راسب', 'Failing'), color: 'text-red-400' },
])

const steps = computed(() => [
  { title: t('سجّل حسابك', 'Create Account'), desc: t('أنشئ حساباً مجانياً في ثوانٍ', 'Create a free account in seconds') },
  { title: t('أثبت ملكية موقعك', 'Verify Your Domain'), desc: t('أضف سجل TXT للتحقق من ملكيتك للنطاق', 'Add a TXT record to verify domain ownership') },
  { title: t('ابدأ الفحص', 'Start Scanning'), desc: t('النظام يفحص موقعك عبر 20 معياراً شاملاً', 'The system scans your site across 20 comprehensive criteria') },
  { title: t('استلم التقرير', 'Get Your Report'), desc: t('تقرير PDF مفصّل مع توصيات الإصلاح وتحليل AI', 'Detailed PDF report with fix recommendations and AI analysis') },
])
</script>

<template>
  <div class="min-h-screen bg-white" :dir="isRTL ? 'rtl' : 'ltr'">

    <!-- Signup Info Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showSignupInfo" class="fixed inset-0 z-[100] flex items-center justify-center p-4" :dir="isRTL ? 'rtl' : 'ltr'">
          <!-- Backdrop -->
          <div class="absolute inset-0 bg-black/50 backdrop-blur-sm" @click="closeSignup"></div>
          <!-- Modal -->
          <div class="relative bg-white rounded-2xl shadow-2xl max-w-md w-full p-8 z-10 transform transition-all">
            <!-- Close button -->
            <button @click="closeSignup" :class="['absolute top-4 w-8 h-8 flex items-center justify-center rounded-full hover:bg-gray-100 transition-colors text-gray-400 hover:text-gray-600', isRTL ? 'left-4' : 'right-4']">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>

            <!-- Icon -->
            <div class="w-16 h-16 bg-indigo-100 rounded-2xl flex items-center justify-center mx-auto mb-5">
              <svg class="w-8 h-8 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
              </svg>
            </div>

            <h3 class="text-2xl font-bold text-gray-900 text-center mb-2">{{ t('مرحباً بك في Seku', 'Welcome to Seku') }}</h3>
            <p class="text-gray-600 text-center mb-5">{{ t('ستبدأ بالخطة المجانية التي تشمل:', 'You will start with the free plan that includes:') }}</p>

            <div class="bg-indigo-50 rounded-xl p-5 mb-5 space-y-3">
              <div class="flex items-center gap-3">
                <div class="w-8 h-8 bg-indigo-100 rounded-lg flex items-center justify-center flex-shrink-0">
                  <svg class="w-4 h-4 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9"/></svg>
                </div>
                <span class="text-sm font-medium text-gray-800">{{ t('5 مواقع', '5 Websites') }}</span>
              </div>
              <div class="flex items-center gap-3">
                <div class="w-8 h-8 bg-indigo-100 rounded-lg flex items-center justify-center flex-shrink-0">
                  <svg class="w-4 h-4 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
                </div>
                <span class="text-sm font-medium text-gray-800">{{ t('10 فحوصات شهرياً', '10 Scans per Month') }}</span>
              </div>
              <div class="flex items-center gap-3">
                <div class="w-8 h-8 bg-indigo-100 rounded-lg flex items-center justify-center flex-shrink-0">
                  <svg class="w-4 h-4 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                </div>
                <span class="text-sm font-medium text-gray-800">{{ t('5 فئات فحص', '5 Scan Categories') }}</span>
              </div>
            </div>

            <p class="text-sm text-gray-500 text-center mb-6">{{ t('يمكنك الترقية في أي وقت للحصول على المزيد من الميزات', 'You can upgrade anytime for more features') }}</p>

            <div class="flex flex-col gap-3">
              <button @click="goRegister" class="w-full px-6 py-3 bg-indigo-600 text-white font-semibold rounded-xl hover:bg-indigo-700 transition-colors shadow-lg shadow-indigo-200">
                {{ t('متابعة التسجيل', 'Continue Registration') }}
              </button>
              <button @click="goPricing" class="w-full px-6 py-3 bg-white text-indigo-600 font-semibold rounded-xl border-2 border-indigo-200 hover:border-indigo-400 hover:bg-indigo-50 transition-colors">
                {{ t('تعرّف على الخطط', 'View Plans') }}
              </button>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Navbar -->
    <nav :class="['fixed top-0 inset-x-0 z-50 transition-all duration-300', scrolled ? 'bg-white/90 backdrop-blur-md shadow-sm border-b border-gray-100' : 'bg-white/60 backdrop-blur-sm']">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex items-center justify-between h-16">
          <!-- Logo -->
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 bg-indigo-600 rounded-lg flex items-center justify-center">
              <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
              </svg>
            </div>
            <span class="text-xl font-bold text-gray-900">Seku</span>
          </div>

          <!-- Center links (hidden on mobile) -->
          <div class="hidden md:flex items-center gap-8">
            <a href="#" @click.prevent="window.scrollTo({top:0,behavior:'smooth'})" class="text-sm font-medium text-gray-700 hover:text-indigo-600 transition-colors">{{ t('الرئيسية', 'Home') }}</a>
            <router-link :to="isRTL ? '/methodology-ar' : '/methodology'" class="text-sm font-medium text-gray-700 hover:text-indigo-600 transition-colors">{{ t('معايير التقييم', 'Methodology') }}</router-link>
            <router-link to="/pricing" class="text-sm font-medium text-gray-700 hover:text-indigo-600 transition-colors">{{ t('الأسعار', 'Pricing') }}</router-link>
          </div>

          <!-- Buttons (hidden on mobile) -->
          <div class="hidden md:flex items-center gap-3">
            <router-link to="/login" class="px-5 py-2 text-sm font-medium text-indigo-600 border border-indigo-300 rounded-lg hover:bg-indigo-50 transition-colors">
              {{ t('تسجيل الدخول', 'Login') }}
            </router-link>
            <button @click="toggleLang" class="px-3 py-2 text-sm font-medium text-gray-600 hover:text-indigo-600 border border-gray-200 rounded-lg hover:border-indigo-300 transition-colors">
              {{ lang === 'ar' ? 'EN' : 'عربي' }}
            </button>
            <button @click="openSignup" class="px-5 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 transition-colors shadow-sm">
              {{ t('ابدأ مجاناً', 'Start Free') }}
            </button>
          </div>

          <!-- Mobile hamburger -->
          <button @click="mobileMenuOpen = !mobileMenuOpen" class="md:hidden w-10 h-10 flex items-center justify-center rounded-lg hover:bg-gray-100 transition-colors">
            <svg v-if="!mobileMenuOpen" class="w-6 h-6 text-gray-700" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
            <svg v-else class="w-6 h-6 text-gray-700" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>
      </div>

      <!-- Mobile menu -->
      <Transition name="slide">
        <div v-if="mobileMenuOpen" class="md:hidden bg-white border-t border-gray-100 shadow-lg">
          <div class="px-4 py-4 space-y-2">
            <a href="#" @click.prevent="mobileMenuOpen = false; window.scrollTo({top:0,behavior:'smooth'})" class="block px-4 py-2.5 text-sm font-medium text-gray-700 hover:bg-indigo-50 hover:text-indigo-600 rounded-lg transition-colors">{{ t('الرئيسية', 'Home') }}</a>
            <router-link :to="isRTL ? '/methodology-ar' : '/methodology'" @click="mobileMenuOpen = false" class="block px-4 py-2.5 text-sm font-medium text-gray-700 hover:bg-indigo-50 hover:text-indigo-600 rounded-lg transition-colors">{{ t('معايير التقييم', 'Methodology') }}</router-link>
            <router-link to="/pricing" @click="mobileMenuOpen = false" class="block px-4 py-2.5 text-sm font-medium text-gray-700 hover:bg-indigo-50 hover:text-indigo-600 rounded-lg transition-colors">{{ t('الأسعار', 'Pricing') }}</router-link>
            <button @click="toggleLang" class="block w-full text-center px-4 py-2.5 text-sm font-medium text-gray-600 hover:bg-indigo-50 hover:text-indigo-600 border border-gray-200 rounded-lg transition-colors">
              {{ lang === 'ar' ? 'English' : 'عربي' }}
            </button>
            <div class="pt-3 border-t border-gray-100 space-y-2">
              <router-link to="/login" @click="mobileMenuOpen = false" class="block w-full text-center px-4 py-2.5 text-sm font-medium text-indigo-600 border border-indigo-300 rounded-lg hover:bg-indigo-50 transition-colors">{{ t('تسجيل الدخول', 'Login') }}</router-link>
              <button @click="openSignup" class="block w-full text-center px-4 py-2.5 text-sm font-medium text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 transition-colors">{{ t('ابدأ مجاناً', 'Start Free') }}</button>
            </div>
          </div>
        </div>
      </Transition>
    </nav>

    <!-- Spacer for fixed navbar -->
    <div class="h-16"></div>

    <!-- Hero Section -->
    <section class="relative overflow-hidden">
      <div class="absolute inset-0 bg-gradient-to-br from-indigo-50 via-white to-blue-50"></div>
      <div class="absolute top-0 left-0 w-96 h-96 bg-indigo-200/30 rounded-full blur-3xl -translate-x-1/2 -translate-y-1/2"></div>
      <div class="absolute bottom-0 right-0 w-96 h-96 bg-blue-200/30 rounded-full blur-3xl translate-x-1/2 translate-y-1/2"></div>

      <div class="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-28 lg:py-36">
        <div class="text-center max-w-4xl mx-auto">
          <div class="inline-flex items-center gap-2 bg-indigo-50 border border-indigo-200 rounded-full px-4 py-1.5 text-sm font-medium text-indigo-700 mb-8">
            <span class="w-2 h-2 bg-indigo-500 rounded-full animate-pulse"></span>
            {{ t('منصة فحص أمان المواقع الإلكترونية', 'Web Security Assessment Platform') }}
          </div>

          <h1 class="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-gray-900 leading-tight tracking-tight">
            {{ t('افحص أمان موقعك', 'Scan Your Website Security') }}
            <br/>
            <span :class="['bg-clip-text text-transparent', isRTL ? 'bg-gradient-to-l from-indigo-600 to-blue-600' : 'bg-gradient-to-r from-indigo-600 to-blue-600']">{{ t('بدقة 1000 نقطة', 'With 1000-Point Precision') }}</span>
          </h1>

          <p class="mt-6 text-lg sm:text-xl text-gray-600 leading-relaxed max-w-2xl mx-auto">
            {{ t('أول منصة عربية متخصصة لفحص أمان المواقع الإلكترونية للمؤسسات التعليمية والحكومية.', 'The first specialized Arabic platform for web security assessment for educational and governmental institutions.') }}
            {{ t('نفحص موقعك عبر', 'We scan your site across') }} <strong class="text-gray-900">{{ t('20 معياراً شاملاً', '20 comprehensive criteria') }}</strong> {{ t('و', 'and') }} <strong class="text-gray-900">{{ t('أكثر من 75 فحصاً تفصيلياً', 'over 75 detailed checks') }}</strong>
            {{ t('ونقدم تقريراً شاملاً مع توصيات الإصلاح.', 'and provide a comprehensive report with fix recommendations.') }}
          </p>

          <div class="mt-10 flex flex-wrap items-center justify-center gap-4">
            <button @click="openSignup" class="px-8 py-3.5 bg-indigo-600 text-white font-semibold rounded-xl hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-200 hover:shadow-xl hover:shadow-indigo-300">
              {{ t('ابدأ الفحص مجاناً', 'Start Scanning Free') }}
            </button>
            <router-link :to="isRTL ? '/methodology-ar' : '/methodology'" class="px-8 py-3.5 bg-white text-gray-700 font-semibold rounded-xl border border-gray-300 hover:border-indigo-300 hover:text-indigo-600 transition-all">
              {{ t('تعرّف على معايير التقييم', 'View Assessment Criteria') }}
            </router-link>
          </div>

          <!-- Trust badges -->
          <div class="mt-12 flex flex-wrap items-center justify-center gap-6 text-sm text-gray-500">
            <div class="flex items-center gap-2">
              <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
              <span>{{ t('100+ جامعة عراقية', '100+ Iraqi Universities') }}</span>
            </div>
            <div class="flex items-center gap-2">
              <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
              <span>{{ t('20 معيار تقييم', '20 Assessment Criteria') }}</span>
            </div>
            <div class="flex items-center gap-2">
              <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
              <span>{{ t('تحليل بالذكاء الاصطناعي', 'AI-Powered Analysis') }}</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Features Grid -->
    <section class="py-20 bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl sm:text-4xl font-bold text-gray-900">{{ t('ماذا نفحص؟', 'What We Scan') }}</h2>
          <p class="mt-4 text-lg text-gray-600 max-w-2xl mx-auto">{{ t('20 فئة تقييم شاملة تغطي الأمان والأداء وجودة الاستضافة وفحص الفايروسات', '20 comprehensive assessment categories covering security, performance, hosting quality, and malware scanning') }}</p>
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
            <div class="mt-3 text-xs font-medium text-indigo-600">{{ t('الوزن:', 'Weight:') }} {{ feature.weight }}%</div>
          </div>
        </div>
      </div>
    </section>

    <!-- Scoring Section -->
    <section class="py-20 bg-gradient-to-br from-slate-900 to-indigo-950 text-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl sm:text-4xl font-bold">{{ t('نظام التقييم من 1000 نقطة', '1000-Point Scoring System') }}</h2>
          <p class="mt-4 text-lg text-indigo-200">{{ t('نظام تقييم دقيق يمنح كل فحص درجة من 1000 بدلاً من 100 لنتائج أكثر تفصيلاً', 'A precise scoring system that rates each scan out of 1000 instead of 100 for more detailed results') }}</p>
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
          <router-link :to="isRTL ? '/methodology-ar' : '/methodology'" class="inline-flex items-center gap-2 px-6 py-3 bg-white/10 border border-white/20 rounded-xl text-white hover:bg-white/20 transition-colors">
            {{ t('اطّلع على المنهجية الكاملة', 'View Full Methodology') }}
            <svg :class="['w-4 h-4', isRTL ? 'rotate-180' : '']" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
          </router-link>
        </div>
      </div>
    </section>

    <!-- How it works -->
    <section class="py-20 bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl sm:text-4xl font-bold text-gray-900">{{ t('كيف يعمل؟', 'How It Works') }}</h2>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div v-for="(step, i) in steps" :key="i" class="text-center relative">
            <!-- Connector line (hidden on last item and on mobile) -->
            <div v-if="i < steps.length - 1" :class="['hidden md:block absolute top-7 w-full h-0.5 bg-indigo-100', isRTL ? '-translate-x-1/2 left-0' : 'translate-x-1/2 right-0']"></div>
            <div class="relative z-10 w-14 h-14 bg-indigo-100 rounded-2xl flex items-center justify-center mx-auto mb-4 text-xl font-black text-indigo-600">
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
        <h2 class="text-3xl sm:text-4xl font-bold text-white mb-4">{{ t('جاهز لفحص أمان مواقعك؟', 'Ready to Scan Your Website Security?') }}</h2>
        <p class="text-lg text-indigo-100 mb-8">{{ t('سجّل الآن واحصل على فحص أمني مجاني لموقعك', 'Sign up now and get a free security scan for your website') }}</p>
        <button @click="openSignup" class="inline-block px-8 py-4 bg-white text-indigo-600 font-bold rounded-xl hover:bg-indigo-50 transition-colors shadow-lg text-lg">
          {{ t('سجّل مجاناً - بدون بطاقة ائتمان', 'Sign Up Free - No Credit Card Required') }}
        </button>
        <p class="mt-6 text-sm text-indigo-200">{{ t('الخطة المجانية تشمل: 5 مواقع | 10 فحوصات | 5 فئات أمنية', 'Free plan includes: 5 websites | 10 scans | 5 security categories') }}</p>
      </div>
    </section>

    <!-- Footer -->
    <footer class="bg-slate-900 text-gray-400 py-12">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-8 pb-8 border-b border-slate-800">
          <!-- Logo & description -->
          <div>
            <div class="flex items-center gap-3 mb-4">
              <div class="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center">
                <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                </svg>
              </div>
              <span class="text-white font-bold text-lg">Seku</span>
            </div>
            <p class="text-sm leading-relaxed">{{ t('منصة فحص أمان المواقع الإلكترونية للمؤسسات التعليمية والحكومية العراقية.', 'Web security assessment platform for Iraqi educational and governmental institutions.') }}</p>
          </div>

          <!-- Quick links -->
          <div>
            <h4 class="text-white font-semibold mb-4">{{ t('روابط سريعة', 'Quick Links') }}</h4>
            <div class="space-y-2 text-sm">
              <router-link :to="isRTL ? '/methodology-ar' : '/methodology'" class="block hover:text-white transition-colors">{{ t('معايير التقييم', 'Methodology') }}</router-link>
              <router-link to="/pricing" class="block hover:text-white transition-colors">{{ t('الأسعار', 'Pricing') }}</router-link>
              <router-link to="/login" class="block hover:text-white transition-colors">{{ t('تسجيل الدخول', 'Login') }}</router-link>
            </div>
          </div>

          <!-- More links -->
          <div>
            <h4 class="text-white font-semibold mb-4">{{ t('المزيد', 'More') }}</h4>
            <div class="space-y-2 text-sm">
              <router-link to="/api-docs" class="block hover:text-white transition-colors">{{ t('وثائق API', 'API Documentation') }}</router-link>
              <router-link to="/contact" class="block hover:text-white transition-colors">{{ t('اتصل بنا', 'Contact Us') }}</router-link>
            </div>
          </div>
        </div>

        <div class="pt-8 text-center text-sm">
          <p>{{ t('جميع الحقوق محفوظة', 'All Rights Reserved') }} &copy; 2026 Seku</p>
        </div>
      </div>
    </footer>
  </div>
</template>

<style scoped>
/* Modal transitions */
.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.3s ease;
}
.modal-enter-active .relative,
.modal-leave-active .relative {
  transition: transform 0.3s ease, opacity 0.3s ease;
}
.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}
.modal-enter-from .relative {
  transform: scale(0.95) translateY(10px);
  opacity: 0;
}
.modal-leave-to .relative {
  transform: scale(0.95) translateY(10px);
  opacity: 0;
}

/* Mobile menu slide transition */
.slide-enter-active,
.slide-leave-active {
  transition: all 0.3s ease;
  max-height: 500px;
  overflow: hidden;
}
.slide-enter-from,
.slide-leave-to {
  max-height: 0;
  opacity: 0;
}
</style>
