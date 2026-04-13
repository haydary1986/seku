<script setup>
import { ref, onMounted, computed } from 'vue'
import { getSEOSettings, updateSettings, uploadOGImage } from '../api'

const seo = ref({
  site_url: '',
  site_name: '',
  site_title: '',
  site_description: '',
  site_keywords: '',
  og_image: '',
  twitter_handle: '',
  google_analytics: '',
  google_search_console: '',
  bing_verification: '',
  facebook_app_id: '',
  disable_indexing: 'false',
  organization_name: '',
  organization_url: '',
})

const loading = ref(true)
const saving = ref(false)
const message = ref('')
const messageType = ref('') // success, error
const activeTab = ref('basic') // basic, social, analytics, advanced

const tabs = [
  { id: 'basic', label: 'الأساسيات', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
  { id: 'social', label: 'وسائل التواصل', icon: 'M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m9.032 4.026a9.001 9.001 0 010-7.448M9 5h6m4 0h.01' },
  { id: 'analytics', label: 'التحليلات', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10' },
  { id: 'advanced', label: 'متقدم', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z' },
]

const sitemapURL = computed(() => seo.value.site_url ? seo.value.site_url.replace(/\/$/, '') + '/sitemap.xml' : '')
const robotsURL = computed(() => seo.value.site_url ? seo.value.site_url.replace(/\/$/, '') + '/robots.txt' : '')

async function load() {
  loading.value = true
  try {
    const { data } = await getSEOSettings()
    seo.value = { ...seo.value, ...data }
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  message.value = ''
  try {
    // Map fields back to seo_* prefixed setting keys
    const payload = {
      seo_site_url: seo.value.site_url,
      seo_site_name: seo.value.site_name,
      seo_site_title: seo.value.site_title,
      seo_site_description: seo.value.site_description,
      seo_site_keywords: seo.value.site_keywords,
      seo_og_image: seo.value.og_image,
      seo_twitter_handle: seo.value.twitter_handle,
      seo_google_analytics: seo.value.google_analytics,
      seo_google_search_console: seo.value.google_search_console,
      seo_bing_verification: seo.value.bing_verification,
      seo_facebook_app_id: seo.value.facebook_app_id,
      seo_disable_indexing: String(seo.value.disable_indexing),
      seo_org_name: seo.value.organization_name,
      seo_org_url: seo.value.organization_url,
    }
    await updateSettings(payload)
    message.value = 'تم حفظ إعدادات SEO بنجاح'
    messageType.value = 'success'
    setTimeout(() => message.value = '', 3000)
  } catch (e) {
    message.value = 'فشل الحفظ: ' + (e.response?.data?.error || e.message)
    messageType.value = 'error'
  } finally {
    saving.value = false
  }
}

const uploadingImage = ref(false)
const fileInput = ref(null)

async function handleImageUpload(event) {
  const file = event.target.files[0]
  if (!file) return

  // Validate
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
    message.value = 'الصيغة غير مدعومة. استخدم PNG أو JPG أو WebP'
    messageType.value = 'error'
    return
  }
  if (file.size > 5 * 1024 * 1024) {
    message.value = 'الحجم أكبر من 5MB'
    messageType.value = 'error'
    return
  }

  uploadingImage.value = true
  try {
    const { data } = await uploadOGImage(file)
    seo.value.og_image = data.url
    message.value = 'تم رفع الصورة بنجاح'
    messageType.value = 'success'
    setTimeout(() => message.value = '', 3000)
  } catch (e) {
    message.value = 'فشل الرفع: ' + (e.response?.data?.error || e.message)
    messageType.value = 'error'
  } finally {
    uploadingImage.value = false
    if (fileInput.value) fileInput.value.value = ''
  }
}

function triggerFileInput() {
  fileInput.value?.click()
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text)
  message.value = 'تم النسخ'
  messageType.value = 'success'
  setTimeout(() => message.value = '', 2000)
}

onMounted(load)
</script>

<template>
  <div>
    <!-- Header -->
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">إعدادات SEO</h1>
        <p class="text-gray-500 mt-1">تحسين ظهور الموقع في محركات البحث</p>
      </div>
      <button @click="save" :disabled="saving"
        class="px-6 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors flex items-center gap-2 text-sm font-medium">
        <div v-if="saving" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
        <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
        </svg>
        {{ saving ? 'جاري الحفظ...' : 'حفظ التغييرات' }}
      </button>
    </div>

    <!-- Message -->
    <div v-if="message" :class="messageType === 'success' ? 'bg-green-50 border-green-200 text-green-700' : 'bg-red-50 border-red-200 text-red-700'"
      class="border rounded-lg p-3 mb-4 text-sm">
      {{ message }}
    </div>

    <!-- Loading -->
    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else class="bg-white rounded-xl shadow-sm border border-gray-200">
      <!-- Tabs -->
      <div class="border-b border-gray-200 p-2 flex gap-1 overflow-x-auto">
        <button v-for="tab in tabs" :key="tab.id" @click="activeTab = tab.id"
          :class="activeTab === tab.id ? 'bg-indigo-100 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'"
          class="px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors whitespace-nowrap">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="tab.icon"/>
          </svg>
          {{ tab.label }}
        </button>
      </div>

      <div class="p-6 space-y-5">
        <!-- BASIC TAB -->
        <div v-if="activeTab === 'basic'" class="space-y-5">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">عنوان الموقع (Title)</label>
            <input v-model="seo.site_title" type="text" maxlength="60"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
            <p class="text-xs text-gray-400 mt-1">{{ seo.site_title?.length || 0 }}/60 — يظهر في تبويب المتصفح ونتائج البحث</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">وصف الموقع (Description)</label>
            <textarea v-model="seo.site_description" maxlength="160" rows="3"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"></textarea>
            <p class="text-xs text-gray-400 mt-1">{{ seo.site_description?.length || 0 }}/160 — يظهر تحت العنوان في نتائج البحث</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">الكلمات المفتاحية (Keywords)</label>
            <textarea v-model="seo.site_keywords" rows="2"
              placeholder="فحص أمان, vulnerability scanner, security audit"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500"></textarea>
            <p class="text-xs text-gray-400 mt-1">افصل بفاصلة. أهم 5-10 كلمات تصف موقعك.</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">رابط الموقع الرسمي</label>
            <input v-model="seo.site_url" type="url" placeholder="https://sec.erticaz.com" dir="ltr"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            <p class="text-xs text-gray-400 mt-1">يستخدم في sitemap.xml و canonical URLs</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">اسم الموقع المختصر</label>
            <input v-model="seo.site_name" type="text" placeholder="Seku - سيكو"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
          </div>

          <!-- Google Preview -->
          <div class="bg-gray-50 rounded-lg p-4 border border-gray-200">
            <p class="text-xs text-gray-500 mb-2 font-semibold">معاينة Google:</p>
            <div class="bg-white p-3 rounded border border-gray-200">
              <p class="text-sm text-gray-600 truncate" dir="ltr">{{ seo.site_url || 'https://example.com' }}</p>
              <h3 class="text-blue-700 text-lg font-medium hover:underline cursor-pointer">{{ seo.site_title || 'عنوان الموقع' }}</h3>
              <p class="text-sm text-gray-700 mt-1">{{ seo.site_description || 'وصف الموقع يظهر هنا...' }}</p>
            </div>
          </div>
        </div>

        <!-- SOCIAL TAB -->
        <div v-if="activeTab === 'social'" class="space-y-5">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">صورة المشاركة (OG Image)</label>

            <!-- Upload zone -->
            <div class="border-2 border-dashed border-gray-300 rounded-lg p-4 hover:border-indigo-400 transition-colors">
              <div v-if="seo.og_image" class="mb-3">
                <img :src="seo.og_image" alt="OG Image"
                  class="max-w-full h-auto rounded-lg border border-gray-200 max-h-48 mx-auto"
                  @error="$event.target.style.display='none'" />
              </div>

              <input ref="fileInput" type="file" accept="image/png,image/jpeg,image/webp"
                @change="handleImageUpload" class="hidden" />

              <div class="flex gap-2">
                <button @click="triggerFileInput" :disabled="uploadingImage"
                  class="flex-1 px-4 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 text-sm font-medium flex items-center justify-center gap-2">
                  <div v-if="uploadingImage" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                  </svg>
                  {{ uploadingImage ? 'جاري الرفع...' : (seo.og_image ? 'تغيير الصورة' : 'رفع صورة') }}
                </button>
                <button v-if="seo.og_image" @click="seo.og_image = ''"
                  class="px-4 py-2.5 bg-red-50 text-red-600 hover:bg-red-100 rounded-lg text-sm font-medium">
                  إزالة
                </button>
              </div>
            </div>

            <!-- Or paste URL -->
            <div class="mt-3">
              <label class="block text-xs text-gray-500 mb-1">أو ألصق رابط الصورة مباشرة:</label>
              <input v-model="seo.og_image" type="url" placeholder="https://your-site.com/og-image.png" dir="ltr"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-xs" />
            </div>

            <!-- Recommendations -->
            <div class="mt-3 bg-blue-50 border border-blue-200 rounded-lg p-3 text-xs text-blue-900">
              <p class="font-semibold mb-1">📏 المواصفات الموصى بها:</p>
              <ul class="list-disc list-inside space-y-0.5 mr-2">
                <li>الحجم: <strong>1200 × 630 بكسل</strong> (نسبة 1.91:1)</li>
                <li>الصيغة: PNG أو JPG أو WebP</li>
                <li>الحد الأقصى: <strong>5MB</strong></li>
                <li>يظهر عند مشاركة الرابط على Facebook, LinkedIn, WhatsApp, Twitter</li>
              </ul>
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">حساب Twitter / X</label>
            <input v-model="seo.twitter_handle" type="text" placeholder="@IrtikazTech" dir="ltr"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Facebook App ID</label>
            <input v-model="seo.facebook_app_id" type="text" placeholder="1234567890" dir="ltr"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
            <p class="text-xs text-gray-400 mt-1">اختياري — للاندماج مع Facebook Insights</p>
          </div>

          <!-- Social Preview -->
          <div class="bg-gray-50 rounded-lg p-4 border border-gray-200">
            <p class="text-xs text-gray-500 mb-2 font-semibold">معاينة Facebook / WhatsApp:</p>
            <div class="bg-white rounded-lg overflow-hidden border border-gray-300 max-w-md">
              <div class="bg-gradient-to-br from-indigo-500 to-purple-600 h-32 flex items-center justify-center text-white text-sm">
                <span v-if="!seo.og_image">صورة OG ستظهر هنا</span>
                <img v-else :src="seo.og_image" alt="OG" class="w-full h-full object-cover" @error="$event.target.style.display='none'" />
              </div>
              <div class="p-3">
                <p class="text-xs text-gray-400 uppercase" dir="ltr">{{ seo.site_url?.replace(/^https?:\/\//, '') }}</p>
                <h4 class="font-bold text-gray-900 text-sm mt-1">{{ seo.site_title || 'عنوان الموقع' }}</h4>
                <p class="text-xs text-gray-600 mt-1">{{ seo.site_description?.slice(0, 100) || 'وصف الموقع...' }}</p>
              </div>
            </div>
          </div>
        </div>

        <!-- ANALYTICS TAB -->
        <div v-if="activeTab === 'analytics'" class="space-y-5">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1 flex items-center gap-2">
              Google Analytics 4 Measurement ID
              <span v-if="seo.google_analytics" class="px-2 py-0.5 bg-green-100 text-green-700 rounded-full text-xs font-semibold">نشط</span>
              <span v-else class="px-2 py-0.5 bg-gray-100 text-gray-500 rounded-full text-xs">غير مفعّل</span>
            </label>
            <input v-model="seo.google_analytics" type="text" placeholder="G-XXXXXXXXXX" dir="ltr"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            <p class="text-xs text-gray-400 mt-1">من Google Analytics 4 — يبدأ بـ G-</p>

            <!-- GA Setup Guide — Detailed -->
            <div v-if="!seo.google_analytics" class="mt-3 bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm">
              <p class="font-bold text-blue-900 mb-3 text-base">📊 خطوات إنشاء Property في Google Analytics 4</p>

              <div class="space-y-3 text-blue-900">
                <!-- Step 1 -->
                <div class="bg-white rounded-lg p-3 border border-blue-100">
                  <p class="font-semibold mb-1">① افتح Google Analytics</p>
                  <a href="https://analytics.google.com/" target="_blank"
                    class="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 underline">
                    https://analytics.google.com
                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
                  </a>
                  <p class="text-xs text-blue-700 mt-1">سجّل دخول بحساب Google الخاص بك</p>
                </div>

                <!-- Step 2 -->
                <div class="bg-white rounded-lg p-3 border border-blue-100">
                  <p class="font-semibold mb-1">② إنشاء حساب (Account)</p>
                  <ul class="text-xs text-blue-700 space-y-1 list-disc list-inside mr-2">
                    <li>اضغط على <strong>الإعدادات (Admin)</strong> ⚙️ في أسفل القائمة اليسرى</li>
                    <li>اضغط <strong>Create Account</strong> (إنشاء حساب)</li>
                    <li>أدخل اسم الحساب: مثلاً <code class="bg-blue-50 px-1 rounded">Irtikaz</code></li>
                    <li>اضغط <strong>Next</strong></li>
                  </ul>
                </div>

                <!-- Step 3 -->
                <div class="bg-white rounded-lg p-3 border border-blue-100">
                  <p class="font-semibold mb-1">③ إنشاء Property (الأهم)</p>
                  <ul class="text-xs text-blue-700 space-y-1 list-disc list-inside mr-2">
                    <li>اسم Property: <code class="bg-blue-50 px-1 rounded">Seku - sec.erticaz.com</code></li>
                    <li>المنطقة الزمنية: <strong>Iraq (GMT+3)</strong></li>
                    <li>العملة: <strong>USD</strong> أو <strong>IQD</strong></li>
                    <li>اضغط <strong>Next</strong> ثم <strong>Create</strong></li>
                  </ul>
                </div>

                <!-- Step 4 -->
                <div class="bg-white rounded-lg p-3 border border-blue-100">
                  <p class="font-semibold mb-1">④ اختر منصة "Web"</p>
                  <ul class="text-xs text-blue-700 space-y-1 list-disc list-inside mr-2">
                    <li>في "Choose a platform" اختر <strong>Web</strong> 🌐</li>
                    <li>أدخل URL الموقع: <code class="bg-blue-50 px-1 rounded">{{ seo.site_url || 'https://sec.erticaz.com' }}</code></li>
                    <li>اسم Stream: <code class="bg-blue-50 px-1 rounded">Main Site</code></li>
                    <li>اضغط <strong>Create stream</strong></li>
                  </ul>
                </div>

                <!-- Step 5 -->
                <div class="bg-white rounded-lg p-3 border-2 border-green-300 bg-green-50">
                  <p class="font-semibold mb-1 text-green-900">⑤ انسخ Measurement ID</p>
                  <ul class="text-xs text-green-800 space-y-1 list-disc list-inside mr-2">
                    <li>سيظهر <strong>Measurement ID</strong> أعلى الصفحة (يبدأ بـ <code class="bg-white px-1 rounded font-bold">G-</code>)</li>
                    <li>مثال: <code class="bg-white px-1 rounded">G-ABC123XYZ</code></li>
                    <li>اضغط أيقونة النسخ 📋 بجانبه</li>
                    <li><strong>الصقه في الحقل أعلاه</strong> واضغط حفظ ✓</li>
                  </ul>
                </div>
              </div>

              <div class="mt-3 p-2 bg-yellow-50 border border-yellow-200 rounded text-xs text-yellow-900">
                <strong>💡 ملاحظة:</strong> Property ID يختلف عن Measurement ID. نحن نحتاج Measurement ID فقط (يبدأ بـ G-).
              </div>
            </div>

            <div v-else class="mt-3 bg-green-50 border border-green-200 rounded-lg p-3 text-xs">
              <div class="flex items-center justify-between">
                <div>
                  <p class="font-semibold text-green-900">✓ Google Analytics متصل</p>
                  <p class="text-green-700 mt-1">يتم تتبع الزوار وتحركاتهم تلقائياً عبر جميع الصفحات.</p>
                </div>
                <a :href="`https://analytics.google.com/analytics/web/#/p${seo.google_analytics?.replace('G-','')}/reports/intelligenthome`" target="_blank"
                  class="px-3 py-1.5 bg-green-600 text-white rounded text-xs font-medium hover:bg-green-700">
                  افتح GA Dashboard
                </a>
              </div>
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Google Search Console Verification</label>
            <input v-model="seo.google_search_console" type="text" placeholder="abc123def456..." dir="ltr"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            <p class="text-xs text-gray-400 mt-1">رمز التحقق من Google Search Console</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Bing Webmaster Verification</label>
            <input v-model="seo.bing_verification" type="text" placeholder="ABC123..." dir="ltr"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
          </div>

          <!-- Useful Links -->
          <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 class="text-sm font-semibold text-blue-900 mb-2">روابط مفيدة:</h4>
            <ul class="space-y-1 text-sm">
              <li><a href="https://search.google.com/search-console" target="_blank" class="text-blue-600 hover:underline">Google Search Console →</a></li>
              <li><a href="https://www.bing.com/webmasters" target="_blank" class="text-blue-600 hover:underline">Bing Webmaster Tools →</a></li>
              <li><a href="https://analytics.google.com/" target="_blank" class="text-blue-600 hover:underline">Google Analytics →</a></li>
              <li><a href="https://pagespeed.web.dev/" target="_blank" class="text-blue-600 hover:underline">Google PageSpeed Insights →</a></li>
            </ul>
          </div>
        </div>

        <!-- ADVANCED TAB -->
        <div v-if="activeTab === 'advanced'" class="space-y-5">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">اسم المنظمة</label>
            <input v-model="seo.organization_name" type="text" placeholder="Irtikaz Technical Solutions"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">رابط المنظمة</label>
            <input v-model="seo.organization_url" type="url" placeholder="https://erticaz.com" dir="ltr"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
          </div>

          <!-- Indexing Toggle -->
          <div class="flex items-center justify-between p-4 bg-red-50 border border-red-200 rounded-lg">
            <div>
              <p class="font-semibold text-red-900">إيقاف فهرسة محركات البحث</p>
              <p class="text-xs text-red-700 mt-1">⚠️ يمنع Google و Bing من فهرسة الموقع. استخدم فقط للمواقع الخاصة.</p>
            </div>
            <label class="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" v-model="seo.disable_indexing" true-value="true" false-value="false" class="sr-only peer" />
              <div class="w-12 h-7 bg-gray-300 peer-checked:bg-red-500 rounded-full transition-colors"></div>
              <div class="absolute right-1 top-1 w-5 h-5 bg-white rounded-full transition-transform peer-checked:-translate-x-5"></div>
            </label>
          </div>

          <!-- Sitemap & Robots URLs -->
          <div class="bg-gray-50 rounded-lg p-4 border border-gray-200">
            <h4 class="text-sm font-semibold text-gray-700 mb-3">روابط نظام SEO:</h4>
            <div class="space-y-2">
              <div class="flex items-center gap-2">
                <span class="text-xs text-gray-500 w-24">Sitemap:</span>
                <code class="flex-1 text-xs bg-white px-2 py-1 rounded border border-gray-200 font-mono" dir="ltr">{{ sitemapURL }}</code>
                <button @click="copyToClipboard(sitemapURL)" class="text-indigo-600 hover:text-indigo-800 text-xs">نسخ</button>
              </div>
              <div class="flex items-center gap-2">
                <span class="text-xs text-gray-500 w-24">Robots:</span>
                <code class="flex-1 text-xs bg-white px-2 py-1 rounded border border-gray-200 font-mono" dir="ltr">{{ robotsURL }}</code>
                <button @click="copyToClipboard(robotsURL)" class="text-indigo-600 hover:text-indigo-800 text-xs">نسخ</button>
              </div>
            </div>
            <p class="text-xs text-gray-500 mt-3">قدّم رابط الـ Sitemap في Google Search Console للحصول على فهرسة أسرع.</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
