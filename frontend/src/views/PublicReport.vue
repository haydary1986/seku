<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const loading = ref(true)
const notFound = ref(false)
const report = ref(null)

const gradeColor = computed(() => {
  const g = report.value?.grade || ''
  if (g.startsWith('A')) return '#0b8457'
  if (g.startsWith('B')) return '#5c9e1f'
  if (g.startsWith('C')) return '#b8860b'
  if (g.startsWith('D')) return '#db6b00'
  return '#d6293e'
})

const sev = computed(() => report.value?.summary || {})
const fmtDate = (s) => s ? new Date(s).toLocaleDateString('ar-IQ', { year: 'numeric', month: 'long', day: 'numeric' }) : ''

async function load() {
  try {
    const res = await fetch(`/api/public/report/${route.params.token}`)
    if (!res.ok) { notFound.value = true; return }
    report.value = await res.json()
  } catch { notFound.value = true } finally { loading.value = false }
}
onMounted(load)
</script>

<template>
  <div dir="rtl" class="min-h-screen bg-gray-50 flex flex-col items-center py-10 px-4">
    <div v-if="loading" class="text-gray-400 py-20">جارٍ التحميل…</div>

    <div v-else-if="notFound" class="text-center py-20">
      <p class="text-2xl font-bold text-gray-900 mb-2">التقرير غير متاح</p>
      <p class="text-gray-500">قد يكون الرابط غير صحيح أو أُلغيت مشاركته.</p>
      <a href="/" class="inline-block mt-6 px-5 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">الذهاب إلى سيكو</a>
    </div>

    <div v-else class="w-full max-w-2xl">
      <!-- Brand header -->
      <div class="flex items-center justify-center gap-2 mb-6">
        <span class="text-2xl">🛡️</span>
        <span class="text-xl font-extrabold text-gray-900">سيكو <span class="text-indigo-600">Seku</span></span>
      </div>

      <!-- Score card -->
      <div class="bg-white rounded-2xl shadow-sm border border-gray-200 p-8 text-center">
        <p class="text-sm text-gray-500 mb-1">تقرير الأمان لِـ</p>
        <p class="text-lg font-bold text-gray-900 break-all mb-6">{{ report.domain }}</p>

        <div class="inline-flex items-end justify-center gap-2 mb-2">
          <span class="text-6xl font-extrabold" :style="{ color: gradeColor }">{{ Math.round(report.score) }}</span>
          <span class="text-2xl text-gray-400 mb-2">/1000</span>
        </div>
        <div class="text-3xl font-extrabold mb-6" :style="{ color: gradeColor }">التقدير: {{ report.grade }}</div>

        <!-- Severity summary -->
        <div class="grid grid-cols-2 sm:grid-cols-5 gap-2 text-sm">
          <div class="rounded-lg p-3 bg-red-50"><div class="font-extrabold text-red-600 text-lg">{{ sev.critical || 0 }}</div><div class="text-gray-500 text-xs">حرِجة</div></div>
          <div class="rounded-lg p-3 bg-orange-50"><div class="font-extrabold text-orange-600 text-lg">{{ sev.high || 0 }}</div><div class="text-gray-500 text-xs">عالية</div></div>
          <div class="rounded-lg p-3 bg-yellow-50"><div class="font-extrabold text-yellow-700 text-lg">{{ sev.medium || 0 }}</div><div class="text-gray-500 text-xs">متوسطة</div></div>
          <div class="rounded-lg p-3 bg-blue-50"><div class="font-extrabold text-blue-600 text-lg">{{ sev.low || 0 }}</div><div class="text-gray-500 text-xs">منخفضة</div></div>
          <div class="rounded-lg p-3 bg-green-50"><div class="font-extrabold text-green-600 text-lg">{{ sev.passed || 0 }}</div><div class="text-gray-500 text-xs">ناجحة</div></div>
        </div>

        <p v-if="report.scanned_at" class="text-xs text-gray-400 mt-6">تاريخ الفحص: {{ fmtDate(report.scanned_at) }}</p>
      </div>

      <!-- Categories -->
      <div v-if="report.categories?.length" class="bg-white rounded-2xl shadow-sm border border-gray-200 p-6 mt-4">
        <h3 class="font-semibold text-gray-900 mb-3">الفئات المفحوصة</h3>
        <div class="flex flex-wrap gap-2">
          <span v-for="cat in report.categories" :key="cat.category"
            class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium"
            :class="cat.status === 'fail' ? 'bg-red-50 text-red-700' : 'bg-green-50 text-green-700'">
            <span>{{ cat.status === 'fail' ? '✕' : '✓' }}</span>{{ cat.category }}
          </span>
        </div>
      </div>

      <!-- CTA -->
      <div class="text-center mt-8">
        <p class="text-gray-500 text-sm mb-3">افحص أمان موقعك مجاناً</p>
        <a href="/register" class="inline-block px-6 py-3 bg-indigo-600 text-white rounded-xl font-semibold hover:bg-indigo-700 transition-all">جرّب سيكو مجاناً</a>
      </div>
      <p class="text-center text-xs text-gray-400 mt-6">مُقدَّم من سيكو · sec.erticaz.com</p>
    </div>
  </div>
</template>
