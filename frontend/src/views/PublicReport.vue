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
  <div dir="rtl" class="public-shell min-h-screen flex flex-col items-center py-10 px-4">
    <div v-if="loading" class="text-gray-400 dark:text-slate-400 py-20">جارٍ التحميل…</div>

    <div v-else-if="notFound" class="text-center py-20">
      <p class="text-2xl font-bold text-gray-900 dark:text-white mb-2">التقرير غير متاح</p>
      <p class="text-gray-500 dark:text-slate-400">قد يكون الرابط غير صحيح أو أُلغيت مشاركته.</p>
      <a href="/" class="inline-block mt-6 px-5 py-2.5 bg-accent-grad glow-accent text-white rounded-lg hover:opacity-90">الذهاب إلى سيكو</a>
    </div>

    <div v-else class="w-full max-w-2xl">
      <!-- Brand header -->
      <div class="flex items-center justify-center gap-2 mb-6">
        <span class="text-2xl">🛡️</span>
        <span class="text-xl font-extrabold text-gray-900 dark:text-white">سيكو <span class="text-gradient">Seku</span></span>
      </div>

      <!-- Score card -->
      <div class="card ring-grid p-8 text-center">
        <p class="text-sm text-gray-500 dark:text-slate-400 mb-1">تقرير الأمان لِـ</p>
        <p class="text-lg font-bold text-gray-900 dark:text-white break-all mb-6">{{ report.domain }}</p>

        <div class="inline-flex items-end justify-center gap-2 mb-2">
          <span class="text-6xl font-extrabold font-mono" :style="{ color: gradeColor }">{{ Math.round(report.score) }}</span>
          <span class="text-2xl font-mono text-gray-400 dark:text-slate-500 mb-2">/1000</span>
        </div>
        <div class="text-3xl font-extrabold font-mono mb-6" :style="{ color: gradeColor }">التقدير: {{ report.grade }}</div>

        <!-- Severity summary -->
        <div class="grid grid-cols-2 sm:grid-cols-5 gap-2 text-sm">
          <div class="rounded-lg p-3 bg-white/5 border border-white/10"><div class="font-extrabold font-mono text-rose-400 text-lg">{{ sev.critical || 0 }}</div><div class="mt-1"><span class="sev sev-critical">حرِجة</span></div></div>
          <div class="rounded-lg p-3 bg-white/5 border border-white/10"><div class="font-extrabold font-mono text-orange-400 text-lg">{{ sev.high || 0 }}</div><div class="mt-1"><span class="sev sev-high">عالية</span></div></div>
          <div class="rounded-lg p-3 bg-white/5 border border-white/10"><div class="font-extrabold font-mono text-amber-400 text-lg">{{ sev.medium || 0 }}</div><div class="mt-1"><span class="sev sev-medium">متوسطة</span></div></div>
          <div class="rounded-lg p-3 bg-white/5 border border-white/10"><div class="font-extrabold font-mono text-sky-400 text-lg">{{ sev.low || 0 }}</div><div class="mt-1"><span class="sev sev-low">منخفضة</span></div></div>
          <div class="rounded-lg p-3 bg-white/5 border border-white/10"><div class="font-extrabold font-mono text-emerald-400 text-lg">{{ sev.passed || 0 }}</div><div class="text-emerald-400 text-xs mt-1">ناجحة</div></div>
        </div>

        <p v-if="report.scanned_at" class="text-xs text-gray-400 dark:text-slate-400 mt-6">تاريخ الفحص: {{ fmtDate(report.scanned_at) }}</p>
      </div>

      <!-- Categories -->
      <div v-if="report.categories?.length" class="card p-6 mt-4">
        <h3 class="font-semibold text-gray-900 dark:text-white mb-3">الفئات المفحوصة</h3>
        <div class="flex flex-wrap gap-2">
          <span v-for="cat in report.categories" :key="cat.category"
            class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium"
            :class="cat.status === 'fail' ? 'bg-rose-500/15 text-rose-300' : 'bg-emerald-500/15 text-emerald-300'">
            <span>{{ cat.status === 'fail' ? '✕' : '✓' }}</span>{{ cat.category }}
          </span>
        </div>
      </div>

      <!-- CTA -->
      <div class="text-center mt-8">
        <p class="text-gray-500 dark:text-slate-400 text-sm mb-3">افحص أمان موقعك مجاناً</p>
        <a href="/register" class="inline-block px-6 py-3 bg-accent-grad glow-accent text-white rounded-xl font-semibold hover:opacity-90 transition-all">جرّب سيكو مجاناً</a>
      </div>
      <p class="text-center text-xs text-gray-400 dark:text-slate-400 mt-6">مُقدَّم من سيكو · sec.erticaz.com</p>
    </div>
  </div>
</template>
