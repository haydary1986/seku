<script setup>
import { ref, computed, onMounted } from 'vue'
import { getCorrelations } from '../api'

const data = ref({ ip: [], nameserver: [], mail: [], email: [], targets: 0 })
const loading = ref(true)
const expanded = ref({})

const sections = [
  { key: 'ip', title: 'نفس عنوان IP', hint: 'مواقع مستضافة على نفس السيرفر', icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01' },
  { key: 'nameserver', title: 'نفس Name Server', hint: 'مواقع على نفس مزوّد الـ DNS', icon: 'M21 12a9 9 0 11-18 0 9 9 0 0118 0zM3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18M12 3a15 15 0 000 18' },
  { key: 'mail', title: 'نفس Mail Server', hint: 'مواقع تشترك بنفس خادم البريد', icon: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
  { key: 'email', title: 'نفس الإيميل', hint: 'إيميل ظهر بأكثر من موقع', icon: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z' },
]

const totalLinks = computed(
  () => sections.reduce((n, s) => n + (data.value[s.key]?.length || 0), 0)
)

function toggle(key, value) {
  const k = key + '::' + value
  expanded.value[k] = !expanded.value[k]
}
function isOpen(key, value) {
  return !!expanded.value[key + '::' + value]
}

async function load(refresh) {
  loading.value = true
  try {
    const { data: d } = await getCorrelations(refresh)
    data.value = d || { ip: [], nameserver: [], mail: [], email: [], targets: 0 }
  } catch {
    /* ignore */
  } finally {
    loading.value = false
  }
}
onMounted(() => load(false))
</script>

<template>
  <div class="max-w-4xl mx-auto p-4 md:p-6">
    <div class="flex items-start justify-between gap-3 mb-2">
      <div>
        <h1 class="text-2xl font-bold text-gray-900">الروابط المشتركة</h1>
        <p class="text-sm text-gray-500 mt-1">
          يكتشف المعلومات المشتركة بين مواقعك — نفس IP، أو Name Server، أو خادم بريد، أو إيميل ظهر بأكثر من موقع.
        </p>
      </div>
      <button
        @click="load(true)"
        :disabled="loading"
        class="flex-shrink-0 px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 flex items-center gap-1.5"
      >
        <svg class="w-4 h-4" :class="loading ? 'animate-spin' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
        تحديث
      </button>
    </div>

    <p v-if="!loading" class="text-xs text-gray-400 mb-5">
      {{ data.targets }} موقع محلّل · {{ totalLinks }} رابط مشترك
    </p>

    <!-- Loading -->
    <div v-if="loading" class="py-16 text-center text-gray-400 text-sm">
      <svg class="w-6 h-6 mx-auto mb-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
      </svg>
      جارٍ تحليل النطاقات (DNS)…
    </div>

    <!-- Empty -->
    <div v-else-if="totalLinks === 0" class="py-16 text-center">
      <p class="text-gray-500">لا توجد روابط مشتركة بين المواقع الحالية.</p>
      <p class="text-xs text-gray-400 mt-1">أضف المزيد من الأهداف أو أعد الفحص، ثم حدّث.</p>
    </div>

    <!-- Tree -->
    <div v-else class="space-y-5">
      <div v-for="s in sections" :key="s.key" v-show="data[s.key]?.length" class="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div class="flex items-center gap-2 px-4 py-3 border-b border-gray-100 bg-gray-50/60">
          <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" :d="s.icon" />
          </svg>
          <div>
            <p class="font-semibold text-gray-900 text-sm">{{ s.title }}</p>
            <p class="text-[11px] text-gray-400">{{ s.hint }}</p>
          </div>
          <span class="mr-auto text-xs bg-indigo-100 text-indigo-700 rounded-full px-2 py-0.5">{{ data[s.key].length }}</span>
        </div>

        <div class="divide-y divide-gray-100">
          <div v-for="g in data[s.key]" :key="g.value" class="px-2">
            <!-- node -->
            <button @click="toggle(s.key, g.value)" class="w-full flex items-center gap-2 py-2.5 px-2 hover:bg-indigo-50/40 rounded-lg text-right">
              <svg class="w-4 h-4 text-gray-400 transition-transform flex-shrink-0" :class="isOpen(s.key, g.value) ? 'rotate-90' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
              </svg>
              <code class="text-sm text-gray-800 break-all">{{ g.value }}</code>
              <span class="mr-auto flex-shrink-0 text-[11px] bg-gray-100 text-gray-600 rounded-full px-2 py-0.5">{{ g.targets.length }} مواقع</span>
            </button>
            <!-- children (targets) -->
            <div v-if="isOpen(s.key, g.value)" class="mr-3 pr-3 border-r-2 border-indigo-100 pb-2 space-y-1">
              <div v-for="t in g.targets" :key="t" class="flex items-center gap-2 text-sm text-gray-600 py-1">
                <span class="w-1.5 h-1.5 rounded-full bg-indigo-300 flex-shrink-0"></span>
                <span class="break-all">{{ t }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
