<script setup>
import { ref, computed, onMounted } from 'vue'
import { getCorrelations, getTargets } from '../api'

const corr = ref({ ip: [], nameserver: [], mail: [], email: [], targets: 0 })
const allTargets = ref([])
const loading = ref(true)
const query = ref('')
const selected = ref('')
const expanded = ref({})

const typeMeta = {
  ip: { label: 'نفس الخادم (IP)', icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01' },
  nameserver: { label: 'نفس Name Server', icon: 'M21 12a9 9 0 11-18 0 9 9 0 0118 0zM3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18M12 3a15 15 0 000 18' },
  mail: { label: 'نفس خادم البريد', icon: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
  email: { label: 'نفس الإيميل', icon: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z' },
}
const types = ['ip', 'nameserver', 'mail', 'email']

function hostOf(url) {
  try {
    let u = (url || '').trim()
    if (!u.includes('://')) u = 'https://' + u
    return new URL(u).hostname.toLowerCase()
  } catch {
    return ''
  }
}

// union of every host that appears anywhere (targets + correlation groups)
const allHosts = computed(() => {
  const set = new Set()
  allTargets.value.forEach((t) => { const h = hostOf(t.url); if (h) set.add(h) })
  types.forEach((k) => (corr.value[k] || []).forEach((g) => g.targets.forEach((h) => set.add(h))))
  return [...set].sort()
})

// what a given host shares with others
function sharedFor(host) {
  const out = []
  for (const k of types) {
    for (const g of corr.value[k] || []) {
      if (g.targets.includes(host)) {
        const others = g.targets.filter((t) => t !== host)
        if (others.length) out.push({ type: k, value: g.value, others })
      }
    }
  }
  return out
}
const selectedShares = computed(() => (selected.value ? sharedFor(selected.value) : []))
const connectedCount = computed(() => {
  const s = new Set()
  selectedShares.value.forEach((x) => x.others.forEach((o) => s.add(o)))
  return s.size
})

const suggestions = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return []
  return allHosts.value.filter((h) => h.includes(q)).slice(0, 8)
})

const totalLinks = computed(() => types.reduce((n, k) => n + (corr.value[k]?.length || 0), 0))

function pick(host) {
  selected.value = host
  query.value = ''
}
function clearSel() {
  selected.value = ''
  query.value = ''
}
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
    const [c, t] = await Promise.all([getCorrelations(refresh), getTargets({ limit: 1000 })])
    corr.value = c.data || { ip: [], nameserver: [], mail: [], email: [], targets: 0 }
    const td = t.data
    allTargets.value = Array.isArray(td) ? td : td.data || []
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
    <div class="flex items-start justify-between gap-3 mb-3">
      <div>
        <h1 class="text-2xl font-bold text-gray-900">الروابط المشتركة</h1>
        <p class="text-sm text-gray-500 mt-1">ابحث عن موقع لتشوف ما يشترك به مع مواقعك الأخرى (نفس IP / Name Server / خادم بريد / إيميل).</p>
      </div>
      <button @click="load(true)" :disabled="loading" class="flex-shrink-0 px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50">تحديث</button>
    </div>

    <!-- Search -->
    <div class="relative mb-5">
      <div class="flex items-center gap-2 bg-white border border-gray-300 rounded-xl px-3 py-2.5 focus-within:ring-2 focus-within:ring-indigo-500">
        <svg class="w-5 h-5 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
        <input v-model="query" type="text" placeholder="اكتب اسم موقع… مثلاً كلية أو جامعة" class="flex-1 outline-none bg-transparent" @keyup.enter="suggestions[0] && pick(suggestions[0])" />
        <button v-if="selected" @click="clearSel" class="text-xs text-gray-400 hover:text-gray-700">مسح ×</button>
      </div>
      <!-- suggestions dropdown -->
      <div v-if="suggestions.length" class="absolute z-20 mt-1 w-full bg-white border border-gray-200 rounded-lg shadow-lg overflow-hidden">
        <button v-for="h in suggestions" :key="h" @click="pick(h)" class="w-full text-right px-3 py-2 text-sm hover:bg-indigo-50 flex items-center gap-2">
          <svg class="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg>
          <span class="break-all">{{ h }}</span>
        </button>
      </div>
    </div>

    <div v-if="loading" class="py-16 text-center text-gray-400 text-sm">جارٍ تحليل النطاقات (DNS)…</div>

    <!-- FOCUS: what a selected site shares -->
    <div v-else-if="selected">
      <div class="bg-white rounded-xl border border-gray-200 shadow-sm p-4 mb-4">
        <p class="text-sm text-gray-500">المشترك مع</p>
        <p class="text-lg font-semibold text-gray-900 break-all">{{ selected }}</p>
        <p class="text-xs mt-1" :class="connectedCount ? 'text-indigo-600' : 'text-gray-400'">
          {{ connectedCount ? `مرتبط بـ ${connectedCount} موقع عبر ${selectedShares.length} خاصية مشتركة` : 'لا يوجد أي عنصر مشترك مع مواقع أخرى' }}
        </p>
      </div>

      <div v-if="selectedShares.length" class="space-y-3">
        <div v-for="(s, i) in selectedShares" :key="i" class="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
          <div class="flex items-center gap-2 mb-2">
            <svg class="w-5 h-5 text-indigo-600 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" :d="typeMeta[s.type].icon" /></svg>
            <span class="text-sm font-semibold text-gray-900">{{ typeMeta[s.type].label }}:</span>
            <code class="text-sm text-gray-700 break-all">{{ s.value }}</code>
          </div>
          <div class="mr-3 pr-3 border-r-2 border-indigo-100 space-y-1">
            <p class="text-[11px] text-gray-400 mb-1">مواقع أخرى تشترك بنفس القيمة:</p>
            <button v-for="o in s.others" :key="o" @click="pick(o)" class="block text-sm text-gray-700 hover:text-indigo-600 py-0.5">
              <span class="inline-block w-1.5 h-1.5 rounded-full bg-indigo-300 ml-2"></span>{{ o }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- OVERVIEW: all shared clusters (when nothing selected) -->
    <div v-else>
      <p class="text-xs text-gray-400 mb-3">{{ corr.targets }} موقع محلّل · {{ totalLinks }} مجموعة مشتركة — أو اكتب اسم موقع فوق للبحث المباشر.</p>
      <div v-if="totalLinks === 0" class="py-14 text-center text-gray-500">لا توجد روابط مشتركة بين المواقع الحالية.</div>
      <div v-else class="space-y-5">
        <div v-for="k in types" :key="k" v-show="corr[k]?.length" class="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div class="flex items-center gap-2 px-4 py-3 border-b border-gray-100 bg-gray-50/60">
            <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" :d="typeMeta[k].icon" /></svg>
            <p class="font-semibold text-gray-900 text-sm">{{ typeMeta[k].label }}</p>
            <span class="mr-auto text-xs bg-indigo-100 text-indigo-700 rounded-full px-2 py-0.5">{{ corr[k].length }}</span>
          </div>
          <div class="divide-y divide-gray-100">
            <div v-for="g in corr[k]" :key="g.value" class="px-2">
              <button @click="toggle(k, g.value)" class="w-full flex items-center gap-2 py-2.5 px-2 hover:bg-indigo-50/40 rounded-lg text-right">
                <svg class="w-4 h-4 text-gray-400 flex-shrink-0 transition-transform" :class="isOpen(k, g.value) ? 'rotate-90' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg>
                <code class="text-sm text-gray-800 break-all">{{ g.value }}</code>
                <span class="mr-auto flex-shrink-0 text-[11px] bg-gray-100 text-gray-600 rounded-full px-2 py-0.5">{{ g.targets.length }} مواقع</span>
              </button>
              <div v-if="isOpen(k, g.value)" class="mr-3 pr-3 border-r-2 border-indigo-100 pb-2 space-y-1">
                <button v-for="t in g.targets" :key="t" @click="pick(t)" class="block text-sm text-gray-600 hover:text-indigo-600 py-1">
                  <span class="inline-block w-1.5 h-1.5 rounded-full bg-indigo-300 ml-2"></span>{{ t }}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
