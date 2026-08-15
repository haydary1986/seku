<script setup>
import { ref, computed, onMounted, watch, nextTick, onUnmounted } from 'vue'
import { getCorrelations, getTargets } from '../api'

const corr = ref({ ip: [], nameserver: [], mail: [], email: [], targets: 0 })
const allTargets = ref([])
const loading = ref(true)
const query = ref('')
const selected = ref('')
const expanded = ref({})
const viewMode = ref('search') // 'search' | 'graph'

const typeMeta = {
  ip: { label: 'نفس الخادم (IP)', color: '#0ea5e9', icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01' },
  nameserver: { label: 'نفس Name Server', color: '#8b5cf6', icon: 'M21 12a9 9 0 11-18 0 9 9 0 0118 0zM3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18M12 3a15 15 0 000 18' },
  mail: { label: 'نفس خادم البريد', color: '#f59e0b', icon: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
  email: { label: 'نفس الإيميل', color: '#ef4444', icon: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z' },
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

const allHosts = computed(() => {
  const set = new Set()
  allTargets.value.forEach((t) => { const h = hostOf(t.url); if (h) set.add(h) })
  types.forEach((k) => (corr.value[k] || []).forEach((g) => g.targets.forEach((h) => set.add(h))))
  return [...set].sort()
})

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
  query.value = ''
  if (viewMode.value === 'graph') focusNode(host)
  else selected.value = host
}
function clearSel() { selected.value = ''; query.value = '' }
function toggle(key, value) { expanded.value[key + '::' + value] = !expanded.value[key + '::' + value] }
function isOpen(key, value) { return !!expanded.value[key + '::' + value] }

// ── Investigation graph (cytoscape, lazy-loaded) ──
let cy = null
const graphEl = ref(null)

function buildElements() {
  const els = []
  const sites = new Set()
  for (const k of types) {
    for (const g of corr.value[k] || []) {
      const entId = k + '::' + g.value
      els.push({ data: { id: entId, label: g.value, kind: k, degree: g.targets.length } })
      for (const site of g.targets) {
        const sid = 'site::' + site
        if (!sites.has(site)) { sites.add(site); els.push({ data: { id: sid, label: site, kind: 'site' } }) }
        els.push({ data: { id: entId + '=>' + sid, source: entId, target: sid } })
      }
    }
  }
  return els
}

async function initGraph() {
  await nextTick()
  if (!graphEl.value) return
  const cytoscape = (await import('cytoscape')).default
  if (cy) { cy.destroy(); cy = null }
  cy = cytoscape({
    container: graphEl.value,
    elements: buildElements(),
    wheelSensitivity: 0.25,
    style: [
      { selector: 'node[kind="site"]', style: { 'background-color': '#059669', label: 'data(label)', 'font-size': 7, width: 14, height: 14, color: '#475569', 'text-valign': 'bottom', 'text-margin-y': 2, 'min-zoomed-font-size': 7 } },
      { selector: 'node[kind!="site"]', style: { label: 'data(label)', 'font-size': 8, color: '#fff', 'text-outline-color': '#0f172a', 'text-outline-width': 1, 'text-valign': 'center', width: 'mapData(degree, 2, 12, 28, 66)', height: 'mapData(degree, 2, 12, 28, 66)', 'min-zoomed-font-size': 8 } },
      { selector: 'node[kind="ip"]', style: { 'background-color': '#0ea5e9', shape: 'round-rectangle' } },
      { selector: 'node[kind="nameserver"]', style: { 'background-color': '#8b5cf6', shape: 'diamond' } },
      { selector: 'node[kind="mail"]', style: { 'background-color': '#f59e0b', shape: 'hexagon' } },
      { selector: 'node[kind="email"]', style: { 'background-color': '#ef4444', shape: 'triangle' } },
      { selector: 'edge', style: { width: 1, 'line-color': '#cbd5e1', 'curve-style': 'bezier' } },
      { selector: '.faded', style: { opacity: 0.1, 'text-opacity': 0 } },
      { selector: '.pulse', style: { 'border-width': 3, 'border-color': '#059669' } },
    ],
    layout: { name: 'cose', animate: true, animationDuration: 600, nodeRepulsion: 6000, idealEdgeLength: 70, padding: 30 },
  })
  cy.on('tap', 'node', (e) => highlight(e.target))
  cy.on('tap', (e) => { if (e.target === cy) resetHi() })
}
function highlight(node) {
  if (!cy) return
  resetHi()
  const nhood = node.closedNeighborhood()
  cy.elements().difference(nhood).addClass('faded')
  node.addClass('pulse')
}
function resetHi() {
  if (!cy) return
  cy.elements().removeClass('faded').removeClass('pulse')
}
function focusNode(host) {
  if (!cy) return
  const n = cy.getElementById('site::' + host)
  if (!n || n.empty()) return
  highlight(n)
  cy.animate({ center: { eles: n }, zoom: 1.4 }, { duration: 400 })
}
function relayout() {
  if (cy) cy.layout({ name: 'cose', animate: true, nodeRepulsion: 6000, idealEdgeLength: 70, padding: 30 }).run()
}

watch(viewMode, (m) => { if (m === 'graph') initGraph() })

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
  if (viewMode.value === 'graph') initGraph()
}
onMounted(() => load(false))
onUnmounted(() => cy && cy.destroy())
</script>

<template>
  <div class="max-w-4xl mx-auto p-4 md:p-6">
    <div class="flex items-start justify-end gap-3 mb-3">
      <button @click="load(true)" :disabled="loading" class="flex-shrink-0 px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50">تحديث</button>
    </div>

    <!-- view tabs -->
    <div class="flex gap-1 border-b border-gray-200 mb-4">
      <button @click="viewMode = 'search'" :class="['px-4 py-2 text-sm font-medium -mb-px border-b-2', viewMode === 'search' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-gray-500 hover:text-gray-700']">بحث</button>
      <button @click="viewMode = 'graph'" :class="['px-4 py-2 text-sm font-medium -mb-px border-b-2', viewMode === 'graph' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-gray-500 hover:text-gray-700']">شجرة التحقيق</button>
    </div>

    <!-- Search box (shared) -->
    <div class="relative mb-5">
      <div class="flex items-center gap-2 bg-white border border-gray-300 rounded-xl px-3 py-2.5 focus-within:ring-2 focus-within:ring-indigo-500">
        <svg class="w-5 h-5 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
        <input v-model="query" type="text" :placeholder="viewMode === 'graph' ? 'ابحث وركّز على موقع في الشجرة…' : 'اكتب اسم موقع… مثلاً كلية أو جامعة'" class="flex-1 outline-none bg-transparent" @keyup.enter="suggestions[0] && pick(suggestions[0])" />
        <button v-if="selected && viewMode === 'search'" @click="clearSel" class="text-xs text-gray-400 hover:text-gray-700">مسح ×</button>
      </div>
      <div v-if="suggestions.length" class="absolute z-20 mt-1 w-full bg-white border border-gray-200 rounded-lg shadow-lg overflow-hidden">
        <button v-for="h in suggestions" :key="h" @click="pick(h)" class="w-full text-right px-3 py-2 text-sm hover:bg-indigo-50 break-all">{{ h }}</button>
      </div>
    </div>

    <div v-if="loading" class="py-16 text-center text-gray-400 text-sm">جارٍ تحليل النطاقات (DNS)…</div>

    <!-- ============ GRAPH VIEW ============ -->
    <div v-show="!loading && viewMode === 'graph'">
      <div class="flex flex-wrap items-center gap-3 mb-2 text-xs text-gray-600">
        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded-full" style="background:#059669"></span> موقع</span>
        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5" style="background:#0ea5e9"></span> IP</span>
        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rotate-45" style="background:#8b5cf6"></span> Name Server</span>
        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5" style="background:#f59e0b"></span> خادم بريد</span>
        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5" style="background:#ef4444"></span> إيميل</span>
        <button @click="relayout" class="mr-auto px-2 py-1 border border-gray-300 rounded hover:bg-gray-50">إعادة الترتيب</button>
      </div>
      <div v-if="totalLinks === 0" class="py-14 text-center text-gray-500 border border-dashed border-gray-200 rounded-xl">لا توجد روابط مشتركة لعرضها كشجرة.</div>
      <div v-else ref="graphEl" class="w-full h-[70vh] bg-slate-50 border border-gray-200 rounded-xl"></div>
      <p class="text-[11px] text-gray-400 mt-2">الكيانات الأكبر = جذور يرتبط بها مواقع أكثر. انقر أي عقدة لعزل شبكتها، واسحب/كبّر للاستكشاف.</p>
    </div>

    <!-- ============ SEARCH VIEW ============ -->
    <div v-show="!loading && viewMode === 'search'">
      <div v-if="selected">
        <div class="bg-white rounded-xl border border-gray-200 shadow-sm p-4 mb-4">
          <p class="text-sm text-gray-500">المشترك مع</p>
          <p class="text-lg font-semibold text-gray-900 break-all">{{ selected }}</p>
          <p class="text-xs mt-1" :class="connectedCount ? 'text-indigo-600' : 'text-gray-400'">{{ connectedCount ? `مرتبط بـ ${connectedCount} موقع عبر ${selectedShares.length} خاصية مشتركة` : 'لا يوجد أي عنصر مشترك مع مواقع أخرى' }}</p>
        </div>
        <div v-if="selectedShares.length" class="space-y-3">
          <div v-for="(s, i) in selectedShares" :key="i" class="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
            <div class="flex items-center gap-2 mb-2">
              <svg class="w-5 h-5 flex-shrink-0" :style="{ color: typeMeta[s.type].color }" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" :d="typeMeta[s.type].icon" /></svg>
              <span class="text-sm font-semibold text-gray-900">{{ typeMeta[s.type].label }}:</span>
              <code class="text-sm text-gray-700 break-all">{{ s.value }}</code>
            </div>
            <div class="mr-3 pr-3 border-r-2 border-indigo-100 space-y-1">
              <p class="text-[11px] text-gray-400 mb-1">مواقع أخرى تشترك بنفس القيمة:</p>
              <button v-for="o in s.others" :key="o" @click="pick(o)" class="block text-sm text-gray-700 hover:text-indigo-600 py-0.5"><span class="inline-block w-1.5 h-1.5 rounded-full bg-indigo-300 ml-2"></span>{{ o }}</button>
            </div>
          </div>
        </div>
      </div>
      <div v-else>
        <p class="text-xs text-gray-400 mb-3">{{ corr.targets }} موقع محلّل · {{ totalLinks }} مجموعة مشتركة — ابحث فوق أو استعرض المجموعات:</p>
        <div v-if="totalLinks === 0" class="py-14 text-center text-gray-500">لا توجد روابط مشتركة بين المواقع الحالية.</div>
        <div v-else class="space-y-5">
          <div v-for="k in types" :key="k" v-show="corr[k]?.length" class="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
            <div class="flex items-center gap-2 px-4 py-3 border-b border-gray-100 bg-gray-50/60">
              <svg class="w-5 h-5" :style="{ color: typeMeta[k].color }" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" :d="typeMeta[k].icon" /></svg>
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
                  <button v-for="t in g.targets" :key="t" @click="pick(t)" class="block text-sm text-gray-600 hover:text-indigo-600 py-1"><span class="inline-block w-1.5 h-1.5 rounded-full bg-indigo-300 ml-2"></span>{{ t }}</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
