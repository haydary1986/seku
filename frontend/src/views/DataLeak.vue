<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { getTargets, runDataLeakScan, getDataLeakResults } from '../api'

const targets = ref([])
const results = ref(null)
const loading = ref(true)
const scanning = ref(false)
const selectedTargets = ref([])
let pollTimer = null

async function loadTargets() {
  try {
    const { data } = await getTargets({ limit: 1000 })
    targets.value = Array.isArray(data) ? data : (data.data || [])
  } catch (e) { console.error(e) }
}

async function loadResults() {
  try {
    const { data } = await getDataLeakResults()
    results.value = data
  } catch (e) { console.error(e) }
}

function toggleSelectAll() {
  if (selectedTargets.value.length === targets.value.length) {
    selectedTargets.value = []
  } else {
    selectedTargets.value = targets.value.map(t => t.ID)
  }
}

async function startScan() {
  scanning.value = true
  try {
    await runDataLeakScan(selectedTargets.value.length > 0 ? selectedTargets.value : [])
    selectedTargets.value = []
    // Poll for results every 5 seconds
    pollTimer = setInterval(async () => {
      await loadResults()
      if (results.value && results.value.running === 0) {
        clearInterval(pollTimer)
        scanning.value = false
      }
    }, 5000)
  } catch (e) {
    alert(e.response?.data?.error || 'Failed to start scan')
    scanning.value = false
  }
}

function getRiskColor(risk) {
  if (risk === 'critical') return 'bg-red-100 text-red-700 border-red-300'
  if (risk === 'high') return 'bg-orange-100 text-orange-700 border-orange-300'
  if (risk === 'medium') return 'bg-yellow-100 text-yellow-700 border-yellow-300'
  return 'bg-green-100 text-green-700 border-green-300'
}

function getRiskLabel(risk) {
  const labels = { critical: 'خطر حرج', high: 'خطر عالي', medium: 'خطر متوسط', safe: 'آمن' }
  return labels[risk] || risk
}

function parseDetails(details) {
  try { return JSON.parse(details) } catch { return {} }
}

onMounted(async () => {
  await loadTargets()
  await loadResults()
  loading.value = false
})

onBeforeUnmount(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">Data Leak Scanner</h1>
        <p class="text-gray-500 mt-1">Scan university domains for leaked credentials and data breaches</p>
      </div>
    </div>

    <!-- Scan Control -->
    <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
      <div class="flex items-center gap-3 mb-4">
        <div class="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center">
          <svg class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
          </svg>
        </div>
        <div>
          <h3 class="font-semibold text-gray-900">Breach Intelligence Search</h3>
          <p class="text-sm text-gray-500">Searches Have I Been Pwned, BreachDirectory, and paste sites for leaked university data</p>
        </div>
      </div>

      <!-- Target Selection -->
      <div class="mb-4">
        <div class="flex items-center justify-between mb-2">
          <label class="text-sm font-medium text-gray-700">Select targets to scan:</label>
          <button @click="toggleSelectAll" class="text-xs text-indigo-600 hover:text-indigo-800">
            {{ selectedTargets.length === targets.length ? 'Deselect All' : 'Select All (' + targets.length + ')' }}
          </button>
        </div>
        <div class="border border-gray-200 rounded-lg p-3 max-h-48 overflow-y-auto">
          <label v-for="t in targets" :key="t.ID" class="flex items-center gap-2 py-1 hover:bg-gray-50 px-1 rounded">
            <input type="checkbox" v-model="selectedTargets" :value="t.ID" class="rounded text-indigo-600" />
            <span class="text-sm">{{ t.name || t.url }}</span>
            <span class="text-xs text-gray-400" dir="ltr">{{ t.url }}</span>
          </label>
        </div>
      </div>

      <button @click="startScan" :disabled="scanning"
        class="px-6 py-2.5 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors flex items-center gap-2 text-sm font-medium">
        <div v-if="scanning" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
        <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
        </svg>
        {{ scanning ? 'Scanning breaches...' : 'Start Data Leak Scan' }}
      </button>

      <p v-if="scanning" class="text-xs text-gray-500 mt-2">This may take several minutes due to API rate limits (1.5s per email check)</p>
    </div>

    <!-- Summary Stats -->
    <div v-if="results && results.total_scanned > 0" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-5 text-center">
        <p class="text-3xl font-bold text-indigo-700">{{ results.total_scanned }}</p>
        <p class="text-sm text-gray-500">Domains Scanned</p>
      </div>
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-5 text-center">
        <p class="text-3xl font-bold text-green-700">{{ results.completed }}</p>
        <p class="text-sm text-gray-500">Completed</p>
      </div>
      <div class="bg-white rounded-xl shadow-sm border border-red-200 p-5 text-center">
        <p class="text-3xl font-bold text-red-700">{{ results.total_breaches }}</p>
        <p class="text-sm text-gray-500">Breaches Found</p>
      </div>
      <div class="bg-white rounded-xl shadow-sm border border-orange-200 p-5 text-center">
        <p class="text-3xl font-bold text-orange-700">{{ results.total_exposed }}</p>
        <p class="text-sm text-gray-500">Emails Exposed</p>
      </div>
    </div>

    <!-- Results per domain -->
    <div v-if="results?.results?.length" class="space-y-4">
      <div v-for="r in results.results" :key="r.domain"
        class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">

        <!-- Domain Header -->
        <div class="p-5 flex items-center justify-between" :class="r.status === 'running' ? 'bg-blue-50' : ''">
          <div class="flex items-center gap-3">
            <div v-if="r.status === 'running'" class="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
            <div v-else-if="r.summary?.risk_level === 'safe'" class="w-5 h-5 bg-green-500 rounded-full flex items-center justify-center">
              <svg class="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/></svg>
            </div>
            <div v-else class="w-5 h-5 bg-red-500 rounded-full flex items-center justify-center">
              <svg class="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M12 9v2m0 4h.01"/></svg>
            </div>
            <div>
              <h3 class="font-semibold text-gray-900">{{ r.name || r.domain }}</h3>
              <p class="text-xs text-gray-400" dir="ltr">{{ r.domain }}</p>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span v-if="r.status === 'running'" class="px-3 py-1 bg-blue-100 text-blue-700 rounded-full text-xs font-medium animate-pulse">Scanning...</span>
            <span v-else-if="r.summary" :class="[getRiskColor(r.summary.risk_level), 'px-3 py-1 rounded-full text-xs font-bold border']">
              {{ getRiskLabel(r.summary.risk_level) }}
            </span>
          </div>
        </div>

        <!-- Check Results -->
        <div v-if="r.status === 'completed' && r.checks?.length" class="border-t border-gray-100">
          <div v-for="check in r.checks" :key="check.check_name" class="p-4 border-b border-gray-50 last:border-0">
            <div class="flex items-center justify-between mb-2">
              <div class="flex items-center gap-2">
                <span :class="[
                  'px-2 py-0.5 rounded text-xs font-medium',
                  check.status === 'fail' ? 'bg-red-100 text-red-700' :
                  check.status === 'warn' ? 'bg-yellow-100 text-yellow-700' :
                  'bg-green-100 text-green-700'
                ]">{{ check.status }}</span>
                <span class="font-medium text-gray-800 text-sm">{{ check.check_name }}</span>
              </div>
              <span :class="[check.score >= 800 ? 'text-green-600' : check.score >= 500 ? 'text-yellow-600' : 'text-red-600', 'font-bold text-sm']">
                {{ Math.round(check.score) }}/1000
              </span>
            </div>

            <!-- Details -->
            <div v-if="check.details" class="bg-gray-50 rounded-lg p-3 text-sm">
              <p class="text-gray-700 mb-2">{{ parseDetails(check.details).message }}</p>

              <!-- Breaches list -->
              <div v-if="parseDetails(check.details).breaches?.length" class="space-y-2 mb-2">
                <div v-for="(b, idx) in parseDetails(check.details).breaches" :key="idx"
                  class="bg-white border border-red-100 rounded p-2">
                  <div class="flex items-center justify-between">
                    <span class="font-medium text-red-800 text-xs">{{ b.name || b.title }}</span>
                    <span class="text-xs text-gray-500">{{ b.date }}</span>
                  </div>
                  <p v-if="b.records" class="text-xs text-gray-600">{{ b.records?.toLocaleString() }} records</p>
                  <div v-if="b.data_classes?.length" class="flex flex-wrap gap-1 mt-1">
                    <span v-for="dc in b.data_classes" :key="dc" class="px-1.5 py-0.5 bg-red-50 text-red-600 rounded text-[10px]">{{ dc }}</span>
                  </div>
                </div>
              </div>

              <!-- Exposed emails -->
              <div v-if="parseDetails(check.details).exposed_emails?.length" class="space-y-2 mb-2">
                <div v-for="(e, idx) in parseDetails(check.details).exposed_emails" :key="idx"
                  class="bg-white border border-orange-100 rounded p-2">
                  <p class="font-mono text-xs text-orange-800" dir="ltr">{{ e.email }}</p>
                  <p class="text-xs text-gray-500">Found in {{ e.breach_count }} breach(es)</p>
                  <div v-if="e.data_leaked?.length" class="flex flex-wrap gap-1 mt-1">
                    <span v-for="d in e.data_leaked" :key="d" class="px-1.5 py-0.5 bg-orange-50 text-orange-600 rounded text-[10px]">{{ d }}</span>
                  </div>
                </div>
              </div>

              <!-- Data types leaked -->
              <div v-if="parseDetails(check.details).data_types_leaked?.length" class="mt-2">
                <p class="text-xs text-gray-500 mb-1">Data types leaked:</p>
                <div class="flex flex-wrap gap-1">
                  <span v-for="dt in parseDetails(check.details).data_types_leaked" :key="dt"
                    class="px-2 py-0.5 bg-red-100 text-red-700 rounded text-xs font-medium">{{ dt }}</span>
                </div>
              </div>

              <!-- Recommendation -->
              <div v-if="parseDetails(check.details).recommendation" class="mt-2 p-2 bg-green-50 border border-green-100 rounded">
                <p class="text-xs text-green-800 whitespace-pre-line">{{ parseDetails(check.details).recommendation }}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Empty State -->
    <div v-else-if="!loading && (!results || !results.total_scanned)" class="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
      <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
      </svg>
      <p class="text-lg text-gray-500">No data leak scans yet</p>
      <p class="text-sm text-gray-400 mt-1">Select targets above and start a breach scan</p>
    </div>
  </div>
</template>
