<script setup>
import { ref, computed, watch, nextTick, onUnmounted } from 'vue'
import { runNucleiTool, getNucleiRuns, getNucleiRun } from '../api'

const activeTab = ref('new')

// ---- form ----
const target = ref('')
const allSeverities = ['critical', 'high', 'medium', 'low', 'info']
const severities = ref(['critical', 'high', 'medium'])
const allTags = ['cve', 'default-login', 'exposure', 'misconfig', 'tech', 'ssl', 'xss', 'sqli', 'lfi', 'rce', 'takeover', 'wordpress', 'panel', 'config', 'backup', 'token']
const tags = ref([])
const starting = ref(false)
const error = ref('')

// ---- active / selected run ----
const run = ref(null)
const polling = ref(false)
const logBox = ref(null)
let pollTimer = null
let stopped = false

// ---- history ----
const runs = ref([])
const historyLoading = ref(false)

function toggleSeverity(s) {
  const i = severities.value.indexOf(s)
  i >= 0 ? severities.value.splice(i, 1) : severities.value.push(s)
}
function toggleTag(t) {
  const i = tags.value.indexOf(t)
  i >= 0 ? tags.value.splice(i, 1) : tags.value.push(t)
}

const sevClass = (s) =>
  ({
    critical: 'bg-red-100 text-red-700 border-red-200',
    high: 'bg-orange-100 text-orange-700 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    low: 'bg-blue-100 text-blue-700 border-blue-200',
    info: 'bg-gray-100 text-gray-600 border-gray-200',
  })[s] || 'bg-gray-100 text-gray-600 border-gray-200'

const statusClass = (s) =>
  ({ running: 'bg-blue-100 text-blue-700', finished: 'bg-green-100 text-green-700', failed: 'bg-red-100 text-red-700' })[s] ||
  'bg-gray-100 text-gray-600'

const findings = computed(() => {
  if (!run.value?.results_json) return []
  let arr = []
  try {
    arr = JSON.parse(run.value.results_json)
  } catch {
    return []
  }
  return arr.filter((r) => (r.check_name || '').startsWith('Nuclei:'))
})
function details(r) {
  try {
    return JSON.parse(r.details || '{}')
  } catch {
    return {}
  }
}

function fmtDur(s) {
  if (s == null) return '—'
  const m = Math.floor(s / 60)
  const ss = s % 60
  return m ? `${m}m ${ss}s` : `${ss}s`
}
function fmtDate(d) {
  if (!d) return ''
  try {
    return new Date(d).toLocaleString()
  } catch {
    return d
  }
}

async function scrollLog() {
  await nextTick()
  if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
}
watch(() => run.value?.log, scrollLog)

async function start() {
  const t = target.value.trim()
  if (!t) return
  starting.value = true
  error.value = ''
  try {
    const { data } = await runNucleiTool({ target: t, severity: severities.value.join(','), tags: tags.value.join(',') })
    run.value = { id: data.id, target: t, status: 'running', log: '', results_json: '' }
    stopped = false
    poll(data.id)
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to start scan.'
  } finally {
    starting.value = false
  }
}

function poll(id) {
  polling.value = true
  const tick = async () => {
    if (stopped) return
    try {
      const { data } = await getNucleiRun(id)
      run.value = data
      if (data.status === 'running') {
        pollTimer = setTimeout(tick, 2000)
      } else {
        polling.value = false
      }
    } catch {
      polling.value = false
    }
  }
  tick()
}

function newScan() {
  stopped = true
  if (pollTimer) clearTimeout(pollTimer)
  run.value = null
  polling.value = false
}

async function loadHistory() {
  historyLoading.value = true
  try {
    const { data } = await getNucleiRuns()
    runs.value = Array.isArray(data) ? data : []
  } catch {
    /* ignore */
  } finally {
    historyLoading.value = false
  }
}

async function openRun(id) {
  stopped = true
  if (pollTimer) clearTimeout(pollTimer)
  activeTab.value = 'new'
  try {
    const { data } = await getNucleiRun(id)
    run.value = data
    if (data.status === 'running') {
      stopped = false
      poll(id)
    }
  } catch {
    /* ignore */
  }
}

watch(activeTab, (t) => {
  if (t === 'history') loadHistory()
})
onUnmounted(() => {
  stopped = true
  if (pollTimer) clearTimeout(pollTimer)
})
</script>

<template>
  <div class="max-w-4xl mx-auto p-4 md:p-6">
    <div class="mb-4">
      <h1 class="text-2xl font-bold text-gray-900 flex items-center gap-2">
        <svg class="w-6 h-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
        Nuclei Scan
      </h1>
      <p class="text-sm text-gray-500 mt-1">
        Run nuclei against a single URL or IP. Scans run in the background — you can leave the page and check History later.
        Only scan systems you are authorized to test.
      </p>
    </div>

    <!-- Tabs -->
    <div class="flex gap-1 border-b border-gray-200 mb-5">
      <button
        @click="activeTab = 'new'"
        :class="['px-4 py-2 text-sm font-medium -mb-px border-b-2', activeTab === 'new' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-gray-500 hover:text-gray-700']"
      >
        New Scan
      </button>
      <button
        @click="activeTab = 'history'"
        :class="['px-4 py-2 text-sm font-medium -mb-px border-b-2', activeTab === 'history' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-gray-500 hover:text-gray-700']"
      >
        History
      </button>
    </div>

    <!-- ================= NEW SCAN ================= -->
    <div v-if="activeTab === 'new'">
      <!-- form -->
      <div class="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-6">
        <label class="block text-sm font-medium text-gray-700 mb-1">Target (URL or IP)</label>
        <div class="flex flex-col sm:flex-row gap-2">
          <input
            v-model="target"
            type="text"
            placeholder="https://example.com  or  185.65.62.222"
            class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
            @keyup.enter="start"
          />
          <button
            @click="start"
            :disabled="starting || !target.trim()"
            class="px-5 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 whitespace-nowrap"
          >
            {{ starting ? 'Starting…' : 'Start Scan' }}
          </button>
        </div>

        <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Severity</label>
            <div class="flex flex-wrap gap-1.5">
              <button
                v-for="s in allSeverities"
                :key="s"
                type="button"
                @click="toggleSeverity(s)"
                :class="['px-2.5 py-1 rounded-full text-xs border capitalize transition', severities.includes(s) ? sevClass(s) + ' font-semibold' : 'bg-gray-50 text-gray-400 border-gray-200']"
              >
                {{ s }}
              </button>
            </div>
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Tags (optional)</label>
            <div class="flex flex-wrap gap-1.5">
              <button
                v-for="tg in allTags"
                :key="tg"
                type="button"
                @click="toggleTag(tg)"
                :class="['px-2.5 py-1 rounded-full text-xs border transition', tags.includes(tg) ? 'bg-indigo-100 text-indigo-700 border-indigo-200 font-semibold' : 'bg-gray-50 text-gray-500 border-gray-200 hover:border-indigo-300']"
              >
                {{ tg }}
              </button>
            </div>
            <p class="text-[11px] text-gray-400 mt-1">No tags = all templates (can take several minutes).</p>
          </div>
        </div>
      </div>

      <div v-if="error" class="mb-6 rounded-lg bg-red-50 border border-red-200 text-red-700 px-4 py-3 text-sm">{{ error }}</div>

      <!-- live run / result -->
      <div v-if="run" class="space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span :class="['px-2 py-0.5 rounded-full text-xs font-medium capitalize', statusClass(run.status)]">
              <span v-if="run.status === 'running'" class="inline-block w-2 h-2 bg-blue-500 rounded-full animate-pulse mr-1"></span>{{ run.status }}
            </span>
            <span class="text-sm text-gray-600 break-all">{{ run.target }}</span>
          </div>
          <div class="flex items-center gap-3 text-sm text-gray-500">
            <span v-if="run.duration_sec">⏱ {{ fmtDur(run.duration_sec) }}</span>
            <span>{{ findings.length }} finding(s)</span>
            <button @click="newScan" class="text-indigo-600 hover:underline">New scan</button>
          </div>
        </div>

        <!-- detailed live log -->
        <div>
          <p class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Scan log</p>
          <pre
            ref="logBox"
            class="text-[12px] leading-relaxed bg-slate-900 text-slate-100 rounded-lg p-3 overflow-auto max-h-96 whitespace-pre-wrap break-words"
          >{{ run.log || 'starting…' }}</pre>
        </div>

        <!-- structured findings (when finished) -->
        <div v-if="findings.length" class="space-y-2">
          <p class="text-xs font-semibold text-gray-500 uppercase tracking-wide">Findings</p>
          <div v-for="(f, i) in findings" :key="i" class="bg-white rounded-lg border border-gray-200 p-3 shadow-sm">
            <div class="flex items-start justify-between gap-3">
              <p class="font-medium text-gray-900">{{ f.check_name.replace(/^Nuclei:\s*/, '') }}</p>
              <span :class="['px-2 py-0.5 rounded-full text-xs border capitalize flex-shrink-0', sevClass(f.severity)]">{{ f.severity }}</span>
            </div>
            <div class="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-400">
              <span v-if="details(f).template_id">template: <code class="text-gray-600">{{ details(f).template_id }}</code></span>
              <span v-if="details(f).matched_at" class="break-all">matched: <code class="text-gray-600">{{ details(f).matched_at }}</code></span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ================= HISTORY ================= -->
    <div v-else>
      <div v-if="historyLoading" class="text-sm text-gray-400 py-8 text-center">Loading…</div>
      <div v-else-if="runs.length === 0" class="text-sm text-gray-400 py-8 text-center">No scans yet.</div>
      <div v-else class="overflow-x-auto bg-white rounded-xl border border-gray-200 shadow-sm">
        <table class="min-w-full text-sm">
          <thead class="bg-gray-50 text-gray-500 text-xs uppercase tracking-wide">
            <tr>
              <th class="text-left px-4 py-2.5">Target</th>
              <th class="text-left px-4 py-2.5">When</th>
              <th class="text-left px-4 py-2.5">Duration</th>
              <th class="text-left px-4 py-2.5">Findings</th>
              <th class="text-left px-4 py-2.5">Status</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <tr v-for="r in runs" :key="r.id" @click="openRun(r.id)" class="hover:bg-indigo-50/50 cursor-pointer">
              <td class="px-4 py-2.5 text-gray-800 break-all max-w-[220px]">{{ r.target }}</td>
              <td class="px-4 py-2.5 text-gray-500 whitespace-nowrap">{{ fmtDate(r.created_at) }}</td>
              <td class="px-4 py-2.5 text-gray-700 whitespace-nowrap">{{ fmtDur(r.duration_sec) }}</td>
              <td class="px-4 py-2.5 text-gray-700">{{ r.findings }}</td>
              <td class="px-4 py-2.5">
                <span :class="['px-2 py-0.5 rounded-full text-xs font-medium capitalize', statusClass(r.status)]">{{ r.status }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="text-[11px] text-gray-400 mt-2">Click a row to open its detailed log and findings.</p>
    </div>
  </div>
</template>
