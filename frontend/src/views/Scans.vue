<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import { getScanJobs, getTargets, startScan, cancelScan, deleteScanJob } from '../api'

const router = useRouter()
const jobs = ref([])
const targets = ref([])
const loading = ref(true)
const showStartForm = ref(false)
const scanning = ref(false)
const scanPage = ref(1)
const scanTotalPages = ref(1)
const statusFilter = ref('')

const wsConnection = ref(null)
const targetProgress = ref({})
const totalTargetCount = ref(0)
let wsRetryCount = 0
let wsRetryTimer = null
let pendingTimers = []

const scanForm = ref({
  name: '',
  target_ids: [],
  selectAll: true,
  policy: 'standard',
})

async function loadData() {
  loading.value = true
  try {
    const [jobsRes, targetsRes] = await Promise.all([
      getScanJobs({ page: scanPage.value, limit: 20, status: statusFilter.value || undefined }),
      getTargets({ limit: 1000 })
    ])
    jobs.value = jobsRes.data.data || jobsRes.data
    scanTotalPages.value = jobsRes.data.pages || 1
    const tData = targetsRes.data
    targets.value = Array.isArray(tData) ? tData : (tData.data || [])
    totalTargetCount.value = targetsRes.data.total || targets.value.length
  } catch (e) {
    console.error('Failed to load data:', e)
  } finally {
    loading.value = false
  }
}

const scanError = ref('')

async function runScan() {
  scanning.value = true
  scanError.value = ''
  try {
    const payload = {
      name: scanForm.value.name,
      target_ids: scanForm.value.selectAll ? [] : scanForm.value.target_ids,
      policy: scanForm.value.policy,
    }
    await startScan(payload)
    showStartForm.value = false
    scanForm.value = { name: '', target_ids: [], selectAll: true, policy: 'standard' }
    await loadData()
  } catch (e) {
    if (e.response?.status === 403 && e.response?.data?.unverified_domains) {
      const domains = e.response.data.unverified_domains.join(', ')
      scanError.value = `يجب التحقق من ملكية النطاقات التالية قبل الفحص: ${domains}. اذهب إلى صفحة المواقع لإتمام التحقق.`
    } else if (e.response?.data?.error) {
      scanError.value = e.response.data.error
    } else {
      scanError.value = 'Failed to start scan. Please try again.'
    }
  } finally {
    scanning.value = false
  }
}

function connectWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const token = localStorage.getItem('token')
  const wsUrl = `${protocol}//${window.location.host}/ws/scan?token=${token}`
  wsConnection.value = new WebSocket(wsUrl)

  wsConnection.value.onopen = () => {
    wsRetryCount = 0 // Reset on successful connection
  }

  wsConnection.value.onmessage = (event) => {
    const progress = JSON.parse(event.data)

    if (progress.type === 'target') {
      targetProgress.value[progress.target_id] = progress
      if (progress.status === 'completed') {
        const tid = progress.target_id
        const t = setTimeout(() => {
          delete targetProgress.value[tid]
        }, 3000)
        pendingTimers.push(t)
      }
    } else {
      const jobIndex = jobs.value.findIndex(j => j.ID === progress.job_id)
      if (jobIndex !== -1) {
        jobs.value[jobIndex].status = progress.status
        jobs.value[jobIndex].progress = {
          total: progress.total,
          completed: progress.completed,
          percent: progress.percent,
          running: 0,
          pending: progress.total - progress.completed,
          failed: 0,
        }
      }
      if (progress.status === 'completed' || progress.status === 'failed' || progress.status === 'cancelled') {
        targetProgress.value = {}
        loadData()
      }
    }
  }

  // Exponential backoff: 1s, 2s, 4s, 8s, ... max 30s
  wsConnection.value.onclose = () => {
    const delay = Math.min(1000 * Math.pow(2, wsRetryCount), 30000)
    wsRetryCount++
    wsRetryTimer = setTimeout(connectWebSocket, delay)
  }
}

onBeforeUnmount(() => {
  // Clear reconnection timer
  if (wsRetryTimer) clearTimeout(wsRetryTimer)
  // Clear all pending cleanup timers
  pendingTimers.forEach(t => clearTimeout(t))
  pendingTimers = []
  // Close WebSocket
  if (wsConnection.value) {
    wsConnection.value.onclose = null
    wsConnection.value.close()
  }
})

async function cancelJob(id) {
  if (!confirm('Cancel this running scan?')) return
  try {
    await cancelScan(id)
    await loadData()
  } catch (e) {
    alert(e.response?.data?.error || 'Failed to cancel scan')
  }
}

async function removeJob(id) {
  if (!confirm('Delete this scan job and all its results?')) return
  try {
    await deleteScanJob(id)
    await loadData()
  } catch (e) {
    console.error('Failed to delete job:', e)
  }
}

function targetProgressForJob(jobId) {
  const result = {}
  for (const [tid, tp] of Object.entries(targetProgress.value)) {
    if (tp.job_id === jobId) {
      result[tid] = tp
    }
  }
  return result
}

function formatDate(dateStr) {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleString('en-GB', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

onMounted(() => {
  loadData()
  connectWebSocket()
})
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">Scans</h1>
        <p class="text-gray-500 mt-1">Manage and run security scans</p>
      </div>
      <div class="flex items-center gap-3">
        <!-- Status Filter -->
        <select v-model="statusFilter" @change="scanPage = 1; loadData()" class="text-sm border border-gray-300 rounded-lg px-3 py-2 bg-white">
          <option value="">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="cancelled">Cancelled</option>
          <option value="failed">Failed</option>
        </select>
      </div>
      <button
        v-if="targets.length > 0"
        @click="showStartForm = !showStartForm"
        class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors flex items-center gap-2"
      >
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        Start New Scan
      </button>
    </div>

    <!-- Error Message -->
    <div v-if="scanError" class="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4 mb-6 flex items-start gap-3">
      <svg class="w-5 h-5 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.999L13.732 4.001c-.77-1.333-2.694-1.333-3.464 0L3.34 16.001c-.77 1.332.192 2.999 1.732 2.999z"/>
      </svg>
      <div>
        <p>{{ scanError }}</p>
        <router-link v-if="scanError.includes('التحقق')" to="/targets" class="text-indigo-600 hover:underline text-sm mt-1 inline-block">
          الذهاب إلى صفحة المواقع
        </router-link>
      </div>
      <button @click="scanError = ''" class="mr-auto text-red-400 hover:text-red-600">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>

    <!-- No Targets Warning -->
    <div v-if="!loading && targets.length === 0" class="bg-yellow-50 border border-yellow-200 rounded-xl p-8 mb-6 text-center">
      <svg class="w-12 h-12 mx-auto text-yellow-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.999L13.732 4.001c-.77-1.333-2.694-1.333-3.464 0L3.34 16.001c-.77 1.332.192 2.999 1.732 2.999z"/>
      </svg>
      <h3 class="text-lg font-semibold text-gray-900 mb-2">No websites added yet</h3>
      <p class="text-gray-600 mb-4">You need to add websites and verify domain ownership before you can start scanning.</p>
      <router-link to="/targets" class="inline-flex items-center gap-2 px-6 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
        </svg>
        Add Your Websites
      </router-link>
    </div>

    <!-- Start Scan Form -->
    <div v-if="showStartForm" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-900 mb-4">Configure Scan</h3>
      <form @submit.prevent="runScan">
        <div class="mb-4">
          <label class="block text-sm text-gray-600 mb-1">Scan Name (optional)</label>
          <input
            v-model="scanForm.name"
            type="text"
            placeholder="e.g., March 2026 Assessment"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>

        <div class="mb-4">
          <label class="flex items-center gap-2 mb-3">
            <input v-model="scanForm.selectAll" type="checkbox" class="rounded text-indigo-600" />
            <span class="text-sm text-gray-700">Scan all targets ({{ totalTargetCount }} websites)</span>
          </label>

          <div v-if="!scanForm.selectAll" class="border border-gray-200 rounded-lg p-3 max-h-60 overflow-y-auto">
            <label v-for="target in targets" :key="target.ID" class="flex items-center gap-2 py-1">
              <input v-model="scanForm.target_ids" :value="target.ID" type="checkbox" class="rounded text-indigo-600" />
              <span class="text-sm">{{ target.name || target.url }}</span>
              <span class="text-xs text-gray-400">{{ target.url }}</span>
            </label>
          </div>
        </div>

        <!-- Scan Policy Selector -->
        <div class="mb-6">
          <label class="block text-sm font-medium text-gray-700 mb-3">Scan Policy</label>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
            <!-- Light -->
            <label
              :class="[
                'relative flex flex-col p-4 rounded-xl border-2 cursor-pointer transition-all',
                scanForm.policy === 'light'
                  ? 'border-yellow-500 bg-yellow-50 shadow-md'
                  : 'border-gray-200 bg-white hover:border-yellow-300 hover:bg-yellow-50/50'
              ]"
            >
              <input v-model="scanForm.policy" type="radio" value="light" class="sr-only" />
              <div class="flex items-center gap-2 mb-2">
                <svg class="w-5 h-5 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                </svg>
                <span class="font-semibold text-gray-900">Light</span>
              </div>
              <p class="text-xs text-gray-500 mb-1">8 categories, ~30s per site</p>
              <p class="text-xs text-gray-400">Quick security check for basic issues</p>
              <div v-if="scanForm.policy === 'light'" class="absolute top-2 right-2">
                <svg class="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
              </div>
            </label>

            <!-- Standard -->
            <label
              :class="[
                'relative flex flex-col p-4 rounded-xl border-2 cursor-pointer transition-all',
                scanForm.policy === 'standard'
                  ? 'border-indigo-500 bg-indigo-50 shadow-md'
                  : 'border-gray-200 bg-white hover:border-indigo-300 hover:bg-indigo-50/50'
              ]"
            >
              <input v-model="scanForm.policy" type="radio" value="standard" class="sr-only" />
              <div class="flex items-center gap-2 mb-2">
                <svg class="w-5 h-5 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                <span class="font-semibold text-gray-900">Standard</span>
                <span class="text-xs bg-indigo-100 text-indigo-700 px-1.5 py-0.5 rounded-full font-medium">Recommended</span>
              </div>
              <p class="text-xs text-gray-500 mb-1">16 categories, ~60s per site</p>
              <p class="text-xs text-gray-400">Comprehensive security audit</p>
              <div v-if="scanForm.policy === 'standard'" class="absolute top-2 right-2">
                <svg class="w-5 h-5 text-indigo-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
              </div>
            </label>

            <!-- Deep -->
            <label
              :class="[
                'relative flex flex-col p-4 rounded-xl border-2 cursor-pointer transition-all',
                scanForm.policy === 'deep'
                  ? 'border-red-500 bg-red-50 shadow-md'
                  : 'border-gray-200 bg-white hover:border-red-300 hover:bg-red-50/50'
              ]"
            >
              <input v-model="scanForm.policy" type="radio" value="deep" class="sr-only" />
              <div class="flex items-center gap-2 mb-2">
                <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
                </svg>
                <span class="font-semibold text-gray-900">Deep</span>
              </div>
              <p class="text-xs text-gray-500 mb-1">All categories, ~2min per site</p>
              <p class="text-xs text-gray-400">Full assessment incl. XSS, malware, secrets</p>
              <div v-if="scanForm.policy === 'deep'" class="absolute top-2 right-2">
                <svg class="w-5 h-5 text-red-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
              </div>
            </label>
          </div>
        </div>

        <button
          type="submit"
          :disabled="scanning || targets.length === 0"
          class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
        >
          <div v-if="scanning" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
          {{ scanning ? 'Starting...' : 'Start Scan' }}
        </button>
      </form>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <!-- Scan Jobs List -->
    <div v-else class="space-y-4">
      <div v-for="job in jobs" :key="job.ID" class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <!-- Progress bar at top for running scans -->
        <div v-if="job.status === 'running' && job.progress" class="h-1.5 bg-gray-100">
          <div
            class="h-full bg-gradient-to-r from-indigo-500 to-blue-500 transition-all duration-700 ease-out"
            :style="{ width: Math.round(job.progress.percent) + '%' }"
          ></div>
        </div>
        <div v-else-if="job.status === 'completed'" class="h-1.5 bg-green-500"></div>
        <div v-else-if="job.status === 'failed'" class="h-1.5 bg-red-500"></div>

        <div class="p-6">
          <div class="flex items-start justify-between gap-4">
            <div class="flex-1">
              <h3 class="text-lg font-semibold text-gray-900">{{ job.name || 'Unnamed Scan' }}</h3>
              <p class="text-sm text-gray-500 mt-1">Created: {{ formatDate(job.CreatedAt) }}</p>
              <div class="flex items-center gap-4 mt-1 text-sm text-gray-500">
                <span v-if="job.started_at">Started: {{ formatDate(job.started_at) }}</span>
                <span v-if="job.ended_at">Ended: {{ formatDate(job.ended_at) }}</span>
              </div>
            </div>
            <div class="flex items-center gap-3 flex-shrink-0">
              <span :class="[
                'px-3 py-1 rounded-full text-sm font-medium',
                job.status === 'completed' ? 'bg-green-100 text-green-700' :
                job.status === 'running' ? 'bg-blue-100 text-blue-700' :
                job.status === 'failed' ? 'bg-red-100 text-red-700' :
                'bg-gray-100 text-gray-700'
              ]">
                {{ job.status === 'running' ? 'Scanning...' : job.status }}
              </span>
              <button
                @click="router.push(`/scans/${job.ID}`)"
                class="px-3 py-1 text-sm text-indigo-600 border border-indigo-300 rounded-lg hover:bg-indigo-50"
              >
                View Details
              </button>
              <button v-if="job.status === 'running'"
                @click="cancelJob(job.ID)"
                class="px-3 py-1 text-sm text-orange-600 border border-orange-300 rounded-lg hover:bg-orange-50"
              >
                Cancel
              </button>
              <button
                @click="removeJob(job.ID)"
                class="px-3 py-1 text-sm text-red-500 border border-red-300 rounded-lg hover:bg-red-50"
              >
                Delete
              </button>
            </div>
          </div>

          <!-- Progress Section for running/completed scans -->
          <div v-if="job.progress && job.progress.total > 0" class="mt-4">
            <!-- Progress bar -->
            <div v-if="job.status === 'running'" class="mb-3">
              <div class="flex items-center justify-between mb-1.5">
                <span class="text-sm font-medium text-gray-700">
                  Scanning {{ job.progress.total }} websites...
                </span>
                <span class="text-sm font-bold text-indigo-600">{{ Math.round(job.progress.percent) }}%</span>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
                <div
                  class="h-full rounded-full bg-gradient-to-r from-indigo-500 via-blue-500 to-indigo-600 transition-all duration-700 ease-out relative"
                  :style="{ width: Math.round(job.progress.percent) + '%' }"
                >
                  <div class="absolute inset-0 bg-white/20 animate-pulse"></div>
                </div>
              </div>
            </div>

            <!-- Per-Target Sub-Progress -->
            <div v-if="job.status === 'running' && Object.keys(targetProgressForJob(job.ID)).length > 0" class="mb-3 space-y-2">
              <p class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Live Scanner Progress</p>
              <div v-for="(tp, tid) in targetProgressForJob(job.ID)" :key="tid"
                class="bg-gray-50 border border-gray-200 rounded-lg p-3">
                <div class="flex items-center justify-between mb-1.5">
                  <div class="flex items-center gap-2 min-w-0">
                    <div v-if="tp.status === 'scanning'" class="w-2 h-2 rounded-full bg-blue-500 animate-pulse flex-shrink-0"></div>
                    <div v-else class="w-2 h-2 rounded-full bg-green-500 flex-shrink-0"></div>
                    <span class="text-sm font-medium text-gray-800 truncate">{{ tp.target_url }}</span>
                  </div>
                  <span class="text-xs font-mono text-gray-500 flex-shrink-0">{{ tp.scanner_index }}/{{ tp.total_scanners }}</span>
                </div>
                <div class="w-full bg-gray-200 rounded-full h-1.5 mb-1">
                  <div class="h-full rounded-full transition-all duration-500"
                    :class="tp.status === 'completed' ? 'bg-green-500' : 'bg-blue-500'"
                    :style="{ width: Math.round(tp.target_percent) + '%' }"></div>
                </div>
                <p class="text-xs text-gray-500">
                  <span v-if="tp.status === 'scanning'" class="text-blue-600 font-medium">{{ tp.scanner_name }}</span>
                  <span v-else class="text-green-600 font-medium">{{ tp.message }}</span>
                </p>
              </div>
            </div>

            <!-- Stats badges -->
            <div class="flex flex-wrap items-center gap-2">
              <span v-if="job.progress.completed > 0"
                class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-green-100 text-green-700">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                {{ job.progress.completed }} completed
              </span>
              <span v-if="job.progress.running > 0"
                class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-700 animate-pulse">
                <div class="w-2 h-2 rounded-full bg-blue-500"></div>
                {{ job.progress.running }} scanning
              </span>
              <span v-if="job.progress.pending > 0"
                class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                <div class="w-2 h-2 rounded-full bg-gray-400"></div>
                {{ job.progress.pending }} pending
              </span>
              <span v-if="job.progress.failed > 0"
                class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-100 text-red-700">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                {{ job.progress.failed }} failed
              </span>
              <span class="text-xs text-gray-400 mr-2">
                {{ job.progress.completed + (job.progress.failed || 0) }} / {{ job.progress.total }} sites
              </span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="!jobs.length" class="text-center py-16 bg-white rounded-xl shadow-sm border border-gray-200">
        <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
        </svg>
        <p class="text-lg text-gray-400">No scans yet</p>
        <p class="text-sm text-gray-400 mt-1">Start a new scan to check your targets</p>
      </div>

      <!-- Pagination -->
      <div v-if="scanTotalPages > 1" class="flex items-center justify-between mt-4">
        <p class="text-sm text-gray-500">Page {{ scanPage }} of {{ scanTotalPages }}</p>
        <div class="flex gap-2">
          <button @click="scanPage--; loadData()" :disabled="scanPage <= 1"
            class="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed">Previous</button>
          <button @click="scanPage++; loadData()" :disabled="scanPage >= scanTotalPages"
            class="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed">Next</button>
        </div>
      </div>
    </div>
  </div>
</template>
