<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import { getScanJobs, getTargets, startScan, deleteScanJob } from '../api'

const router = useRouter()
const jobs = ref([])
const targets = ref([])
const loading = ref(true)
const showStartForm = ref(false)
const scanning = ref(false)

const pollInterval = ref(null)

const scanForm = ref({
  name: '',
  target_ids: [],
  selectAll: true,
})

async function loadData() {
  loading.value = true
  try {
    const [jobsRes, targetsRes] = await Promise.all([getScanJobs(), getTargets()])
    jobs.value = jobsRes.data
    targets.value = targetsRes.data
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
    }
    const { data } = await startScan(payload)
    showStartForm.value = false
    scanForm.value = { name: '', target_ids: [], selectAll: true }
    await loadData()
    pollJob(data.ID)
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

function pollJob(jobId) {
  pollInterval.value = setInterval(async () => {
    try {
      await loadData()
      const job = jobs.value.find(j => j.ID === jobId)
      if (job && (job.status === 'completed' || job.status === 'failed')) {
        clearInterval(pollInterval.value)
        pollInterval.value = null
      }
    } catch {
      clearInterval(pollInterval.value)
      pollInterval.value = null
    }
  }, 3000)
}

onBeforeUnmount(() => {
  if (pollInterval.value) {
    clearInterval(pollInterval.value)
  }
})

async function removeJob(id) {
  if (!confirm('Delete this scan job and all its results?')) return
  try {
    await deleteScanJob(id)
    await loadData()
  } catch (e) {
    console.error('Failed to delete job:', e)
  }
}

function formatDate(dateStr) {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleString('en-GB', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

onMounted(loadData)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">Scans</h1>
        <p class="text-gray-500 mt-1">Manage and run security scans</p>
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
            <span class="text-sm text-gray-700">Scan all targets ({{ targets.length }} websites)</span>
          </label>

          <div v-if="!scanForm.selectAll" class="border border-gray-200 rounded-lg p-3 max-h-60 overflow-y-auto">
            <label v-for="target in targets" :key="target.ID" class="flex items-center gap-2 py-1">
              <input v-model="scanForm.target_ids" :value="target.ID" type="checkbox" class="rounded text-indigo-600" />
              <span class="text-sm">{{ target.name || target.url }}</span>
              <span class="text-xs text-gray-400">{{ target.url }}</span>
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
    </div>
  </div>
</template>
