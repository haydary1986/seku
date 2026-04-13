<script setup>
import { ref, onMounted, onBeforeUnmount, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getScanJob } from '../api'
import { Bar } from 'vue-chartjs'
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

const route = useRoute()
const router = useRouter()
const job = ref(null)
const loading = ref(true)
const wsConnection = ref(null)
const targetProgress = ref({}) // live per-target scanner progress
let wsRetryCount = 0
let wsRetryTimer = null
let pendingTimers = []

const chartData = computed(() => {
  if (!job.value?.results) return { labels: [], datasets: [] }
  const completed = job.value.results.filter(r => r.status === 'completed')
  return {
    labels: completed.map(r => r.scan_target?.name || r.scan_target?.url || 'Unknown'),
    datasets: [{
      label: 'Security Score',
      data: completed.map(r => Math.round(r.overall_score)),
      backgroundColor: completed.map(r => {
        if (r.overall_score >= 800) return '#10b981'
        if (r.overall_score >= 600) return '#3b82f6'
        if (r.overall_score >= 400) return '#f59e0b'
        if (r.overall_score >= 200) return '#f97316'
        return '#ef4444'
      }),
      borderRadius: 6,
    }],
  }
})

const chartOptions = {
  responsive: true,
  indexAxis: 'y',
  scales: {
    x: { min: 0, max: 1000, title: { display: true, text: 'Score (/1000)' } },
  },
  plugins: { legend: { display: false } },
}

function getScoreColor(score) {
  if (score >= 800) return 'text-green-600'
  if (score >= 600) return 'text-blue-600'
  if (score >= 400) return 'text-yellow-600'
  if (score >= 200) return 'text-orange-600'
  return 'text-red-600'
}

function getScoreBg(score) {
  if (score >= 800) return 'bg-green-100'
  if (score >= 600) return 'bg-blue-100'
  if (score >= 400) return 'bg-yellow-100'
  if (score >= 200) return 'bg-orange-100'
  return 'bg-red-100'
}

function connectWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const token = localStorage.getItem('token')
  const wsUrl = `${protocol}//${window.location.host}/ws/scan?token=${token}`
  wsConnection.value = new WebSocket(wsUrl)

  wsConnection.value.onopen = () => { wsRetryCount = 0 }

  wsConnection.value.onmessage = (event) => {
    const progress = JSON.parse(event.data)
    if (progress.type === 'target' && progress.job_id === job.value?.ID) {
      targetProgress.value[progress.target_id] = progress
      if (progress.status === 'completed') {
        const tid = progress.target_id
        const t = setTimeout(() => { delete targetProgress.value[tid] }, 3000)
        pendingTimers.push(t)
      }
    } else if (progress.type === 'job' && progress.job_id === job.value?.ID) {
      if (progress.status === 'completed' || progress.status === 'failed' || progress.status === 'cancelled') {
        targetProgress.value = {}
        getScanJob(route.params.id).then(res => { job.value = res.data })
      }
    }
  }

  wsConnection.value.onclose = () => {
    const delay = Math.min(1000 * Math.pow(2, wsRetryCount), 30000)
    wsRetryCount++
    wsRetryTimer = setTimeout(connectWebSocket, delay)
  }
}

onBeforeUnmount(() => {
  if (wsRetryTimer) clearTimeout(wsRetryTimer)
  pendingTimers.forEach(t => clearTimeout(t))
  pendingTimers = []
  if (wsConnection.value) {
    wsConnection.value.onclose = null
    wsConnection.value.close()
  }
})

onMounted(async () => {
  try {
    const { data } = await getScanJob(route.params.id)
    job.value = data
    if (data.status === 'running') {
      connectWebSocket()
    }
  } catch (e) {
    console.error('Failed to load scan job:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <button @click="router.push('/scans')" class="text-indigo-600 hover:text-indigo-800 mb-4 flex items-center gap-1">
      <svg class="w-4 h-4 rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
      </svg>
      Back to Scans
    </button>

    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else-if="job">
      <div class="mb-8">
        <h1 class="text-3xl font-bold text-gray-900">{{ job.name || 'Scan Details' }}</h1>
        <div class="flex items-center gap-3 mt-2">
          <span :class="[
            'px-3 py-1 rounded-full text-sm font-medium',
            job.status === 'completed' ? 'bg-green-100 text-green-700' :
            job.status === 'running' ? 'bg-blue-100 text-blue-700 animate-pulse' :
            job.status === 'failed' ? 'bg-red-100 text-red-700' :
            'bg-gray-100 text-gray-700'
          ]">
            {{ job.status }}
          </span>
          <span class="text-sm text-gray-500">{{ job.results?.length || 0 }} websites scanned</span>
        </div>
      </div>

      <!-- Comparison Chart -->
      <div v-if="chartData.labels.length" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Score Comparison</h3>
        <Bar :data="chartData" :options="chartOptions" />
      </div>

      <!-- Results Table -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50">
            <tr>
              <th class="text-right py-3 px-4 text-gray-600 font-medium">#</th>
              <th class="text-right py-3 px-4 text-gray-600 font-medium">Website</th>
              <th class="text-center py-3 px-4 text-gray-600 font-medium">Score</th>
              <th class="text-center py-3 px-4 text-gray-600 font-medium">Status</th>
              <th class="text-center py-3 px-4 text-gray-600 font-medium">Details</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(result, i) in job.results" :key="result.ID" class="border-t border-gray-100 hover:bg-gray-50">
              <td class="py-4 px-4 text-gray-400">{{ i + 1 }}</td>
              <td class="py-4 px-4">
                <div class="font-medium text-gray-900">{{ result.scan_target?.name || 'N/A' }}</div>
                <div class="text-xs text-gray-400">{{ result.scan_target?.url }}</div>
              </td>
              <td class="py-4 px-4 text-center">
                <div :class="['inline-flex items-center justify-center w-14 h-14 rounded-full font-bold text-lg', getScoreBg(result.overall_score), getScoreColor(result.overall_score)]">
                  {{ Math.round(result.overall_score) }}
                </div>
              </td>
              <td class="py-4 px-4 text-center">
                <span :class="[
                  'px-2 py-1 rounded-full text-xs font-medium',
                  result.status === 'completed' ? 'bg-green-100 text-green-700' :
                  result.status === 'running' ? 'bg-blue-100 text-blue-700 animate-pulse' :
                  result.status === 'failed' ? 'bg-red-100 text-red-700' :
                  'bg-gray-100 text-gray-700'
                ]">
                  {{ result.status }}
                </span>
                <!-- Live sub-progress for running targets -->
                <div v-if="targetProgress[result.scan_target_id]" class="mt-2 text-right">
                  <div class="w-full bg-gray-200 rounded-full h-1.5 mb-1">
                    <div class="h-full rounded-full bg-blue-500 transition-all duration-500"
                      :style="{ width: Math.round(targetProgress[result.scan_target_id].target_percent) + '%' }"></div>
                  </div>
                  <p class="text-[11px] text-blue-600 font-medium truncate">
                    {{ targetProgress[result.scan_target_id].scanner_name }}
                    <span class="text-gray-400">({{ targetProgress[result.scan_target_id].scanner_index }}/{{ targetProgress[result.scan_target_id].total_scanners }})</span>
                  </p>
                </div>
              </td>
              <td class="py-4 px-4 text-center">
                <button
                  @click="router.push(`/results/${result.ID}`)"
                  class="px-3 py-1 text-sm text-indigo-600 border border-indigo-300 rounded-lg hover:bg-indigo-50"
                >
                  View Report
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>
