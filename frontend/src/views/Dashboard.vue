<script setup>
import { ref, onMounted } from 'vue'
import { getDashboardStats } from '../api'
import { Doughnut, Bar } from 'vue-chartjs'
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js'

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement)

const stats = ref(null)
const loading = ref(true)

const scoreChartData = ref({ labels: [], datasets: [] })
const scoreChartOptions = {
  responsive: true,
  plugins: { legend: { position: 'bottom' } },
}

onMounted(async () => {
  try {
    const { data } = await getDashboardStats()
    stats.value = data

    if (data.score_distribution) {
      scoreChartData.value = {
        labels: data.score_distribution.map(d => d.range),
        datasets: [{
          data: data.score_distribution.map(d => d.count),
          backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#f97316', '#ef4444'],
        }],
      }
    }
  } catch (e) {
    console.error('Failed to load dashboard:', e)
  } finally {
    loading.value = false
  }
})

function getScoreColor(score) {
  if (score >= 800) return 'text-green-600'
  if (score >= 600) return 'text-blue-600'
  if (score >= 400) return 'text-yellow-600'
  if (score >= 200) return 'text-orange-600'
  return 'text-red-600'
}

function getScoreLabel(score) {
  if (score >= 800) return 'Excellent'
  if (score >= 600) return 'Good'
  if (score >= 400) return 'Average'
  if (score >= 200) return 'Poor'
  return 'Critical'
}
</script>

<template>
  <div>
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Dashboard</h1>
      <p class="text-gray-500 mt-1">Overview of security scan results</p>
    </div>

    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else-if="stats">
      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-500">Total Targets</p>
              <p class="text-3xl font-bold text-gray-900 mt-1">{{ stats.total_targets }}</p>
            </div>
            <div class="w-12 h-12 bg-indigo-100 rounded-lg flex items-center justify-center">
              <svg class="w-6 h-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/>
              </svg>
            </div>
          </div>
        </div>

        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-500">Total Scans</p>
              <p class="text-3xl font-bold text-gray-900 mt-1">{{ stats.total_scans }}</p>
            </div>
            <div class="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
              <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
              </svg>
            </div>
          </div>
        </div>

        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-500">Completed Scans</p>
              <p class="text-3xl font-bold text-gray-900 mt-1">{{ stats.completed_scans }}</p>
            </div>
            <div class="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
              <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
              </svg>
            </div>
          </div>
        </div>

        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-500">Average Score</p>
              <p :class="['text-3xl font-bold mt-1', getScoreColor(stats.average_score)]">
                {{ Math.round(stats.average_score) }}/1000
              </p>
              <p class="text-xs text-gray-400 mt-1">{{ getScoreLabel(stats.average_score) }}</p>
            </div>
            <div class="w-12 h-12 bg-yellow-100 rounded-lg flex items-center justify-center">
              <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
              </svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Charts & Latest Results -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Score Distribution Chart -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h3 class="text-lg font-semibold text-gray-900 mb-4">Score Distribution</h3>
          <Doughnut v-if="scoreChartData.labels.length" :data="scoreChartData" :options="scoreChartOptions" />
          <p v-else class="text-gray-400 text-center py-10">No data yet</p>
        </div>

        <!-- Latest Scan Results -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 lg:col-span-2">
          <h3 class="text-lg font-semibold text-gray-900 mb-4">Latest Results</h3>
          <div v-if="stats.latest_results && stats.latest_results.length" class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-gray-200">
                  <th class="text-right py-3 px-2 text-gray-500 font-medium">Website</th>
                  <th class="text-center py-3 px-2 text-gray-500 font-medium">Score</th>
                  <th class="text-center py-3 px-2 text-gray-500 font-medium">Status</th>
                  <th class="text-left py-3 px-2 text-gray-500 font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="result in stats.latest_results" :key="result.ID" class="border-b border-gray-100 hover:bg-gray-50">
                  <td class="py-3 px-2">
                    <div class="font-medium text-gray-900">{{ result.scan_target?.name || 'N/A' }}</div>
                    <div class="text-xs text-gray-400">{{ result.scan_target?.url }}</div>
                  </td>
                  <td class="py-3 px-2 text-center">
                    <span :class="['font-bold', getScoreColor(result.overall_score)]">
                      {{ Math.round(result.overall_score) }}/1000
                    </span>
                  </td>
                  <td class="py-3 px-2 text-center">
                    <span :class="[
                      'px-2 py-1 rounded-full text-xs font-medium',
                      result.status === 'completed' ? 'bg-green-100 text-green-700' :
                      result.status === 'running' ? 'bg-blue-100 text-blue-700' :
                      result.status === 'failed' ? 'bg-red-100 text-red-700' :
                      'bg-gray-100 text-gray-700'
                    ]">
                      {{ result.status }}
                    </span>
                  </td>
                  <td class="py-3 px-2">
                    <router-link :to="`/results/${result.ID}`" class="text-indigo-600 hover:text-indigo-800 text-sm">
                      View Details
                    </router-link>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p v-else class="text-gray-400 text-center py-10">No scan results yet. Add targets and start a scan.</p>
        </div>
      </div>
    </div>
  </div>
</template>
