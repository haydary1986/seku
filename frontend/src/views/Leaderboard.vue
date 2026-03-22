<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getLeaderboard } from '../api'
import { Bar } from 'vue-chartjs'
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

const router = useRouter()
const data = ref(null)
const loading = ref(true)

const chartData = ref({ labels: [], datasets: [] })
const chartOptions = {
  responsive: true,
  indexAxis: 'y',
  scales: { x: { min: 0, max: 1000, title: { display: true, text: 'Security Score (/1000)' } } },
  plugins: { legend: { display: false } },
}

function getGradeColor(grade) {
  const colors = { 'A+': 'bg-green-500', 'A': 'bg-green-400', 'B': 'bg-blue-500', 'C': 'bg-yellow-500', 'D': 'bg-orange-500', 'F': 'bg-red-500' }
  return colors[grade] || 'bg-gray-500'
}

function getScoreColor(score) {
  if (score >= 800) return 'text-green-600'
  if (score >= 600) return 'text-blue-600'
  if (score >= 400) return 'text-yellow-600'
  if (score >= 200) return 'text-orange-600'
  return 'text-red-600'
}

function getBarColor(score) {
  if (score >= 800) return '#10b981'
  if (score >= 600) return '#3b82f6'
  if (score >= 400) return '#f59e0b'
  if (score >= 200) return '#f97316'
  return '#ef4444'
}

onMounted(async () => {
  try {
    const res = await getLeaderboard()
    data.value = res.data

    if (res.data.rankings?.length) {
      chartData.value = {
        labels: res.data.rankings.map(r => r.name || r.url),
        datasets: [{
          label: 'Security Score',
          data: res.data.rankings.map(r => Math.round(r.latest_score)),
          backgroundColor: res.data.rankings.map(r => getBarColor(r.latest_score)),
          borderRadius: 6,
        }],
      }
    }
  } catch (e) {
    console.error('Failed to load leaderboard:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Leaderboard</h1>
      <p class="text-gray-500 mt-1">All websites ranked by security score (highest to lowest)</p>
    </div>

    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else-if="data">
      <!-- Summary -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-5 text-center">
          <p class="text-sm text-gray-500">Total Sites</p>
          <p class="text-3xl font-bold text-gray-900">{{ data.total_sites }}</p>
        </div>
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-5 text-center">
          <p class="text-sm text-gray-500">Scanned</p>
          <p class="text-3xl font-bold text-indigo-600">{{ data.scanned_sites }}</p>
        </div>
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-5 text-center">
          <p class="text-sm text-gray-500">Average Score</p>
          <p :class="['text-3xl font-bold', getScoreColor(data.average_score)]">{{ Math.round(data.average_score) }}%</p>
        </div>
      </div>

      <!-- Chart -->
      <div v-if="chartData.labels.length" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Score Comparison</h3>
        <Bar :data="chartData" :options="chartOptions" />
      </div>

      <!-- Rankings Table -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50">
            <tr>
              <th class="py-3 px-4 text-right text-gray-600 font-medium">Rank</th>
              <th class="py-3 px-4 text-right text-gray-600 font-medium">Website</th>
              <th class="py-3 px-4 text-center text-gray-600 font-medium">Grade</th>
              <th class="py-3 px-4 text-center text-gray-600 font-medium">Score</th>
              <th class="py-3 px-4 text-center text-gray-600 font-medium">Details</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="site in data.rankings" :key="site.scan_target_id" class="border-t border-gray-100 hover:bg-gray-50">
              <td class="py-4 px-4">
                <div class="flex items-center gap-2">
                  <span v-if="site.rank <= 3" class="text-lg">{{ site.rank === 1 ? '🥇' : site.rank === 2 ? '🥈' : '🥉' }}</span>
                  <span v-else class="text-gray-400 font-mono">{{ site.rank }}</span>
                </div>
              </td>
              <td class="py-4 px-4">
                <div class="font-medium text-gray-900">{{ site.name || 'N/A' }}</div>
                <div class="text-xs text-gray-400">{{ site.url }}</div>
                <div v-if="site.institution" class="text-xs text-gray-500">{{ site.institution }}</div>
              </td>
              <td class="py-4 px-4 text-center">
                <span :class="['inline-flex items-center justify-center w-10 h-10 rounded-full text-white font-bold text-sm', getGradeColor(site.grade)]">
                  {{ site.grade }}
                </span>
              </td>
              <td class="py-4 px-4 text-center">
                <span :class="['text-2xl font-bold', getScoreColor(site.latest_score)]">
                  {{ Math.round(site.latest_score) }}
                </span>
                <span class="text-gray-400 text-sm">/1000</span>
              </td>
              <td class="py-4 px-4 text-center">
                <button
                  @click="router.push(`/results/${site.scan_result_id}`)"
                  class="px-3 py-1 text-sm text-indigo-600 border border-indigo-300 rounded-lg hover:bg-indigo-50"
                >
                  View Report
                </button>
              </td>
            </tr>
          </tbody>
        </table>

        <div v-if="!data.rankings?.length" class="text-center py-16 text-gray-400">
          <p class="text-lg">No scan results yet</p>
          <p class="text-sm">Run a scan first to see the leaderboard</p>
        </div>
      </div>
    </div>
  </div>
</template>
