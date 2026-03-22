<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getScanResult, analyzeResult, getAIAnalysis } from '../api'
import { categoryInfo, getCheckExplanation } from '../data/securityKnowledge'
import { Radar } from 'vue-chartjs'
import { Chart as ChartJS, RadialLinearScale, PointElement, LineElement, Filler, Tooltip } from 'chart.js'

ChartJS.register(RadialLinearScale, PointElement, LineElement, Filler, Tooltip)

const route = useRoute()
const router = useRouter()
const result = ref(null)
const categories = ref({})
const loading = ref(true)
const activeCategory = ref(null)
const aiAnalysis = ref(null)
const aiLoading = ref(false)
const showAI = ref(false)

const categoryLabels = {
  ssl: 'SSL/TLS',
  headers: 'Security Headers',
  cookies: 'Cookies',
  server_info: 'Server Info',
  directory: 'Directory & Files',
  performance: 'Performance',
  ddos: 'DDoS Protection',
  cors: 'CORS',
  http_methods: 'HTTP Methods',
  dns: 'DNS Security',
  mixed_content: 'Mixed Content',
  info_disclosure: 'Information Disclosure',
}

const categoryIcons = {
  ssl: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
  headers: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  cookies: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
  server_info: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2',
  directory: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z',
  performance: 'M13 10V3L4 14h7v7l9-11h-7z',
  ddos: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
  cors: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
}

const radarData = computed(() => {
  if (!categories.value) return { labels: [], datasets: [] }
  const cats = Object.keys(categories.value)
  const scores = cats.map(cat => {
    const checks = categories.value[cat]
    const total = checks.reduce((sum, c) => sum + c.score * c.weight, 0)
    const weight = checks.reduce((sum, c) => sum + c.weight, 0)
    return weight > 0 ? Math.round(total / weight) : 0
  })
  return {
    labels: cats.map(c => categoryLabels[c] || c),
    datasets: [{
      label: 'Score',
      data: scores,
      backgroundColor: 'rgba(99, 102, 241, 0.2)',
      borderColor: 'rgb(99, 102, 241)',
      pointBackgroundColor: 'rgb(99, 102, 241)',
    }],
  }
})

const radarOptions = {
  responsive: true,
  scales: {
    r: { min: 0, max: 1000, ticks: { stepSize: 200 } },
  },
  plugins: { legend: { display: false } },
}

function getStatusColor(status) {
  const colors = {
    pass: 'bg-green-100 text-green-700',
    fail: 'bg-red-100 text-red-700',
    warning: 'bg-yellow-100 text-yellow-700',
    info: 'bg-blue-100 text-blue-700',
    error: 'bg-gray-100 text-gray-700',
  }
  return colors[status] || 'bg-gray-100 text-gray-700'
}

function getSeverityColor(severity) {
  const colors = {
    critical: 'text-red-600 bg-red-50',
    high: 'text-orange-600 bg-orange-50',
    medium: 'text-yellow-600 bg-yellow-50',
    low: 'text-blue-600 bg-blue-50',
    info: 'text-gray-500 bg-gray-50',
  }
  return colors[severity] || 'text-gray-500 bg-gray-50'
}

function getCategoryScore(catKey) {
  const checks = categories.value[catKey]
  if (!checks || !checks.length) return 0
  const total = checks.reduce((sum, c) => sum + c.score * c.weight, 0)
  const weight = checks.reduce((sum, c) => sum + c.weight, 0)
  return weight > 0 ? Math.round(total / weight) : 0
}

function parseDetails(details) {
  try { return JSON.parse(details) } catch { return {} }
}

function getScoreColor(score) {
  if (score >= 800) return 'text-green-600'
  if (score >= 600) return 'text-blue-600'
  if (score >= 400) return 'text-yellow-600'
  if (score >= 200) return 'text-orange-600'
  return 'text-red-600'
}

function getScoreBg(score) {
  if (score >= 800) return 'bg-green-500'
  if (score >= 600) return 'bg-blue-500'
  if (score >= 400) return 'bg-yellow-500'
  if (score >= 200) return 'bg-orange-500'
  return 'bg-red-500'
}

async function runAIAnalysis() {
  aiLoading.value = true
  showAI.value = true
  try {
    const { data } = await analyzeResult(route.params.id)
    aiAnalysis.value = data
  } catch (e) {
    alert(e.response?.data?.error || 'AI analysis failed')
  } finally {
    aiLoading.value = false
  }
}

async function loadExistingAnalysis() {
  try {
    const { data } = await getAIAnalysis(route.params.id)
    aiAnalysis.value = data
    showAI.value = true
  } catch { /* no existing analysis */ }
}

onMounted(async () => {
  try {
    const { data } = await getScanResult(route.params.id)
    result.value = data.result
    categories.value = data.categories
    const cats = Object.keys(data.categories)
    if (cats.length) activeCategory.value = cats[0]
    await loadExistingAnalysis()
  } catch (e) {
    console.error('Failed to load result:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <button @click="router.back()" class="text-indigo-600 hover:text-indigo-800 mb-4 flex items-center gap-1">
      <svg class="w-4 h-4 rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
      </svg>
      Back
    </button>

    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else-if="result">
      <!-- Header -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-2xl font-bold text-gray-900">{{ result.scan_target?.name || 'Scan Result' }}</h1>
            <a :href="'https://' + result.scan_target?.url" target="_blank" class="text-indigo-600 hover:underline text-sm">
              {{ result.scan_target?.url }}
            </a>
          </div>
          <div class="text-center">
            <div :class="['inline-flex items-center justify-center w-24 h-24 rounded-full text-3xl font-bold text-white', getScoreBg(result.overall_score)]">
              {{ Math.round(result.overall_score) }}
            </div>
            <p class="text-sm text-gray-500 mt-2">Overall Score</p>
          </div>
          <div class="mt-4 flex gap-2">
            <button @click="runAIAnalysis" :disabled="aiLoading"
              class="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 flex items-center gap-2 text-sm">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
              </svg>
              {{ aiLoading ? 'Analyzing...' : 'AI Analysis' }}
            </button>
            <button v-if="aiAnalysis" @click="showAI = !showAI"
              class="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 text-sm">
              {{ showAI ? 'Hide AI Report' : 'Show AI Report' }}
            </button>
          </div>
        </div>
      </div>

      <!-- AI Analysis Panel -->
      <div v-if="showAI" class="bg-white rounded-xl shadow-sm border border-purple-200 p-6 mb-6">
        <div class="flex items-center gap-2 mb-4">
          <svg class="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
          </svg>
          <h3 class="text-lg font-semibold text-purple-900">AI Security Analysis</h3>
          <span v-if="aiAnalysis" class="text-xs text-purple-500">({{ aiAnalysis.provider }})</span>
        </div>
        <div v-if="aiLoading" class="flex items-center justify-center py-10">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 ml-3"></div>
          <span class="text-purple-600">AI is analyzing the scan results...</span>
        </div>
        <div v-else-if="aiAnalysis?.analysis" class="prose prose-sm max-w-none text-gray-800 whitespace-pre-wrap" dir="ltr" style="text-align: left;">
          {{ aiAnalysis.analysis }}
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Radar Chart -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h3 class="text-lg font-semibold text-gray-900 mb-4">Category Scores</h3>
          <Radar v-if="radarData.labels.length" :data="radarData" :options="radarOptions" />
        </div>

        <!-- Category Cards -->
        <div class="lg:col-span-2">
          <div class="grid grid-cols-2 md:grid-cols-3 gap-3 mb-6">
            <button
              v-for="(checks, catKey) in categories"
              :key="catKey"
              @click="activeCategory = catKey"
              :class="[
                'p-4 rounded-xl border text-right transition-all',
                activeCategory === catKey
                  ? 'border-indigo-500 bg-indigo-50 shadow-md'
                  : 'border-gray-200 bg-white hover:border-gray-300'
              ]"
            >
              <div class="flex items-center gap-2 mb-2">
                <svg class="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="categoryIcons[catKey] || categoryIcons.headers"/>
                </svg>
                <span class="text-sm font-medium text-gray-700">{{ categoryLabels[catKey] || catKey }}</span>
              </div>
              <span :class="['text-2xl font-bold', getScoreColor(getCategoryScore(catKey))]">
                {{ getCategoryScore(catKey) }}/1000
              </span>
            </button>
          </div>

          <!-- Category Description -->
          <div v-if="activeCategory && categoryInfo[activeCategory]" class="bg-indigo-50 border border-indigo-200 rounded-xl p-4 mb-4">
            <h4 class="font-semibold text-indigo-900 mb-1">{{ categoryInfo[activeCategory].title }}</h4>
            <p class="text-sm text-indigo-800 mb-2">{{ categoryInfo[activeCategory].description }}</p>
            <div class="bg-red-50 border border-red-200 rounded-lg p-3 mt-2">
              <p class="text-xs font-semibold text-red-700 mb-1">Attack Scenario:</p>
              <p class="text-sm text-red-800">{{ categoryInfo[activeCategory].attackScenario }}</p>
            </div>
          </div>

          <!-- Check Details -->
          <div v-if="activeCategory && categories[activeCategory]" class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div class="p-4 bg-gray-50 border-b border-gray-200">
              <h3 class="text-lg font-semibold text-gray-900">
                {{ categoryLabels[activeCategory] || activeCategory }} - Detailed Checks
              </h3>
            </div>
            <div class="divide-y divide-gray-100">
              <div v-for="check in categories[activeCategory]" :key="check.ID" class="p-4">
                <div class="flex items-center justify-between mb-2">
                  <div class="flex items-center gap-2">
                    <span :class="['px-2 py-0.5 rounded text-xs font-medium', getStatusColor(check.status)]">
                      {{ check.status.toUpperCase() }}
                    </span>
                    <span class="font-medium text-gray-900">{{ check.check_name }}</span>
                  </div>
                  <div class="flex items-center gap-2">
                    <span :class="['px-2 py-0.5 rounded text-xs', getSeverityColor(check.severity)]">
                      {{ check.severity }}
                    </span>
                    <span :class="['font-bold', getScoreColor(check.score)]">{{ Math.round(check.score) }}/1000</span>
                  </div>
                </div>

                <!-- Explanation Box -->
                <div v-if="getCheckExplanation(check.check_name)" class="mt-2 border border-gray-200 rounded-lg overflow-hidden">
                  <div class="bg-blue-50 p-3 text-sm">
                    <p class="font-medium text-blue-900 mb-1">What this checks:</p>
                    <p class="text-blue-800">{{ getCheckExplanation(check.check_name).what }}</p>
                  </div>
                  <div v-if="check.status === 'fail' || check.status === 'warning'" class="bg-red-50 p-3 text-sm border-t border-gray-200">
                    <p class="font-medium text-red-900 mb-1">Risk:</p>
                    <p class="text-red-800">{{ getCheckExplanation(check.check_name).risk }}</p>
                    <p class="font-medium text-red-900 mt-2 mb-1">How attackers exploit this:</p>
                    <p class="text-red-800">{{ getCheckExplanation(check.check_name).exploit }}</p>
                    <p class="font-medium text-green-900 mt-2 mb-1">Recommended fix:</p>
                    <p class="text-green-800">{{ getCheckExplanation(check.check_name).fix }}</p>
                  </div>
                </div>

                <!-- Raw Details -->
                <div v-if="check.details" class="mt-2 bg-gray-50 rounded-lg p-3 text-sm">
                  <p class="text-xs text-gray-400 mb-1">Technical Details:</p>
                  <div v-for="(value, key) in parseDetails(check.details)" :key="key" class="flex gap-2 py-0.5">
                    <span class="text-gray-500 min-w-[100px]">{{ key }}:</span>
                    <span class="text-gray-700">{{ typeof value === 'object' ? JSON.stringify(value) : value }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
