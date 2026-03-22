<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getLeaderboard } from '../api'
import { Bar } from 'vue-chartjs'
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

const router = useRouter()
const data = ref(null)
const loading = ref(true)

// --- Filter / search state ---
const selectedCategory = ref('overall')
const selectedInstitution = ref('all')
const searchQuery = ref('')

// Category ID -> human label mapping
const categoryOptions = [
  { id: 'overall', label: 'Overall Score' },
  { id: 'ssl', label: 'SSL/TLS' },
  { id: 'headers', label: 'Security Headers' },
  { id: 'cookies', label: 'Cookie Security' },
  { id: 'server_info', label: 'Server Info' },
  { id: 'directory', label: 'Directory & Files' },
  { id: 'performance', label: 'Performance' },
  { id: 'ddos', label: 'DDoS Protection' },
  { id: 'cors', label: 'CORS' },
  { id: 'http_methods', label: 'HTTP Methods' },
  { id: 'dns', label: 'DNS Security' },
  { id: 'mixed_content', label: 'Mixed Content' },
  { id: 'info_disclosure', label: 'Information Disclosure' },
  { id: 'content', label: 'Content Optimization' },
  { id: 'hosting', label: 'Hosting Quality' },
  { id: 'advanced_security', label: 'Advanced Security' },
  { id: 'malware', label: 'Malware & Threats' },
  { id: 'threat_intel', label: 'Threat Intelligence' },
  { id: 'seo', label: 'SEO & Technical Health' },
  { id: 'third_party', label: 'Third-Party Scripts' },
  { id: 'js_libraries', label: 'JavaScript Libraries' },
]

const categoryLabelMap = Object.fromEntries(categoryOptions.map(c => [c.id, c.label]))

// --- Institution options ---
const institutionOptions = [
  { id: 'all', label: 'All' },
  { id: 'حكومية', label: 'حكومية' },
  { id: 'أهلية', label: 'أهلية' },
]

// --- Helpers ---

function getCategoryScore(site, catId) {
  if (catId === 'overall') return site.latest_score
  const cat = site.categories?.find(c => c.category === catId)
  return cat ? cat.score : 0
}

function getGradeColor(grade) {
  const colors = {
    'A+': 'bg-green-500',
    'A': 'bg-green-400',
    'B': 'bg-blue-500',
    'C': 'bg-yellow-500',
    'D': 'bg-orange-500',
    'F': 'bg-red-500',
  }
  return colors[grade] || 'bg-gray-500'
}

function getScoreColor(score) {
  if (score >= 800) return 'text-green-600'
  if (score >= 600) return 'text-blue-600'
  if (score >= 400) return 'text-yellow-600'
  if (score >= 200) return 'text-orange-600'
  return 'text-red-600'
}

function getScoreBg(score) {
  if (score >= 800) return 'bg-green-50 border-green-200'
  if (score >= 600) return 'bg-blue-50 border-blue-200'
  if (score >= 400) return 'bg-yellow-50 border-yellow-200'
  if (score >= 200) return 'bg-orange-50 border-orange-200'
  return 'bg-red-50 border-red-200'
}

function getBarColor(score) {
  if (score >= 800) return '#10b981'
  if (score >= 600) return '#3b82f6'
  if (score >= 400) return '#f59e0b'
  if (score >= 200) return '#f97316'
  return '#ef4444'
}

// --- Computed: filtered + sorted rankings ---

const filteredRankings = computed(() => {
  if (!data.value?.rankings) return []

  let list = [...data.value.rankings]

  // Institution filter
  if (selectedInstitution.value !== 'all') {
    list = list.filter(s => s.institution === selectedInstitution.value)
  }

  // Search filter (name or url)
  if (searchQuery.value.trim()) {
    const q = searchQuery.value.trim().toLowerCase()
    list = list.filter(s =>
      (s.name && s.name.toLowerCase().includes(q)) ||
      (s.url && s.url.toLowerCase().includes(q))
    )
  }

  // Sort by selected category score (descending)
  list.sort((a, b) => getCategoryScore(b, selectedCategory.value) - getCategoryScore(a, selectedCategory.value))

  // Re-assign ranks after filtering/sorting
  return list.map((site, idx) => ({ ...site, displayRank: idx + 1 }))
})

// --- Computed: stats for filtered set ---

const stats = computed(() => {
  const list = filteredRankings.value
  if (!list.length) return { count: 0, min: 0, max: 0, avg: 0 }

  const scores = list.map(s => getCategoryScore(s, selectedCategory.value))
  const sum = scores.reduce((a, b) => a + b, 0)
  return {
    count: list.length,
    min: Math.round(Math.min(...scores)),
    max: Math.round(Math.max(...scores)),
    avg: Math.round(sum / scores.length),
  }
})

// --- Computed: chart data (reactive to filters) ---

const chartData = computed(() => {
  const list = filteredRankings.value
  if (!list.length) return { labels: [], datasets: [] }

  const scores = list.map(s => Math.round(getCategoryScore(s, selectedCategory.value)))
  const labels = list.map(s => s.name || s.url)
  const colors = scores.map(s => getBarColor(s))

  const catLabel = categoryLabelMap[selectedCategory.value] || 'Score'

  return {
    labels,
    datasets: [{
      label: catLabel,
      data: scores,
      backgroundColor: colors,
      borderRadius: 6,
    }],
  }
})

const chartOptions = computed(() => ({
  responsive: true,
  indexAxis: 'y',
  scales: {
    x: {
      min: 0,
      max: 1000,
      title: {
        display: true,
        text: `${categoryLabelMap[selectedCategory.value] || 'Score'} (/1000)`,
      },
    },
  },
  plugins: {
    legend: { display: false },
    tooltip: {
      callbacks: {
        label: (ctx) => `${ctx.parsed.x}/1000`,
      },
    },
  },
}))

// --- Load data ---

onMounted(async () => {
  try {
    const res = await getLeaderboard()
    data.value = res.data
  } catch (e) {
    console.error('Failed to load leaderboard:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <!-- Header -->
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Leaderboard</h1>
      <p class="text-gray-500 mt-1">All websites ranked by security score (highest to lowest)</p>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else-if="data">

      <!-- ============ Filters Row ============ -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-4 mb-6">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <!-- Category Filter -->
          <div>
            <label class="block text-xs font-medium text-gray-500 mb-1">Sort / Rank by Category</label>
            <select
              v-model="selectedCategory"
              class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            >
              <option v-for="cat in categoryOptions" :key="cat.id" :value="cat.id">
                {{ cat.label }}
              </option>
            </select>
          </div>

          <!-- Institution Filter -->
          <div>
            <label class="block text-xs font-medium text-gray-500 mb-1">Institution Type</label>
            <select
              v-model="selectedInstitution"
              class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
            >
              <option v-for="inst in institutionOptions" :key="inst.id" :value="inst.id">
                {{ inst.label }}
              </option>
            </select>
          </div>

          <!-- Search Box -->
          <div>
            <label class="block text-xs font-medium text-gray-500 mb-1">Search</label>
            <div class="relative">
              <svg class="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
              <input
                v-model="searchQuery"
                type="text"
                placeholder="Search by name or URL..."
                class="w-full rounded-lg border border-gray-300 bg-white pl-3 pr-10 py-2 text-sm text-gray-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none"
              />
            </div>
          </div>
        </div>
      </div>

      <!-- ============ Stats Row ============ -->
      <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-4 text-center">
          <p class="text-xs text-gray-500">Total Sites</p>
          <p class="text-2xl font-bold text-gray-900">{{ data.total_sites }}</p>
        </div>
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-4 text-center">
          <p class="text-xs text-gray-500">Showing</p>
          <p class="text-2xl font-bold text-indigo-600">{{ stats.count }}</p>
        </div>
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-4 text-center">
          <p class="text-xs text-gray-500">Min Score</p>
          <p :class="['text-2xl font-bold', getScoreColor(stats.min)]">{{ stats.min }}<span class="text-sm text-gray-400 font-normal">/1000</span></p>
        </div>
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-4 text-center">
          <p class="text-xs text-gray-500">Max Score</p>
          <p :class="['text-2xl font-bold', getScoreColor(stats.max)]">{{ stats.max }}<span class="text-sm text-gray-400 font-normal">/1000</span></p>
        </div>
        <div class="col-span-2 md:col-span-1 bg-white rounded-xl shadow-sm border border-gray-200 p-4 text-center">
          <p class="text-xs text-gray-500">Average Score</p>
          <p :class="['text-2xl font-bold', getScoreColor(stats.avg)]">{{ stats.avg }}<span class="text-sm text-gray-400 font-normal">/1000</span></p>
        </div>
      </div>

      <!-- ============ Chart ============ -->
      <div v-if="chartData.labels.length" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-1">
          Score Comparison
          <span v-if="selectedCategory !== 'overall'" class="text-sm font-normal text-indigo-600">
            &mdash; {{ categoryLabelMap[selectedCategory] }}
          </span>
        </h3>
        <p class="text-xs text-gray-400 mb-4">Sorted by {{ categoryLabelMap[selectedCategory] || 'Overall Score' }} (descending)</p>
        <Bar :data="chartData" :options="chartOptions" />
      </div>

      <!-- ============ Rankings Table ============ -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="bg-gray-50">
              <tr>
                <th class="py-3 px-4 text-right text-gray-600 font-medium">Rank</th>
                <th class="py-3 px-4 text-right text-gray-600 font-medium">Website</th>
                <th class="py-3 px-4 text-center text-gray-600 font-medium">Grade</th>
                <th class="py-3 px-4 text-center text-gray-600 font-medium">
                  {{ selectedCategory === 'overall' ? 'Overall Score' : categoryLabelMap[selectedCategory] }}
                </th>
                <th v-if="selectedCategory !== 'overall'" class="py-3 px-4 text-center text-gray-600 font-medium">
                  Overall
                </th>
                <th class="py-3 px-4 text-center text-gray-600 font-medium">Details</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="site in filteredRankings"
                :key="site.scan_target_id"
                class="border-t border-gray-100 hover:bg-gray-50 transition-colors"
              >
                <!-- Rank -->
                <td class="py-4 px-4">
                  <div class="flex items-center gap-2">
                    <span v-if="site.displayRank <= 3" class="text-lg">
                      {{ site.displayRank === 1 ? '\uD83E\uDD47' : site.displayRank === 2 ? '\uD83E\uDD48' : '\uD83E\uDD49' }}
                    </span>
                    <span v-else class="text-gray-400 font-mono">{{ site.displayRank }}</span>
                  </div>
                </td>

                <!-- Website -->
                <td class="py-4 px-4">
                  <div class="font-medium text-gray-900">{{ site.name || 'N/A' }}</div>
                  <div class="text-xs text-gray-400">{{ site.url }}</div>
                  <div v-if="site.institution" class="text-xs text-gray-500 mt-0.5">
                    <span class="inline-block px-1.5 py-0.5 rounded bg-gray-100 text-gray-600">{{ site.institution }}</span>
                  </div>
                </td>

                <!-- Grade -->
                <td class="py-4 px-4 text-center">
                  <span :class="['inline-flex items-center justify-center w-10 h-10 rounded-full text-white font-bold text-sm', getGradeColor(site.grade)]">
                    {{ site.grade }}
                  </span>
                </td>

                <!-- Primary Score (selected category) -->
                <td class="py-4 px-4 text-center">
                  <span :class="['text-2xl font-bold', getScoreColor(getCategoryScore(site, selectedCategory))]">
                    {{ Math.round(getCategoryScore(site, selectedCategory)) }}
                  </span>
                  <span class="text-gray-400 text-sm">/1000</span>
                </td>

                <!-- Overall score column (only when viewing a category) -->
                <td v-if="selectedCategory !== 'overall'" class="py-4 px-4 text-center">
                  <span :class="['text-lg font-semibold', getScoreColor(site.latest_score)]">
                    {{ Math.round(site.latest_score) }}
                  </span>
                  <span class="text-gray-400 text-xs">/1000</span>
                </td>

                <!-- Details -->
                <td class="py-4 px-4 text-center">
                  <button
                    @click="router.push(`/results/${site.scan_result_id}`)"
                    class="px-3 py-1 text-sm text-indigo-600 border border-indigo-300 rounded-lg hover:bg-indigo-50 transition-colors"
                  >
                    View Report
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Empty state -->
        <div v-if="!filteredRankings.length" class="text-center py-16 text-gray-400">
          <svg class="mx-auto w-12 h-12 text-gray-300 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <p class="text-lg" v-if="data.rankings?.length">No results match your filters</p>
          <p class="text-lg" v-else>No scan results yet</p>
          <p class="text-sm mt-1" v-if="!data.rankings?.length">Run a scan first to see the leaderboard</p>
          <button
            v-if="data.rankings?.length && (searchQuery || selectedInstitution !== 'all')"
            @click="searchQuery = ''; selectedInstitution = 'all'"
            class="mt-3 px-4 py-2 text-sm text-indigo-600 border border-indigo-300 rounded-lg hover:bg-indigo-50 transition-colors"
          >
            Clear Filters
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
