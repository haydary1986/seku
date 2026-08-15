<script setup>
import { ref, computed } from 'vue'
import { compareScanResults, getScanJobs, getScanJob } from '../api'

const jobs = ref([])
const allResults = ref([])
const loading = ref(false)
const jobsLoading = ref(true)
const oldId = ref('')
const newId = ref('')
const comparison = ref(null)
const error = ref('')
const filter = ref('all')

const filteredChecks = computed(() => {
  if (!comparison.value) return []
  if (filter.value === 'all') return comparison.value.checks
  return comparison.value.checks.filter(c => c.status === filter.value)
})

async function loadJobs() {
  jobsLoading.value = true
  try {
    const { data } = await getScanJobs()
    jobs.value = data || []
    // Load completed results from each completed job
    const results = []
    for (const job of jobs.value) {
      if (job.status === 'completed') {
        try {
          const { data: jobData } = await getScanJob(job.ID)
          if (jobData.results) {
            for (const r of jobData.results) {
              if (r.status === 'completed') {
                results.push({
                  id: r.ID,
                  label: `${r.scan_target?.name || r.scan_target?.url || 'Target'} - Score: ${Math.round(r.overall_score)} (${new Date(r.ended_at).toLocaleDateString()})`,
                  score: r.overall_score,
                  target: r.scan_target,
                  date: r.ended_at,
                })
              }
            }
          }
        } catch { /* skip failed job loads */ }
      }
    }
    allResults.value = results
  } catch (e) {
    error.value = 'Failed to load scan jobs'
  } finally {
    jobsLoading.value = false
  }
}

async function runComparison() {
  if (!oldId.value || !newId.value) return
  loading.value = true
  error.value = ''
  comparison.value = null
  try {
    const { data } = await compareScanResults(oldId.value, newId.value)
    comparison.value = data
  } catch (e) {
    error.value = e.response?.data?.error || 'Comparison failed'
  } finally {
    loading.value = false
  }
}

function getChangeIcon(status) {
  if (status === 'improved') return { symbol: '\u25B2', color: 'text-green-600' }
  if (status === 'declined') return { symbol: '\u25BC', color: 'text-red-600' }
  return { symbol: '=', color: 'text-gray-400' }
}

function getRowBg(status) {
  if (status === 'improved') return 'bg-green-50 dark:bg-green-900/20'
  if (status === 'declined') return 'bg-red-50 dark:bg-red-900/20'
  return ''
}

loadJobs()
</script>

<template>
  <div>
    <!-- Loading state -->
    <div v-if="jobsLoading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <template v-else>
      <!-- Selector -->
      <div class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 mb-6">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Old Scan Result (Before)</label>
            <select v-model="oldId" class="w-full border border-gray-300 dark:border-slate-600 rounded-lg px-3 py-2 bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-200 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500">
              <option value="">Select old scan result...</option>
              <option v-for="r in allResults" :key="'old-' + r.id" :value="r.id">{{ r.label }}</option>
            </select>
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">New Scan Result (After)</label>
            <select v-model="newId" class="w-full border border-gray-300 dark:border-slate-600 rounded-lg px-3 py-2 bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-200 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500">
              <option value="">Select new scan result...</option>
              <option v-for="r in allResults" :key="'new-' + r.id" :value="r.id">{{ r.label }}</option>
            </select>
          </div>
        </div>
        <button
          @click="runComparison"
          :disabled="!oldId || !newId || loading"
          class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
        >
          <svg v-if="loading" class="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
          {{ loading ? 'Comparing...' : 'Compare' }}
        </button>
      </div>

      <!-- Error -->
      <div v-if="error" class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl p-4 mb-6">
        <p class="text-red-700 dark:text-red-400">{{ error }}</p>
      </div>

      <!-- No results hint -->
      <div v-if="allResults.length === 0" class="text-center py-16 bg-white dark:bg-slate-900 rounded-xl border border-gray-200 dark:border-slate-700">
        <svg class="w-16 h-16 mx-auto text-gray-300 dark:text-slate-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
        </svg>
        <p class="text-gray-500 dark:text-gray-400 text-lg">No scan results available</p>
        <p class="text-gray-400 dark:text-gray-500 text-sm mt-1">Run at least two scans to compare results</p>
      </div>

      <!-- Comparison Results -->
      <template v-if="comparison">
        <!-- Summary Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <!-- Score Change -->
          <div class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 text-center col-span-1 md:col-span-1">
            <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">Score Change</p>
            <div class="flex items-center justify-center gap-2">
              <span :class="[
                'text-4xl font-bold',
                comparison.score_change > 0 ? 'text-green-600' : comparison.score_change < 0 ? 'text-red-600' : 'text-gray-500'
              ]">
                {{ comparison.score_change > 0 ? '+' : '' }}{{ Math.round(comparison.score_change) }}
              </span>
              <svg v-if="comparison.score_change > 0" class="w-8 h-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18"/>
              </svg>
              <svg v-else-if="comparison.score_change < 0" class="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 14l-7 7m0 0l-7-7m7 7V3"/>
              </svg>
            </div>
            <div class="mt-2 text-sm text-gray-400 dark:text-gray-500">
              {{ Math.round(comparison.old_result?.score || 0) }} -> {{ Math.round(comparison.new_result?.score || 0) }}
            </div>
          </div>

          <!-- Improved -->
          <div class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 text-center">
            <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">Improved</p>
            <p class="text-3xl font-bold text-green-600">{{ comparison.summary?.improved || 0 }}</p>
          </div>

          <!-- Declined -->
          <div class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 text-center">
            <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">Declined</p>
            <p class="text-3xl font-bold text-red-600">{{ comparison.summary?.declined || 0 }}</p>
          </div>

          <!-- Unchanged -->
          <div class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 text-center">
            <p class="text-sm text-gray-500 dark:text-gray-400 mb-2">Unchanged</p>
            <p class="text-3xl font-bold text-gray-500">{{ comparison.summary?.unchanged || 0 }}</p>
          </div>
        </div>

        <!-- Category Comparison Bar Chart -->
        <div v-if="comparison.categories && comparison.categories.length" class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 mb-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Category Comparison</h3>
          <div class="space-y-4">
            <div v-for="cat in comparison.categories" :key="cat.category" class="flex items-center gap-4">
              <span class="w-40 text-sm font-medium text-gray-700 dark:text-gray-300 truncate">{{ cat.category }}</span>
              <div class="flex-1 flex items-center gap-2">
                <!-- Old bar (gray) -->
                <div class="flex-1 relative">
                  <div class="h-5 bg-gray-100 dark:bg-slate-800 rounded-full overflow-hidden">
                    <div class="h-full bg-gray-400 dark:bg-slate-500 rounded-full transition-all" :style="{ width: (cat.old_score / 10) + '%' }"></div>
                  </div>
                  <span class="absolute inset-0 flex items-center justify-center text-xs font-medium text-gray-600 dark:text-gray-300">{{ Math.round(cat.old_score) }}</span>
                </div>
                <!-- New bar (indigo) -->
                <div class="flex-1 relative">
                  <div class="h-5 bg-gray-100 dark:bg-slate-800 rounded-full overflow-hidden">
                    <div class="h-full bg-indigo-500 rounded-full transition-all" :style="{ width: (cat.new_score / 10) + '%' }"></div>
                  </div>
                  <span class="absolute inset-0 flex items-center justify-center text-xs font-medium text-white mix-blend-difference">{{ Math.round(cat.new_score) }}</span>
                </div>
              </div>
              <span :class="['text-sm font-bold w-16 text-end', getChangeIcon(cat.status).color]">
                {{ getChangeIcon(cat.status).symbol }} {{ Math.round(Math.abs(cat.change)) }}
              </span>
            </div>
          </div>
          <div class="flex items-center gap-6 mt-4 text-xs text-gray-500 dark:text-gray-400">
            <span class="flex items-center gap-1"><span class="w-3 h-3 bg-gray-400 dark:bg-slate-500 rounded-full inline-block"></span> Old</span>
            <span class="flex items-center gap-1"><span class="w-3 h-3 bg-indigo-500 rounded-full inline-block"></span> New</span>
          </div>
        </div>

        <!-- Checks Table with Filter -->
        <div v-if="comparison.checks && comparison.checks.length" class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 overflow-hidden">
          <div class="p-4 border-b border-gray-200 dark:border-slate-700 flex flex-wrap items-center justify-between gap-3">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Check Comparison</h3>
            <div class="flex gap-2">
              <button
                v-for="f in ['all', 'improved', 'declined', 'unchanged']"
                :key="f"
                @click="filter = f"
                :class="[
                  'px-3 py-1 rounded-lg text-sm font-medium transition-colors',
                  filter === f
                    ? 'bg-indigo-600 text-white'
                    : 'bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-slate-700'
                ]"
              >
                {{ f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1) }}
                <span v-if="f === 'all'" class="ml-1 opacity-70">({{ comparison.checks.length }})</span>
                <span v-else-if="f === 'improved'" class="ml-1 opacity-70">({{ comparison.summary?.improved || 0 }})</span>
                <span v-else-if="f === 'declined'" class="ml-1 opacity-70">({{ comparison.summary?.declined || 0 }})</span>
                <span v-else class="ml-1 opacity-70">({{ comparison.summary?.unchanged || 0 }})</span>
              </button>
            </div>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full">
              <thead class="bg-gray-50 dark:bg-slate-800">
                <tr>
                  <th class="px-4 py-3 text-start text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Check</th>
                  <th class="px-4 py-3 text-start text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Category</th>
                  <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Old Score</th>
                  <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">New Score</th>
                  <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Change</th>
                  <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Status</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-100 dark:divide-slate-700">
                <tr v-for="check in filteredChecks" :key="check.check_name" :class="getRowBg(check.status)">
                  <td class="px-4 py-3 text-sm font-medium text-gray-900 dark:text-gray-200">{{ check.check_name }}</td>
                  <td class="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{{ check.category }}</td>
                  <td class="px-4 py-3 text-center text-sm text-gray-600 dark:text-gray-300">{{ Math.round(check.old_score) }}</td>
                  <td class="px-4 py-3 text-center text-sm font-medium text-gray-900 dark:text-gray-200">{{ Math.round(check.new_score) }}</td>
                  <td class="px-4 py-3 text-center text-sm font-bold" :class="getChangeIcon(check.status).color">
                    {{ getChangeIcon(check.status).symbol }} {{ Math.round(Math.abs(check.change)) }}
                  </td>
                  <td class="px-4 py-3 text-center">
                    <span :class="[
                      'px-2 py-1 rounded-full text-xs font-medium',
                      check.status === 'improved' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
                      check.status === 'declined' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                      'bg-gray-100 text-gray-600 dark:bg-slate-700 dark:text-gray-400'
                    ]">
                      {{ check.status }}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </template>
    </template>
  </div>
</template>
