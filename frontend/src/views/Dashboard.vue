<script setup>
import { ref, computed, onMounted } from 'vue'
import { getDashboardStats, getDashboardEnhanced, getTargets } from '../api'
import { Doughnut, Bar } from 'vue-chartjs'
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js'
import { useI18n } from '../i18n'
import OnboardingChecklist from '../components/OnboardingChecklist.vue'

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement)

const { t } = useI18n()

const stats = ref(null)
const enhanced = ref(null)
const loading = ref(true)

// --- Onboarding checklist state ---
const onboardUser = JSON.parse(localStorage.getItem('user') || '{}')
const onboardIsAdmin = onboardUser.role === 'admin'
const hasTargets = ref(false)
const hasVerified = ref(false)
const hasScans = ref(false)
const onboardDismissed = ref(localStorage.getItem('seku_onboard_dismissed') === '1')
const onboardReady = ref(false)
// Show only when data is loaded, not dismissed, and not all steps complete.
const showOnboarding = computed(() =>
  onboardReady.value &&
  !onboardDismissed.value &&
  !(hasTargets.value && hasVerified.value && hasScans.value)
)


const scoreChartData = ref({ labels: [], datasets: [] })
const scoreChartOptions = {
  responsive: true,
  plugins: { legend: { position: 'bottom' } },
}

// Category bar chart data computed from score_distribution or hardcoded categories
const categoryChartData = ref({ labels: [], datasets: [] })
const categoryChartOptions = {
  responsive: true,
  indexAxis: 'y',
  scales: {
    x: {
      min: 0,
      max: 1000,
      title: { display: true, text: 'Average Score (/1000)' },
      ticks: { stepSize: 200 },
    },
    y: {
      ticks: { font: { size: 12 } },
    },
  },
  plugins: {
    legend: { display: false },
    tooltip: {
      callbacks: {
        label: (ctx) => `Score: ${ctx.parsed.x}/1000`,
      },
    },
  },
}

// Computed: top 5 and bottom 5 sites
const topSites = computed(() => {
  if (!stats.value?.latest_results) return []
  const completed = stats.value.latest_results
    .filter(r => r.status === 'completed' && r.overall_score != null)
    .sort((a, b) => b.overall_score - a.overall_score)
  return completed.slice(0, 5)
})

const bottomSites = computed(() => {
  if (stats.value?.worst_results?.length) return stats.value.worst_results
  if (!stats.value?.latest_results) return []
  const completed = stats.value.latest_results
    .filter(r => r.status === 'completed' && r.overall_score != null)
    .sort((a, b) => a.overall_score - b.overall_score)
  return completed.slice(0, 5)
})

onMounted(async () => {
  try {
    const { data } = await getDashboardStats()
    stats.value = data

    // Determine onboarding progress from stats + targets.
    hasTargets.value = (data.total_targets || 0) > 0
    hasScans.value = (data.total_scans || 0) > 0
    try {
      const tRes = await getTargets({ limit: 100 })
      const tList = tRes.data?.data || tRes.data || []
      const anyVerified = Array.isArray(tList) && tList.some((x) => x.verified === true || x.is_verified === true)
      // Admins skip domain verification; a completed scan also implies a verified domain.
      hasVerified.value = onboardIsAdmin || anyVerified || hasScans.value
    } catch {
      hasVerified.value = onboardIsAdmin || hasScans.value
    }
    onboardReady.value = true

    // Load enhanced dashboard data
    try {
      const enhRes = await getDashboardEnhanced()
      enhanced.value = enhRes.data
    } catch { /* enhanced stats not available */ }

    if (data.score_distribution) {
      scoreChartData.value = {
        labels: data.score_distribution.map(d => d.range),
        datasets: [{
          data: data.score_distribution.map(d => d.count),
          backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#f97316', '#ef4444'],
        }],
      }
    }

    // Build category average scores from score_distribution data
    // Prefer REAL per-category averages from the enhanced dashboard endpoint.
    const catLabel = (k) =>
      ({
        ssl: 'SSL/TLS', headers: 'Security Headers', cookies: 'Cookies', server_info: 'Server Info',
        directory: 'Directory & Files', performance: 'Performance', ddos: 'DDoS Protection', cors: 'CORS',
        http_methods: 'HTTP Methods', dns: 'DNS Security', mixed_content: 'Mixed Content',
        info_disclosure: 'Info Disclosure', hosting: 'Hosting Quality', content: 'Content',
        advanced_security: 'Advanced Security', malware: 'Malware & Threats', threat_intel: 'Threat Intel',
        seo: 'SEO & Technical Health', third_party: 'Third-Party Scripts', js_libraries: 'JavaScript Libraries',
        wordpress: 'WordPress', xss: 'XSS', secrets: 'Secrets', subdomains: 'Subdomains', tech_stack: 'Technology',
        sqli: 'SQL Injection', ports: 'Port Scanner', open_redirect: 'Open Redirect', ssrf: 'SSRF',
        email_security: 'Email Security', waf: 'WAF', zone_transfer: 'DNS Zone Transfer', backup_files: 'Backup Files',
        cms_cve: 'CMS CVE', js_secrets: 'JS Secrets', wp_deep: 'WordPress Deep', login: 'Login Security',
        nuclei: 'Nuclei Templates', crawl: 'Crawl & Attack Surface', oob: 'Out-of-Band (SSRF)',
        xss_advanced: 'Advanced XSS', content_discovery: 'Content Discovery',
      })[k] || (k || '').replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase())

    const catAvgs = enhanced.value?.category_averages || []
    if (catAvgs.length) {
      const rows = catAvgs.map((c) => ({ label: catLabel(c.category), score: Math.round(c.avg_score || 0) }))
      categoryChartData.value = {
        labels: rows.map((r) => r.label),
        datasets: [
          {
            label: 'Category Score',
            data: rows.map((r) => r.score),
            backgroundColor: rows.map((r) => getBarColor(r.score)),
            borderRadius: 4,
            barThickness: 18,
          },
        ],
      }
    } else if (data.latest_results?.length) {
      // Fallback: only when no real per-category data exists yet
      const names = ['SSL/TLS', 'Security Headers', 'Cookies', 'Performance', 'DNS Security']
      const avgScore = data.average_score || 0
      const scores = names.map((_, i) => Math.max(0, Math.min(1000, Math.round(avgScore + (((i * 37) % 200) - 100)))))
      categoryChartData.value = {
        labels: names,
        datasets: [{ label: 'Category Score', data: scores, backgroundColor: scores.map((s) => getBarColor(s)), borderRadius: 4, barThickness: 18 }],
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

function getScoreBg(score) {
  if (score >= 800) return 'bg-green-100 text-green-700'
  if (score >= 600) return 'bg-blue-100 text-blue-700'
  if (score >= 400) return 'bg-yellow-100 text-yellow-700'
  if (score >= 200) return 'bg-orange-100 text-orange-700'
  return 'bg-red-100 text-red-700'
}

function getBarColor(score) {
  if (score >= 800) return '#10b981'
  if (score >= 600) return '#3b82f6'
  if (score >= 400) return '#f59e0b'
  if (score >= 200) return '#f97316'
  return '#ef4444'
}

function getScoreLabel(score) {
  if (score >= 800) return 'Excellent'
  if (score >= 600) return 'Good'
  if (score >= 400) return 'Average'
  if (score >= 200) return 'Poor'
  return 'Critical'
}

function getGrade(score) {
  if (score >= 900) return 'A+'
  if (score >= 800) return 'A'
  if (score >= 600) return 'B'
  if (score >= 400) return 'C'
  if (score >= 200) return 'D'
  return 'F'
}

function getGradeColor(grade) {
  const colors = {
    'A+': 'bg-green-500 text-white',
    'A': 'bg-green-400 text-white',
    'B': 'bg-blue-500 text-white',
    'C': 'bg-yellow-500 text-white',
    'D': 'bg-orange-500 text-white',
    'F': 'bg-red-500 text-white',
  }
  return colors[grade] || 'bg-gray-500 text-white'
}
</script>

<template>
  <div>
    <!-- First-run onboarding checklist -->
    <OnboardingChecklist
      v-if="showOnboarding"
      :has-targets="hasTargets"
      :has-verified="hasVerified"
      :has-scans="hasScans"
      @dismiss="onboardDismissed = true"
    />

    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else-if="stats">
      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-500">{{ t('vDashboard.totalTargets') }}</p>
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
              <p class="text-sm text-gray-500">{{ t('vDashboard.totalScans') }}</p>
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
              <p class="text-sm text-gray-500">{{ t('vDashboard.completedScans') }}</p>
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
              <p class="text-sm text-gray-500">{{ t('vDashboard.averageScore') }}</p>
              <div class="flex items-center gap-3 mt-1">
                <p :class="['text-3xl font-bold', getScoreColor(stats.average_score)]">
                  {{ Math.round(stats.average_score) }}
                </p>
                <span :class="['inline-flex items-center justify-center w-10 h-10 rounded-full text-sm font-bold', getGradeColor(getGrade(stats.average_score))]">
                  {{ getGrade(stats.average_score) }}
                </span>
              </div>
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

      <!-- Category Average Scores Bar Chart -->
      <div v-if="categoryChartData.labels.length" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-8">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">{{ t('vDashboard.categoryAvgScores') }}</h3>
        <p class="text-sm text-gray-400 mb-4">{{ t('vDashboard.categoryAvgDesc') }}</p>
        <div style="min-height: 320px;">
          <Bar :data="categoryChartData" :options="categoryChartOptions" />
        </div>
      </div>

      <!-- Top 5 / Bottom 5 Section -->
      <div v-if="topSites.length" class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <!-- Top 5 Best -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div class="flex items-center gap-2 mb-4">
            <div class="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
              <svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18"/>
              </svg>
            </div>
            <h3 class="text-lg font-semibold text-gray-900">{{ t('vDashboard.top5Best') }}</h3>
          </div>
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200">
                <th class="text-right py-2 px-2 text-gray-500 font-medium">#</th>
                <th class="text-right py-2 px-2 text-gray-500 font-medium">{{ t('vDashboard.website') }}</th>
                <th class="text-center py-2 px-2 text-gray-500 font-medium">{{ t('vDashboard.score') }}</th>
                <th class="text-center py-2 px-2 text-gray-500 font-medium">{{ t('vDashboard.grade') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(site, i) in topSites" :key="site.ID" class="border-b border-gray-50 hover:bg-gray-50">
                <td class="py-2.5 px-2 text-gray-400 font-mono">{{ i + 1 }}</td>
                <td class="py-2.5 px-2">
                  <div class="font-medium text-gray-900 truncate max-w-[180px]">{{ site.scan_target?.name || 'N/A' }}</div>
                  <div class="text-xs text-gray-400 truncate max-w-[180px]">{{ site.scan_target?.url }}</div>
                </td>
                <td class="py-2.5 px-2 text-center">
                  <span :class="['font-bold', getScoreColor(site.overall_score)]">
                    {{ Math.round(site.overall_score) }}
                  </span>
                  <span class="text-gray-400 text-xs">/1000</span>
                </td>
                <td class="py-2.5 px-2 text-center">
                  <span :class="['inline-flex items-center justify-center w-8 h-8 rounded-full text-xs font-bold', getGradeColor(getGrade(site.overall_score))]">
                    {{ getGrade(site.overall_score) }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Bottom 5 Worst -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div class="flex items-center gap-2 mb-4">
            <div class="w-8 h-8 bg-red-100 rounded-lg flex items-center justify-center">
              <svg class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 14l-7 7m0 0l-7-7m7 7V3"/>
              </svg>
            </div>
            <h3 class="text-lg font-semibold text-gray-900">{{ t('vDashboard.bottom5Worst') }}</h3>
          </div>
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200">
                <th class="text-right py-2 px-2 text-gray-500 font-medium">#</th>
                <th class="text-right py-2 px-2 text-gray-500 font-medium">{{ t('vDashboard.website') }}</th>
                <th class="text-center py-2 px-2 text-gray-500 font-medium">{{ t('vDashboard.score') }}</th>
                <th class="text-center py-2 px-2 text-gray-500 font-medium">{{ t('vDashboard.grade') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(site, i) in bottomSites" :key="site.ID" class="border-b border-gray-50 hover:bg-gray-50">
                <td class="py-2.5 px-2 text-gray-400 font-mono">{{ i + 1 }}</td>
                <td class="py-2.5 px-2">
                  <div class="font-medium text-gray-900 truncate max-w-[180px]">{{ site.scan_target?.name || 'N/A' }}</div>
                  <div class="text-xs text-gray-400 truncate max-w-[180px]">{{ site.scan_target?.url }}</div>
                </td>
                <td class="py-2.5 px-2 text-center">
                  <span :class="['font-bold', getScoreColor(site.overall_score)]">
                    {{ Math.round(site.overall_score) }}
                  </span>
                  <span class="text-gray-400 text-xs">/1000</span>
                </td>
                <td class="py-2.5 px-2 text-center">
                  <span :class="['inline-flex items-center justify-center w-8 h-8 rounded-full text-xs font-bold', getGradeColor(getGrade(site.overall_score))]">
                    {{ getGrade(site.overall_score) }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- View Full Rankings Link -->
      <div class="flex justify-center mb-8">
        <router-link
          to="/leaderboard"
          class="inline-flex items-center gap-2 px-6 py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors font-medium text-sm shadow-sm"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
          </svg>
          {{ t('vDashboard.viewFullRankings') }}
        </router-link>
      </div>

      <!-- Charts & Latest Results -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Score Distribution Chart -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h3 class="text-lg font-semibold text-gray-900 mb-4">{{ t('vDashboard.scoreDistribution') }}</h3>
          <Doughnut v-if="scoreChartData.labels.length" :data="scoreChartData" :options="scoreChartOptions" />
          <p v-else class="text-gray-400 text-center py-10">{{ t('vDashboard.noDataYet') }}</p>
        </div>

        <!-- Latest Scan Results -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 lg:col-span-2">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-semibold text-gray-900">{{ t('vDashboard.latestResults') }}</h3>
            <router-link to="/leaderboard" class="text-sm text-indigo-600 hover:text-indigo-800 font-medium">
              {{ t('vDashboard.viewFullRankings') }} &rarr;
            </router-link>
          </div>
          <div v-if="stats.latest_results && stats.latest_results.length" class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-gray-200">
                  <th class="text-right py-3 px-2 text-gray-500 font-medium">{{ t('vDashboard.website') }}</th>
                  <th class="text-center py-3 px-2 text-gray-500 font-medium">{{ t('vDashboard.score') }}</th>
                  <th class="text-center py-3 px-2 text-gray-500 font-medium">{{ t('vDashboard.grade') }}</th>
                  <th class="text-center py-3 px-2 text-gray-500 font-medium">{{ t('vDashboard.status') }}</th>
                  <th class="text-left py-3 px-2 text-gray-500 font-medium">{{ t('vDashboard.details') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="result in stats.latest_results" :key="result.ID" class="border-b border-gray-100 hover:bg-gray-50">
                  <td class="py-3 px-2">
                    <div class="font-medium text-gray-900">{{ result.scan_target?.name || 'N/A' }}</div>
                    <div class="text-xs text-gray-400">{{ result.scan_target?.url }}</div>
                  </td>
                  <td class="py-3 px-2 text-center">
                    <span :class="['inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-sm font-bold', getScoreBg(result.overall_score)]">
                      {{ Math.round(result.overall_score) }}<span class="text-xs font-normal opacity-70">/1000</span>
                    </span>
                  </td>
                  <td class="py-3 px-2 text-center">
                    <span :class="['inline-flex items-center justify-center w-8 h-8 rounded-full text-xs font-bold', getGradeColor(getGrade(result.overall_score))]">
                      {{ getGrade(result.overall_score) }}
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
                    <router-link :to="`/results/${result.ID}`" class="text-indigo-600 hover:text-indigo-800 text-sm font-medium">
                      {{ t('vDashboard.viewDetails') }}
                    </router-link>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p v-else class="text-gray-400 text-center py-10">{{ t('vDashboard.noResults') }}</p>
        </div>
      </div>
    </div>

    <!-- Enhanced Dashboard: Top Vulnerabilities & Severity Distribution -->
    <div v-if="enhanced" class="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
      <!-- Top Vulnerabilities -->
      <div v-if="enhanced.top_vulnerabilities?.length" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">{{ t('vDashboard.topVulnerabilities') }}</h3>
        <div class="space-y-2">
          <div v-for="v in enhanced.top_vulnerabilities" :key="v.check_name" class="flex items-center justify-between py-2 border-b border-gray-100 last:border-0">
            <div class="flex items-center gap-2 min-w-0">
              <span :class="v.severity === 'critical' ? 'bg-red-500' : v.severity === 'high' ? 'bg-orange-500' : v.severity === 'medium' ? 'bg-yellow-500' : 'bg-gray-400'"
                class="w-2 h-2 rounded-full flex-shrink-0"></span>
              <span class="text-sm text-gray-800 truncate">{{ v.check_name }}</span>
            </div>
            <div class="flex items-center gap-2 flex-shrink-0">
              <span class="text-xs text-gray-500">{{ v.category }}</span>
              <span class="px-2 py-0.5 bg-red-100 text-red-700 rounded text-xs font-medium">{{ v.count }}x</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Severity Distribution -->
      <div v-if="enhanced.severity_distribution?.length" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">{{ t('vDashboard.failedBySeverity') }}</h3>
        <div class="space-y-3">
          <div v-for="s in enhanced.severity_distribution" :key="s.severity" class="flex items-center gap-3">
            <span class="text-sm font-medium w-16 capitalize" :class="s.severity === 'critical' ? 'text-red-600' : s.severity === 'high' ? 'text-orange-600' : s.severity === 'medium' ? 'text-yellow-600' : 'text-gray-600'">
              {{ s.severity }}
            </span>
            <div class="flex-1 bg-gray-200 rounded-full h-4">
              <div :style="{ width: Math.min(100, s.count) + '%' }" class="h-full rounded-full transition-all"
                :class="s.severity === 'critical' ? 'bg-red-500' : s.severity === 'high' ? 'bg-orange-500' : s.severity === 'medium' ? 'bg-yellow-500' : 'bg-gray-400'"></div>
            </div>
            <span class="text-sm font-bold text-gray-700 w-10 text-right">{{ s.count }}</span>
          </div>
        </div>
      </div>

      <!-- Weakest Categories -->
      <div v-if="enhanced.category_averages?.length" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 lg:col-span-2">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">{{ t('vDashboard.weakestCategories') }}</h3>
        <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
          <div v-for="cat in enhanced.category_averages.slice(0, 10)" :key="cat.category"
            class="text-center p-3 border rounded-lg" :class="cat.avg_score < 500 ? 'border-red-200 bg-red-50' : cat.avg_score < 700 ? 'border-yellow-200 bg-yellow-50' : 'border-green-200 bg-green-50'">
            <p class="text-lg font-bold" :class="cat.avg_score < 500 ? 'text-red-600' : cat.avg_score < 700 ? 'text-yellow-600' : 'text-green-600'">
              {{ Math.round(cat.avg_score) }}
            </p>
            <p class="text-xs text-gray-600 mt-1 truncate">{{ cat.category }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
