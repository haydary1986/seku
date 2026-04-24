<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getScanResult, analyzeResult, getAIAnalysis, downloadReport, exportSARIF, exportCSV, getUpgradeSuggestions, getScoreHistory, getComplianceReport, getRemediationGuide, createGitHubIssue, createJiraIssue, getFixPriority, getTimelineComparison } from '../api'
import { categoryInfo, getCheckExplanation } from '../data/securityKnowledge'
import PasswordInput from '../components/PasswordInput.vue'
import { Radar, Line } from 'vue-chartjs'
import { Chart as ChartJS, RadialLinearScale, PointElement, LineElement, Filler, Tooltip, CategoryScale, LinearScale } from 'chart.js'

ChartJS.register(RadialLinearScale, PointElement, LineElement, Filler, Tooltip, CategoryScale, LinearScale)

const route = useRoute()
const router = useRouter()
const result = ref(null)
const categories = ref({})
const loading = ref(true)
const activeCategory = ref(null)
const aiAnalysis = ref(null)
const aiLoading = ref(false)
const showAI = ref(false)
const pdfLoading = ref(false)
const scoreHistory = ref([])
const historyLoading = ref(false)
const compliance = ref(null)
const complianceLoading = ref(false)
const expandedOwasp = ref({})

// Remediation state
const showRemediation = ref(false)
const remediationGuide = ref(null)
const remediationLoading = ref(false)
const remediationCheckName = ref('')
const activeServerType = ref('apache')

// SARIF export state
const sarifLoading = ref(false)

// CSV export state
const csvLoading = ref(false)

// Upgrade suggestions state
const upgradeSuggestions = ref([])
const upgradesLoading = ref(false)
const copiedUpgrade = ref(null)

// Fix Priority
const fixPriority = ref(null)
const fixPriorityLoading = ref(false)

// Timeline
const timeline = ref(null)
const timelineLoading = ref(false)

const historyChartData = computed(() => {
  if (scoreHistory.value.length < 2) return null
  return {
    labels: scoreHistory.value.map(p => {
      const d = new Date(p.scanned_at)
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
    }),
    datasets: [{
      label: 'Score',
      data: scoreHistory.value.map(p => Math.round(p.score)),
      borderColor: 'rgb(99, 102, 241)',
      backgroundColor: 'rgba(99, 102, 241, 0.1)',
      pointBackgroundColor: 'rgb(99, 102, 241)',
      pointRadius: 4,
      pointHoverRadius: 6,
      tension: 0.3,
      fill: true,
    }],
  }
})

const historyChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    y: { min: 0, max: 1000, ticks: { stepSize: 200 } },
    x: { grid: { display: false } },
  },
  plugins: {
    legend: { display: false },
    tooltip: {
      callbacks: {
        label: (ctx) => `Score: ${ctx.parsed.y}/1000`,
      },
    },
  },
}

async function downloadPDF() {
  pdfLoading.value = true
  try {
    const { data } = await downloadReport(route.params.id)
    const url = window.URL.createObjectURL(new Blob([data], { type: 'application/pdf' }))
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', `vscan-report-${route.params.id}.pdf`)
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
  } catch (e) {
    alert(e.response?.data?.error || 'Failed to download PDF report')
  } finally {
    pdfLoading.value = false
  }
}

async function downloadSARIF() {
  sarifLoading.value = true
  try {
    const { data } = await exportSARIF(route.params.id)
    const url = window.URL.createObjectURL(new Blob([data], { type: 'application/sarif+json' }))
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', `vscan-report-${route.params.id}.sarif`)
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
  } catch (e) {
    alert(e.response?.data?.error || 'Failed to download SARIF report')
  } finally {
    sarifLoading.value = false
  }
}

async function downloadCSV() {
  csvLoading.value = true
  try {
    const { data } = await exportCSV(route.params.id)
    const url = window.URL.createObjectURL(new Blob([data], { type: 'text/csv' }))
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', `vscan-report-${route.params.id}.csv`)
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
  } catch (e) {
    alert(e.response?.data?.error || 'Failed to download CSV report')
  } finally {
    csvLoading.value = false
  }
}

function getUpgradeCommand(suggestion) {
  const lib = suggestion.library.toLowerCase()
  if (lib === 'wordpress' || lib === 'elementor') {
    return `wp core update  # Update to ${suggestion.safe_version}`
  }
  return `npm install ${lib}@${suggestion.safe_version}`
}

function copyUpgradeCommand(suggestion) {
  const cmd = getUpgradeCommand(suggestion)
  navigator.clipboard.writeText(cmd).then(() => {
    copiedUpgrade.value = suggestion.library
    setTimeout(() => { copiedUpgrade.value = null }, 2000)
  }).catch(() => {})
}

function getUpgradeSeverityColor(severity) {
  const colors = {
    critical: 'bg-red-100 text-red-700 border-red-200',
    high: 'bg-orange-100 text-orange-700 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    low: 'bg-blue-100 text-blue-700 border-blue-200',
  }
  return colors[severity] || 'bg-gray-100 text-gray-700 border-gray-200'
}

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
  hosting: 'Hosting Quality',
  content: 'Content Optimization',
  advanced_security: 'Advanced Security',
  malware: 'Malware & Threats',
  threat_intel: 'Threat Intelligence',
  seo: 'SEO & Technical Health',
  third_party: 'Third-Party Scripts',
  js_libraries: 'JavaScript Libraries',
  wordpress: 'WordPress Security',
  xss: 'XSS Vulnerabilities',
  secrets: 'Secrets Detection',
  subdomains: 'Subdomain Discovery',
  tech_stack: 'Technology Detection',
  sqli: 'SQL Injection',
  ports: 'Port Scanner',
  open_redirect: 'Open Redirect',
  ssrf: 'SSRF Detection',
  email_security: 'Email Security',
  waf: 'WAF Detection',
  zone_transfer: 'DNS Zone Transfer',
  data_leak: 'Data Leak Detection',
  backup_files: 'Backup & Sensitive Files',
  cms_cve: 'CMS CVE Matching',
  js_secrets: 'JavaScript File Secrets',
  wp_deep: 'WordPress Deep Security',
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
  http_methods: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
  dns: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9',
  mixed_content: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
  info_disclosure: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
  hosting: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01',
  content: 'M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z',
  advanced_security: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
  malware: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
  seo: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01',
  third_party: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1',
  js_libraries: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',
  threat_intel: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
  wordpress: 'M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm0 1.5c4.694 0 8.5 3.806 8.5 8.5s-3.806 8.5-8.5 8.5S3.5 16.694 3.5 12 7.306 3.5 12 3.5zM6 12l2.5 7 2-5.5L13 19l2.5-7h2.5',
  xss: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
  secrets: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
  subdomains: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
  tech_stack: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',
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

function toggleOwasp(id) {
  expandedOwasp.value = { ...expandedOwasp.value, [id]: !expandedOwasp.value[id] }
}

function getComplianceColor(pct) {
  if (pct >= 100) return 'bg-green-500'
  if (pct >= 50) return 'bg-yellow-500'
  return 'bg-red-500'
}

function getComplianceTextColor(pct) {
  if (pct >= 100) return 'text-green-600'
  if (pct >= 50) return 'text-yellow-600'
  return 'text-red-600'
}

async function runAIAnalysis() {
  aiLoading.value = true
  showAI.value = true
  try {
    // First trigger the analysis
    await analyzeResult(route.params.id)
    // Then poll for the result (analysis runs async on server)
    let attempts = 0
    const maxAttempts = 60 // 2 minutes max
    const poll = async () => {
      attempts++
      try {
        const { data } = await getAIAnalysis(route.params.id)
        if (data && data.status === 'completed' && data.analysis) {
          aiAnalysis.value = data
          aiLoading.value = false
          return
        }
      } catch { /* still pending */ }
      if (attempts < maxAttempts && aiLoading.value) {
        setTimeout(poll, 2000)
      } else {
        aiLoading.value = false
      }
    }
    setTimeout(poll, 3000) // Wait 3s then start polling
  } catch (e) {
    alert(e.response?.data?.error || 'AI analysis failed. Check AI settings.')
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

// --- Severity Filter (Feature 2) ---
const severityFilter = ref('all')

// Flatten all checks from all categories for counting
const allChecks = computed(() => {
  const checks = []
  for (const catKey of Object.keys(categories.value)) {
    checks.push(...categories.value[catKey])
  }
  return checks
})

const criticalCount = computed(() => allChecks.value.filter(c => c.severity === 'critical').length)
const highCount = computed(() => allChecks.value.filter(c => c.severity === 'high').length)
const mediumCount = computed(() => allChecks.value.filter(c => c.severity === 'medium').length)

function filterChecksBySeverity(checks) {
  if (severityFilter.value === 'all') return checks
  if (severityFilter.value === 'fail') return checks.filter(c => c.status === 'fail')
  return checks.filter(c => c.severity === severityFilter.value)
}

// Remediation
const serverTypes = [
  { key: 'cloudflare', label: 'Cloudflare' },
  { key: 'apache', label: 'Apache' },
  { key: 'nginx', label: 'Nginx' },
  { key: 'litespeed', label: 'LiteSpeed' },
  { key: 'plesk', label: 'Plesk' },
  { key: 'cpanel', label: 'cPanel' },
  { key: 'wordpress', label: 'WordPress' },
]

async function loadRemediation(checkName) {
  remediationCheckName.value = checkName
  remediationLoading.value = true
  showRemediation.value = true
  remediationGuide.value = null
  try {
    const { data } = await getRemediationGuide(checkName)
    remediationGuide.value = data
    // Select first available server type
    const availableKeys = Object.keys(data.guides || {})
    if (availableKeys.length && !availableKeys.includes(activeServerType.value)) {
      activeServerType.value = availableKeys[0]
    }
  } catch {
    remediationGuide.value = null
  } finally {
    remediationLoading.value = false
  }
}

function closeRemediation() {
  showRemediation.value = false
  remediationGuide.value = null
}

function copyCodeBlock(text) {
  navigator.clipboard.writeText(text).then(() => {
    // Brief visual feedback is handled by the button text change
  }).catch(() => {
    // Fallback for older browsers
    const textarea = document.createElement('textarea')
    textarea.value = text
    document.body.appendChild(textarea)
    textarea.select()
    document.execCommand('copy')
    document.body.removeChild(textarea)
  })
}

function getPriorityColor(priority) {
  const colors = {
    critical: 'bg-red-100 text-red-700 border-red-200',
    high: 'bg-orange-100 text-orange-700 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    low: 'bg-blue-100 text-blue-700 border-blue-200',
  }
  return colors[priority] || 'bg-gray-100 text-gray-700 border-gray-200'
}

function getConfidenceClass(confidence) {
  if (confidence >= 90) return 'bg-green-100 text-green-700'
  if (confidence >= 70) return 'bg-yellow-100 text-yellow-700'
  return 'bg-orange-100 text-orange-700'
}

// CVSS badge color
function getCVSSClass(rating) {
  const classes = {
    Critical: 'bg-red-100 text-red-800 border border-red-300',
    High: 'bg-orange-100 text-orange-800 border border-orange-300',
    Medium: 'bg-yellow-100 text-yellow-800 border border-yellow-300',
    Low: 'bg-blue-100 text-blue-800 border border-blue-300',
    None: 'bg-gray-100 text-gray-600 border border-gray-300',
  }
  return classes[rating] || 'bg-gray-100 text-gray-600 border border-gray-300'
}

// --- Issue Creation (GitHub / Jira) ---
const showIssueModal = ref(false)
const issueType = ref('') // 'github' or 'jira'
const issueCheckId = ref(null)
const issueCheckName = ref('')
const issueLoading = ref(false)
const issueSuccess = ref('')
const issueError = ref('')

const issueForm = ref({
  repo_owner: '',
  repo_name: '',
  token: '',
  jira_url: '',
  project_key: '',
  email: '',
})

function openIssueModal(type, check) {
  issueType.value = type
  issueCheckId.value = check.ID
  issueCheckName.value = check.check_name
  issueSuccess.value = ''
  issueError.value = ''
  showIssueModal.value = true
}

function closeIssueModal() {
  showIssueModal.value = false
  issueType.value = ''
  issueCheckId.value = null
  issueCheckName.value = ''
  issueSuccess.value = ''
  issueError.value = ''
}

async function submitIssue() {
  issueLoading.value = true
  issueError.value = ''
  issueSuccess.value = ''
  try {
    if (issueType.value === 'github') {
      const { data } = await createGitHubIssue({
        check_id: issueCheckId.value,
        repo_owner: issueForm.value.repo_owner,
        repo_name: issueForm.value.repo_name,
        token: issueForm.value.token,
      })
      issueSuccess.value = data.issue_url
    } else {
      const { data } = await createJiraIssue({
        check_id: issueCheckId.value,
        jira_url: issueForm.value.jira_url,
        project_key: issueForm.value.project_key,
        token: issueForm.value.token,
        email: issueForm.value.email,
      })
      issueSuccess.value = data.issue_url
    }
  } catch (e) {
    issueError.value = e.response?.data?.error || 'Failed to create issue'
  } finally {
    issueLoading.value = false
  }
}

onMounted(async () => {
  try {
    const { data } = await getScanResult(route.params.id)
    result.value = data.result
    categories.value = data.categories
    const cats = Object.keys(data.categories)
    if (cats.length) activeCategory.value = cats[0]
    await loadExistingAnalysis()
    // Load score history
    if (data.result.scan_target_id) {
      historyLoading.value = true
      try {
        const histRes = await getScoreHistory(data.result.scan_target_id)
        scoreHistory.value = histRes.data || []
      } catch { /* no history available */ }
      historyLoading.value = false
    }
    // Load compliance report
    complianceLoading.value = true
    try {
      const compRes = await getComplianceReport(route.params.id)
      compliance.value = compRes.data || null
    } catch { /* no compliance data available */ }
    complianceLoading.value = false
    // Load upgrade suggestions
    upgradesLoading.value = true
    try {
      const upgRes = await getUpgradeSuggestions(route.params.id)
      upgradeSuggestions.value = upgRes.data || []
    } catch { /* no upgrade data available */ }
    upgradesLoading.value = false

    // Load fix priority
    fixPriorityLoading.value = true
    try {
      const fpRes = await getFixPriority(route.params.id)
      fixPriority.value = fpRes.data
    } catch { /* ignore */ }
    fixPriorityLoading.value = false

    // Load timeline comparison
    if (result.value?.scan_target_id) {
      timelineLoading.value = true
      try {
        const tlRes = await getTimelineComparison(result.value.scan_target_id)
        timeline.value = tlRes.data
      } catch { /* ignore */ }
      timelineLoading.value = false
    }
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
            <button @click="downloadPDF" :disabled="pdfLoading"
              class="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 flex items-center gap-2 text-sm">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
              </svg>
              {{ pdfLoading ? 'Generating...' : 'Download PDF' }}
            </button>
            <button @click="downloadSARIF" :disabled="sarifLoading"
              class="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-800 disabled:opacity-50 flex items-center gap-2 text-sm">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
              </svg>
              {{ sarifLoading ? 'Exporting...' : 'SARIF Export' }}
            </button>
            <button @click="downloadCSV" :disabled="csvLoading"
              class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 flex items-center gap-2 text-sm">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/>
              </svg>
              {{ csvLoading ? 'Exporting...' : 'CSV Export' }}
            </button>
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

      <!-- Score History -->
      <div v-if="historyChartData" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div class="flex items-center gap-2 mb-4">
          <svg class="w-6 h-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
          </svg>
          <h3 class="text-lg font-semibold text-gray-900">Score History</h3>
          <span class="text-xs text-gray-500">({{ scoreHistory.length }} scans)</span>
        </div>
        <div style="height: 250px;">
          <Line :data="historyChartData" :options="historyChartOptions" />
        </div>
      </div>

      <!-- OWASP Top 10 Compliance -->
      <div v-if="compliance && compliance.owasp_categories && compliance.owasp_categories.length" class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 mb-6">
        <div class="flex items-center gap-3 mb-6">
          <svg class="w-7 h-7 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
          <div>
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">OWASP Top 10 Compliance</h3>
            <p class="text-sm text-gray-500 dark:text-gray-400">{{ compliance.total_passed }}/{{ compliance.total_checks }} checks passed</p>
          </div>
          <!-- Circular Gauge -->
          <div class="ms-auto flex items-center gap-4">
            <div class="relative w-20 h-20">
              <svg class="w-20 h-20 -rotate-90" viewBox="0 0 36 36">
                <path class="text-gray-200 dark:text-slate-700" stroke="currentColor" stroke-width="3" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
                <path :class="getComplianceColor(compliance.overall_compliance).replace('bg-', 'text-')" stroke="currentColor" stroke-width="3" fill="none" stroke-linecap="round" :stroke-dasharray="`${compliance.overall_compliance}, 100`" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
              </svg>
              <span :class="['absolute inset-0 flex items-center justify-center text-sm font-bold', getComplianceTextColor(compliance.overall_compliance)]">
                {{ Math.round(compliance.overall_compliance) }}%
              </span>
            </div>
          </div>
        </div>

        <!-- OWASP Category Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div v-for="cat in compliance.owasp_categories" :key="cat.id" class="border border-gray-200 dark:border-slate-700 rounded-xl overflow-hidden">
            <button @click="toggleOwasp(cat.id)" class="w-full p-4 text-start hover:bg-gray-50 dark:hover:bg-slate-800 transition-colors">
              <div class="flex items-center justify-between mb-2">
                <span class="text-xs font-mono font-bold text-indigo-600 dark:text-indigo-400">{{ cat.id }}</span>
                <span :class="['text-xs font-medium px-2 py-0.5 rounded-full', cat.compliance >= 100 ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' : cat.compliance >= 50 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400']">
                  {{ cat.passed_checks }}/{{ cat.total_checks }} passed
                </span>
              </div>
              <p class="text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">{{ cat.name }}</p>
              <div class="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-2.5">
                <div :class="['h-2.5 rounded-full transition-all', getComplianceColor(cat.compliance)]" :style="{ width: cat.compliance + '%' }"></div>
              </div>
              <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">{{ Math.round(cat.compliance) }}% compliant</p>
            </button>
            <!-- Expanded checks -->
            <div v-if="expandedOwasp[cat.id]" class="border-t border-gray-200 dark:border-slate-700 bg-gray-50 dark:bg-slate-800/50 p-3 space-y-2">
              <div v-for="ch in cat.checks" :key="ch.name" class="flex items-center justify-between text-sm">
                <div class="flex items-center gap-2">
                  <span :class="['w-2 h-2 rounded-full', ch.status === 'pass' ? 'bg-green-500' : ch.status === 'fail' ? 'bg-red-500' : 'bg-yellow-500']"></span>
                  <span class="text-gray-700 dark:text-gray-300">{{ ch.name }}</span>
                </div>
                <span :class="['text-xs font-medium', ch.status === 'pass' ? 'text-green-600' : ch.status === 'fail' ? 'text-red-600' : 'text-yellow-600']">{{ ch.status }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div v-else-if="complianceLoading" class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 mb-6 flex justify-center">
        <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>

      <!-- Smart Upgrade Suggestions -->
      <div v-if="upgradeSuggestions.length" class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 mb-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="p-2 bg-amber-100 dark:bg-amber-900/30 rounded-lg">
            <svg class="w-6 h-6 text-amber-600 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
          </div>
          <div>
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Smart Upgrade Suggestions</h3>
            <p class="text-sm text-gray-500 dark:text-gray-400">{{ upgradeSuggestions.length }} libraries need attention</p>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div v-for="suggestion in upgradeSuggestions" :key="suggestion.library"
            class="border border-gray-200 dark:border-slate-700 rounded-xl p-4 hover:shadow-md transition-shadow">
            <!-- Header: Library name + severity badge -->
            <div class="flex items-center justify-between mb-3">
              <h4 class="font-semibold text-gray-900 dark:text-white text-base">{{ suggestion.library }}</h4>
              <span :class="['px-2.5 py-0.5 rounded-full text-xs font-semibold border', getUpgradeSeverityColor(suggestion.severity)]">
                {{ suggestion.severity.toUpperCase() }}
              </span>
            </div>

            <!-- Version info: current -> safe -->
            <div class="flex items-center gap-2 mb-3 text-sm">
              <span class="px-2 py-1 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 rounded font-mono text-xs">
                {{ suggestion.current_version || 'detected' }}
              </span>
              <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
              </svg>
              <span class="px-2 py-1 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 rounded font-mono text-xs">
                {{ suggestion.safe_version }}
              </span>
              <span v-if="suggestion.latest_version !== suggestion.safe_version" class="text-xs text-gray-400 dark:text-gray-500">
                (latest: {{ suggestion.latest_version }})
              </span>
            </div>

            <!-- Description -->
            <p class="text-sm text-gray-600 dark:text-gray-400 mb-3">{{ suggestion.description }}</p>

            <!-- CVE badges -->
            <div v-if="suggestion.cves && suggestion.cves.length" class="flex flex-wrap gap-1.5 mb-3">
              <span v-for="cve in suggestion.cves" :key="cve"
                class="px-2 py-0.5 bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-400 rounded text-xs font-mono">
                {{ cve }}
              </span>
            </div>

            <!-- Breaking changes warning -->
            <div v-if="suggestion.breaking" class="flex items-center gap-2 mb-3 px-3 py-2 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
              <svg class="w-4 h-4 text-amber-600 dark:text-amber-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
              </svg>
              <span class="text-xs text-amber-700 dark:text-amber-400 font-medium">Potential breaking changes - test thoroughly</span>
            </div>

            <!-- Copy upgrade command -->
            <button @click="copyUpgradeCommand(suggestion)"
              class="w-full flex items-center justify-center gap-2 px-3 py-2 bg-gray-50 dark:bg-slate-800 border border-gray-200 dark:border-slate-600 rounded-lg text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 transition-colors font-mono">
              <svg v-if="copiedUpgrade !== suggestion.library" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
              </svg>
              <svg v-else class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
              </svg>
              <span v-if="copiedUpgrade === suggestion.library" class="text-green-600">Copied!</span>
              <span v-else>{{ getUpgradeCommand(suggestion) }}</span>
            </button>
          </div>
        </div>
      </div>
      <div v-else-if="upgradesLoading" class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 mb-6 flex justify-center">
        <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-amber-600"></div>
      </div>

      <!-- Fix Priority Recommendations -->
      <div v-if="fixPriority && fixPriority.recommendations?.length" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div class="flex items-center gap-3 mb-4">
          <div class="p-2 bg-red-100 rounded-lg">
            <svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
            </svg>
          </div>
          <div>
            <h3 class="text-lg font-semibold text-gray-900">Fix Priority</h3>
            <p class="text-sm text-gray-500">{{ fixPriority.total_issues }} issues | {{ fixPriority.quick_wins }} quick wins</p>
          </div>
        </div>
        <div class="space-y-2">
          <div v-for="rec in fixPriority.recommendations.slice(0, 10)" :key="rec.priority"
            class="flex items-center gap-3 p-3 border border-gray-100 rounded-lg hover:bg-gray-50">
            <span class="flex-shrink-0 w-7 h-7 flex items-center justify-center rounded-full text-white text-xs font-bold"
              :class="rec.priority <= 3 ? 'bg-red-500' : rec.priority <= 6 ? 'bg-orange-500' : 'bg-yellow-500'">
              {{ rec.priority }}
            </span>
            <div class="flex-1 min-w-0">
              <p class="text-sm font-medium text-gray-900 truncate">{{ rec.check_name }}</p>
              <p class="text-xs text-gray-500">{{ rec.recommendation }}</p>
            </div>
            <div class="flex items-center gap-2 flex-shrink-0">
              <span :class="rec.effort === 'easy' ? 'bg-green-100 text-green-700' : rec.effort === 'hard' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'"
                class="px-2 py-0.5 rounded text-xs font-medium">{{ rec.effort }}</span>
              <span class="text-xs text-gray-400">{{ rec.category }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Timeline Comparison -->
      <div v-if="timeline && timeline.timeline?.length > 1" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div class="flex items-center gap-3 mb-4">
          <div class="p-2 bg-blue-100 rounded-lg">
            <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
            </svg>
          </div>
          <div>
            <h3 class="text-lg font-semibold text-gray-900">Score Timeline</h3>
            <p class="text-sm text-gray-500">{{ timeline.total_scans }} scans over time</p>
          </div>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
          <div v-for="(entry, idx) in timeline.timeline" :key="idx"
            class="text-center p-3 border rounded-lg" :class="idx === timeline.timeline.length - 1 ? 'border-indigo-300 bg-indigo-50' : 'border-gray-200'">
            <p class="text-2xl font-bold" :class="entry.score >= 800 ? 'text-green-600' : entry.score >= 500 ? 'text-yellow-600' : 'text-red-600'">{{ entry.grade }}</p>
            <p class="text-sm font-medium text-gray-700">{{ Math.round(entry.score) }}</p>
            <p class="text-xs text-gray-400 mt-1">{{ entry.scanned_at?.split(' ')[0] }}</p>
            <div class="flex justify-center gap-1 mt-1">
              <span class="text-xs text-red-500">{{ entry.fail_count }}F</span>
              <span class="text-xs text-yellow-500">{{ entry.warn_count }}W</span>
              <span class="text-xs text-green-500">{{ entry.pass_count }}P</span>
            </div>
          </div>
        </div>
        <!-- Category changes -->
        <div v-if="timeline.category_comparison?.length" class="mt-4 border-t pt-4">
          <h4 class="text-sm font-semibold text-gray-700 mb-2">Category Changes (First vs Last scan)</h4>
          <div class="flex flex-wrap gap-2">
            <span v-for="cat in timeline.category_comparison" :key="cat.category"
              :class="cat.status === 'improved' ? 'bg-green-100 text-green-700' : cat.status === 'declined' ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-600'"
              class="px-2 py-1 rounded text-xs">
              {{ cat.category }}: {{ cat.change > 0 ? '+' : '' }}{{ Math.round(cat.change) }}
            </span>
          </div>
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

          <!-- Severity Filter -->
          <div class="flex flex-wrap gap-2 mb-4">
            <button @click="severityFilter = 'all'" :class="severityFilter === 'all' ? 'bg-indigo-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'" class="px-3 py-1.5 rounded-lg text-sm transition-colors">
              All ({{ allChecks.length }})
            </button>
            <button @click="severityFilter = 'critical'" :class="severityFilter === 'critical' ? 'bg-red-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'" class="px-3 py-1.5 rounded-lg text-sm transition-colors">
              Critical ({{ criticalCount }})
            </button>
            <button @click="severityFilter = 'high'" :class="severityFilter === 'high' ? 'bg-orange-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'" class="px-3 py-1.5 rounded-lg text-sm transition-colors">
              High ({{ highCount }})
            </button>
            <button @click="severityFilter = 'medium'" :class="severityFilter === 'medium' ? 'bg-yellow-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'" class="px-3 py-1.5 rounded-lg text-sm transition-colors">
              Medium ({{ mediumCount }})
            </button>
            <button @click="severityFilter = 'fail'" :class="severityFilter === 'fail' ? 'bg-red-500 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'" class="px-3 py-1.5 rounded-lg text-sm transition-colors">
              Failed Only
            </button>
          </div>

          <!-- Check Details -->
          <div v-if="activeCategory && categories[activeCategory]" class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            <div class="p-4 bg-gray-50 border-b border-gray-200">
              <h3 class="text-lg font-semibold text-gray-900">
                {{ categoryLabels[activeCategory] || activeCategory }} - Detailed Checks
              </h3>
            </div>
            <div class="divide-y divide-gray-100">
              <div v-for="check in filterChecksBySeverity(categories[activeCategory])" :key="check.ID" class="p-4">
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
                    <span v-if="check.owasp" class="px-2 py-0.5 bg-purple-100 text-purple-700 rounded text-xs font-mono">{{ check.owasp }}</span>
                    <span v-if="check.cwe" class="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs font-mono">{{ check.cwe }}</span>
                    <span v-if="check.cvss_score > 0" :class="[getCVSSClass(check.cvss_rating), 'px-2 py-0.5 rounded text-xs font-mono']">
                      CVSS {{ check.cvss_score }}
                    </span>
                    <span v-if="check.confidence" :class="[getConfidenceClass(check.confidence), 'px-2 py-0.5 rounded text-xs']">
                      {{ check.confidence }}% confidence
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

                <!-- Subdomain Individual Scan Details -->
                <div v-if="check.details && check.check_name.startsWith('Subdomain Scan:')" class="mt-2 bg-gray-50 rounded-lg p-3 text-sm">
                  <div class="flex items-center gap-2 mb-2">
                    <span class="font-semibold text-gray-800">{{ parseDetails(check.details).subdomain }}</span>
                    <span v-if="parseDetails(check.details).scheme" :class="parseDetails(check.details).scheme === 'https' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'" class="px-2 py-0.5 rounded text-xs font-medium">
                      {{ parseDetails(check.details).scheme?.toUpperCase() }}
                    </span>
                    <span v-if="parseDetails(check.details).status_code" class="bg-blue-100 text-blue-700 px-2 py-0.5 rounded text-xs font-medium">
                      HTTP {{ parseDetails(check.details).status_code }}
                    </span>
                    <span v-if="parseDetails(check.details).server" class="bg-gray-200 text-gray-700 px-2 py-0.5 rounded text-xs">
                      {{ parseDetails(check.details).server }}
                    </span>
                    <span v-if="parseDetails(check.details).is_cloudflare" class="bg-orange-100 text-orange-700 px-2 py-0.5 rounded text-xs font-medium">
                      Cloudflare
                    </span>
                  </div>
                  <!-- IPs -->
                  <div v-if="parseDetails(check.details).ips" class="flex gap-1 mb-2 flex-wrap">
                    <span class="text-xs text-gray-500">IPs:</span>
                    <span v-for="ip in parseDetails(check.details).ips" :key="ip" class="bg-gray-200 text-gray-700 px-1.5 py-0.5 rounded text-xs font-mono">{{ ip }}</span>
                  </div>
                  <!-- TLS Info -->
                  <div v-if="parseDetails(check.details).tls_issuer" class="flex gap-2 mb-2 text-xs">
                    <span :class="parseDetails(check.details).tls_valid ? 'text-green-700' : 'text-red-700'" class="flex items-center gap-1">
                      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="parseDetails(check.details).tls_valid ? 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' : 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z'"/></svg>
                      TLS: {{ parseDetails(check.details).tls_issuer }}
                    </span>
                    <span class="text-gray-500">Expires: {{ parseDetails(check.details).tls_expires }}</span>
                  </div>
                  <!-- Issues -->
                  <div v-if="parseDetails(check.details).issues?.length" class="mb-2">
                    <p class="text-xs font-semibold text-red-700 mb-1">Issues ({{ parseDetails(check.details).issues_count }}):</p>
                    <ul class="space-y-0.5">
                      <li v-for="(issue, idx) in parseDetails(check.details).issues" :key="idx" class="flex items-start gap-1.5 text-red-700">
                        <svg class="w-3.5 h-3.5 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>
                        <span>{{ issue }}</span>
                      </li>
                    </ul>
                  </div>
                  <!-- Good findings -->
                  <div v-if="parseDetails(check.details).good?.length">
                    <p class="text-xs font-semibold text-green-700 mb-1">Passed ({{ parseDetails(check.details).good_count }}):</p>
                    <ul class="space-y-0.5">
                      <li v-for="(item, idx) in parseDetails(check.details).good" :key="idx" class="flex items-start gap-1.5 text-green-700">
                        <svg class="w-3.5 h-3.5 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                        <span>{{ item }}</span>
                      </li>
                    </ul>
                  </div>
                </div>

                <!-- Common Subdomain Enumeration — detailed table -->
                <div v-else-if="check.details && check.check_name === 'Common Subdomain Enumeration'" class="mt-2 bg-gray-50 rounded-lg p-3 text-sm">
                  <p class="font-semibold text-gray-800 mb-2">
                    {{ parseDetails(check.details).message }}
                  </p>
                  <div v-if="parseDetails(check.details).subdomains?.length" class="overflow-x-auto">
                    <table class="w-full text-xs border-collapse">
                      <thead>
                        <tr class="bg-gray-100 border-b border-gray-200">
                          <th class="text-right py-2 px-2 text-gray-600">#</th>
                          <th class="text-right py-2 px-2 text-gray-600">Subdomain</th>
                          <th class="text-center py-2 px-2 text-gray-600">HTTPS</th>
                          <th class="text-center py-2 px-2 text-gray-600">Cloudflare</th>
                          <th class="text-right py-2 px-2 text-gray-600">IP Addresses</th>
                          <th class="text-right py-2 px-2 text-gray-600">CNAME</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr v-for="(sub, i) in parseDetails(check.details).subdomains" :key="sub.subdomain" class="border-b border-gray-100 hover:bg-white">
                          <td class="py-2 px-2 text-gray-400">{{ i + 1 }}</td>
                          <td class="py-2 px-2 font-mono text-gray-800" dir="ltr">{{ sub.subdomain }}</td>
                          <td class="py-2 px-2 text-center">
                            <span v-if="sub.has_https" class="inline-block px-1.5 py-0.5 bg-green-100 text-green-700 rounded text-[10px] font-bold">HTTPS ✓</span>
                            <span v-else class="inline-block px-1.5 py-0.5 bg-red-100 text-red-700 rounded text-[10px] font-bold">HTTP ✗</span>
                          </td>
                          <td class="py-2 px-2 text-center">
                            <span v-if="sub.is_cloudflare" class="inline-block px-1.5 py-0.5 bg-orange-100 text-orange-700 rounded text-[10px] font-medium">CF</span>
                            <span v-else class="text-gray-300">—</span>
                          </td>
                          <td class="py-2 px-2 font-mono text-[10px] text-gray-600" dir="ltr">
                            <div v-if="sub.ips && sub.ips.length">
                              <span v-for="(ip, idx) in sub.ips.slice(0, 2)" :key="ip" class="inline-block mr-1 px-1 bg-gray-200 rounded">{{ ip }}</span>
                              <span v-if="sub.ips.length > 2" class="text-gray-400">+{{ sub.ips.length - 2 }}</span>
                            </div>
                          </td>
                          <td class="py-2 px-2 font-mono text-[10px] text-purple-700" dir="ltr">{{ sub.cname || '—' }}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                <!-- Subdomain Security Check — show with/without HTTPS lists -->
                <div v-else-if="check.details && check.check_name === 'Subdomain Security Check'" class="mt-2 bg-gray-50 rounded-lg p-3 text-sm">
                  <p class="font-semibold text-gray-800 mb-2">{{ parseDetails(check.details).message }}</p>
                  <div class="grid grid-cols-2 gap-3 mb-2 text-xs">
                    <div class="bg-green-50 rounded p-2 border border-green-200">
                      <p class="font-semibold text-green-700 mb-1">✓ HTTPS enabled ({{ parseDetails(check.details).https_count }})</p>
                      <ul class="space-y-0.5 text-green-800" dir="ltr">
                        <li v-for="h in parseDetails(check.details).with_https" :key="h" class="font-mono truncate">{{ h }}</li>
                      </ul>
                    </div>
                    <div class="bg-red-50 rounded p-2 border border-red-200">
                      <p class="font-semibold text-red-700 mb-1">✗ HTTPS missing ({{ (parseDetails(check.details).without_https || []).length }})</p>
                      <ul class="space-y-0.5 text-red-800" dir="ltr">
                        <li v-for="h in parseDetails(check.details).without_https" :key="h" class="font-mono truncate">{{ h }}</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <!-- Dangling DNS / Takeover — highlight risks -->
                <div v-else-if="check.details && check.check_name === 'Dangling DNS / Subdomain Takeover Risk'" class="mt-2 bg-gray-50 rounded-lg p-3 text-sm">
                  <p class="font-semibold text-gray-800 mb-2">{{ parseDetails(check.details).message }}</p>
                  <div v-if="parseDetails(check.details).potential_takeovers?.length" class="space-y-1 mb-2">
                    <p class="text-xs font-semibold text-red-700">⚠️ Potential Takeovers:</p>
                    <div v-for="t in parseDetails(check.details).potential_takeovers" :key="t.subdomain"
                      class="bg-red-50 border border-red-200 rounded p-2 text-xs" dir="ltr">
                      <div class="font-mono font-bold text-red-800">{{ t.subdomain }}</div>
                      <div class="text-red-600">CNAME → {{ t.cname }}</div>
                    </div>
                  </div>
                  <div v-if="parseDetails(check.details).cnames?.length" class="text-xs text-gray-600" dir="ltr">
                    <p class="font-semibold mb-1">External CNAMEs:</p>
                    <ul class="space-y-0.5">
                      <li v-for="c in parseDetails(check.details).cnames" :key="c" class="font-mono">{{ c }}</li>
                    </ul>
                  </div>
                </div>

                <!-- Raw Details (non-subdomain checks) -->
                <div v-else-if="check.details" class="mt-2 bg-gray-50 rounded-lg p-3 text-sm">
                  <p class="text-xs text-gray-400 mb-1">Technical Details:</p>
                  <div v-for="(value, key) in parseDetails(check.details)" :key="key" class="flex gap-2 py-0.5">
                    <span class="text-gray-500 min-w-[100px]">{{ key }}:</span>
                    <span class="text-gray-700">{{ typeof value === 'object' ? JSON.stringify(value) : value }}</span>
                  </div>
                </div>

                <!-- Fix This + Create Issue Buttons -->
                <div v-if="check.status === 'fail' || check.status === 'warn' || check.status === 'warning' || check.score < 800" class="mt-3 flex flex-wrap gap-2">
                  <button @click="loadRemediation(check.check_name)"
                    class="px-4 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors flex items-center gap-2 text-sm font-medium">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                    </svg>
                    Fix This
                  </button>
                  <!-- Create Issue dropdown -->
                  <div v-if="check.status === 'fail'" class="relative group">
                    <button class="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-800 transition-colors flex items-center gap-2 text-sm font-medium">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z"/>
                      </svg>
                      Create Issue
                      <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
                    </button>
                    <div class="absolute left-0 mt-1 w-48 bg-white border border-gray-200 rounded-lg shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-20">
                      <button @click="openIssueModal('github', check)" class="w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 rounded-t-lg flex items-center gap-2">
                        <svg class="w-4 h-4" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
                        GitHub Issue
                      </button>
                      <button @click="openIssueModal('jira', check)" class="w-full text-left px-4 py-2.5 text-sm text-gray-700 hover:bg-gray-50 rounded-b-lg flex items-center gap-2">
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M11.571 11.513H0a5.218 5.218 0 005.232 5.215h2.13v2.057A5.215 5.215 0 0012.575 24V12.518a1.005 1.005 0 00-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 005.215 5.214h2.129v2.058a5.218 5.218 0 005.215 5.214V6.758a1.001 1.001 0 00-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 005.215 5.215h2.129v2.057A5.215 5.215 0 0024 12.483V1.005A1.005 1.005 0 0023.013 0z"/></svg>
                        Jira Ticket
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create Issue Modal -->
    <Teleport to="body">
      <div v-if="showIssueModal" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/50" @click="closeIssueModal"></div>
        <div class="relative bg-white rounded-2xl shadow-2xl w-full max-w-md p-6 mx-4">
          <div class="flex items-center justify-between mb-5">
            <div class="flex items-center gap-3">
              <!-- GitHub icon -->
              <svg v-if="issueType === 'github'" class="w-6 h-6" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
              <!-- Jira icon -->
              <svg v-else class="w-6 h-6 text-blue-600" viewBox="0 0 24 24" fill="currentColor"><path d="M11.571 11.513H0a5.218 5.218 0 005.232 5.215h2.13v2.057A5.215 5.215 0 0012.575 24V12.518a1.005 1.005 0 00-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 005.215 5.214h2.129v2.058a5.218 5.218 0 005.215 5.214V6.758a1.001 1.001 0 00-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 005.215 5.215h2.129v2.057A5.215 5.215 0 0024 12.483V1.005A1.005 1.005 0 0023.013 0z"/></svg>
              <h3 class="text-lg font-bold text-gray-900">
                {{ issueType === 'github' ? 'Create GitHub Issue' : 'Create Jira Ticket' }}
              </h3>
            </div>
            <button @click="closeIssueModal" class="p-1 text-gray-400 hover:text-gray-600 rounded">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
          </div>

          <p class="text-sm text-gray-500 mb-4">Creating issue for: <strong>{{ issueCheckName }}</strong></p>

          <!-- Success -->
          <div v-if="issueSuccess" class="bg-green-50 border border-green-200 rounded-lg p-4 mb-4">
            <p class="text-sm text-green-700 font-medium mb-1">Issue created successfully!</p>
            <a :href="issueSuccess" target="_blank" class="text-sm text-indigo-600 hover:underline break-all">{{ issueSuccess }}</a>
          </div>

          <!-- Error -->
          <div v-if="issueError" class="bg-red-50 border border-red-200 rounded-lg p-3 mb-4">
            <p class="text-sm text-red-700">{{ issueError }}</p>
          </div>

          <!-- GitHub Form -->
          <form v-if="issueType === 'github' && !issueSuccess" @submit.prevent="submitIssue" class="space-y-3">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Repository Owner</label>
              <input v-model="issueForm.repo_owner" type="text" required placeholder="e.g., octocat"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Repository Name</label>
              <input v-model="issueForm.repo_name" type="text" required placeholder="e.g., my-project"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Personal Access Token</label>
              <PasswordInput v-model="issueForm.token" :required="true" placeholder="ghp_..."
                input-class="w-full px-3 py-2 pl-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm" />
              <p class="text-xs text-gray-400 mt-1">Needs "repo" scope</p>
            </div>
            <button type="submit" :disabled="issueLoading"
              class="w-full px-4 py-2.5 bg-gray-900 text-white rounded-lg hover:bg-gray-800 disabled:opacity-50 flex items-center justify-center gap-2 text-sm font-medium">
              <div v-if="issueLoading" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              {{ issueLoading ? 'Creating...' : 'Create GitHub Issue' }}
            </button>
          </form>

          <!-- Jira Form -->
          <form v-if="issueType === 'jira' && !issueSuccess" @submit.prevent="submitIssue" class="space-y-3">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Jira URL</label>
              <input v-model="issueForm.jira_url" type="url" required placeholder="https://company.atlassian.net"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Project Key</label>
              <input v-model="issueForm.project_key" type="text" required placeholder="e.g., SEC"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <input v-model="issueForm.email" type="email" required placeholder="user@company.com"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">API Token</label>
              <PasswordInput v-model="issueForm.token" :required="true" placeholder="Jira API token"
                input-class="w-full px-3 py-2 pl-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent text-sm" />
            </div>
            <button type="submit" :disabled="issueLoading"
              class="w-full px-4 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center gap-2 text-sm font-medium">
              <div v-if="issueLoading" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              {{ issueLoading ? 'Creating...' : 'Create Jira Ticket' }}
            </button>
          </form>

          <!-- Close button when success -->
          <button v-if="issueSuccess" @click="closeIssueModal"
            class="w-full mt-3 px-4 py-2.5 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 text-sm font-medium">
            Close
          </button>
        </div>
      </div>
    </Teleport>

    <!-- Remediation Slide-Out Panel -->
    <Teleport to="body">
      <div v-if="showRemediation" class="fixed inset-0 z-50 flex justify-end">
        <!-- Backdrop -->
        <div class="absolute inset-0 bg-black/50" @click="closeRemediation"></div>

        <!-- Panel -->
        <div class="relative w-full max-w-2xl bg-white shadow-2xl overflow-y-auto animate-slide-in-right">
          <!-- Header -->
          <div class="sticky top-0 bg-white border-b border-gray-200 p-6 z-10">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-3">
                <div class="p-2 bg-emerald-100 rounded-lg">
                  <svg class="w-6 h-6 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                  </svg>
                </div>
                <div>
                  <h2 class="text-lg font-bold text-gray-900">Remediation Guide</h2>
                  <p class="text-sm text-gray-500">{{ remediationCheckName }}</p>
                </div>
              </div>
              <button @click="closeRemediation" class="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
              </button>
            </div>

            <!-- Priority & Time badges -->
            <div v-if="remediationGuide" class="flex items-center gap-3 mt-3">
              <span :class="['px-3 py-1 rounded-full text-xs font-semibold border', getPriorityColor(remediationGuide.priority)]">
                {{ remediationGuide.priority?.toUpperCase() }} PRIORITY
              </span>
              <span class="px-3 py-1 rounded-full text-xs font-semibold bg-indigo-100 text-indigo-700 border border-indigo-200">
                ~ {{ remediationGuide.time_estimate }}
              </span>
            </div>
          </div>

          <!-- Loading -->
          <div v-if="remediationLoading" class="flex items-center justify-center py-20">
            <div class="animate-spin rounded-full h-10 w-10 border-b-2 border-emerald-600"></div>
          </div>

          <!-- No Guide Found -->
          <div v-else-if="!remediationGuide" class="p-6 text-center">
            <svg class="w-16 h-16 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            <p class="text-gray-500 text-lg">No remediation guide available for this check yet.</p>
            <p class="text-gray-400 text-sm mt-2">Use the AI Analysis feature for custom recommendations.</p>
          </div>

          <!-- Guide Content -->
          <div v-else class="p-6">
            <!-- Description -->
            <div class="mb-6">
              <h3 class="font-semibold text-gray-900 mb-2">{{ remediationGuide.title }}</h3>
              <p class="text-sm text-gray-600">{{ remediationGuide.description }}</p>
            </div>

            <!-- Server Type Tabs -->
            <div class="mb-6">
              <p class="text-sm font-medium text-gray-700 mb-2">Select your server type:</p>
              <div class="flex flex-wrap gap-2">
                <button
                  v-for="st in serverTypes.filter(s => remediationGuide.guides && remediationGuide.guides[s.key])"
                  :key="st.key"
                  @click="activeServerType = st.key"
                  :class="[
                    'px-4 py-2 rounded-lg text-sm font-medium transition-all border',
                    activeServerType === st.key
                      ? 'bg-emerald-600 text-white border-emerald-600 shadow-sm'
                      : 'bg-white text-gray-700 border-gray-200 hover:border-emerald-300 hover:bg-emerald-50'
                  ]"
                >
                  {{ st.label }}
                </button>
              </div>
            </div>

            <!-- Instructions -->
            <div v-if="remediationGuide.guides && remediationGuide.guides[activeServerType]" class="prose prose-sm max-w-none">
              <div class="bg-gray-50 rounded-xl border border-gray-200 p-5">
                <div v-for="(block, idx) in remediationGuide.guides[activeServerType].split('```')" :key="idx">
                  <!-- Code block (odd indices after split on ```) -->
                  <div v-if="idx % 2 === 1" class="my-3">
                    <div class="flex items-center justify-between bg-gray-800 rounded-t-lg px-4 py-2">
                      <span class="text-xs text-gray-400 font-mono">{{ block.split('\n')[0] || 'code' }}</span>
                      <button @click="copyCodeBlock(block.split('\n').slice(1).join('\n').trim())"
                        class="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 transition-colors">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                        </svg>
                        Copy
                      </button>
                    </div>
                    <pre class="bg-gray-900 text-gray-100 p-4 rounded-b-lg overflow-x-auto text-xs leading-relaxed"><code>{{ block.split('\n').slice(1).join('\n').trim() }}</code></pre>
                  </div>
                  <!-- Regular text (even indices) -->
                  <div v-else class="text-sm text-gray-700 leading-relaxed whitespace-pre-wrap">{{ block }}</div>
                </div>
              </div>
            </div>

            <div v-else class="text-center py-10 text-gray-500">
              <p>Select a server type above to see the remediation guide.</p>
            </div>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
@keyframes slideInRight {
  from {
    transform: translateX(100%);
  }
  to {
    transform: translateX(0);
  }
}
.animate-slide-in-right {
  animation: slideInRight 0.3s ease-out;
}
</style>
