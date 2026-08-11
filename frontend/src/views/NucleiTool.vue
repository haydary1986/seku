<script setup>
import { ref, computed } from 'vue'
import { runNucleiTool } from '../api'

const target = ref('')
const tags = ref([])
const allTags = ['cve', 'default-login', 'exposure', 'misconfig', 'tech', 'ssl', 'xss', 'sqli', 'lfi', 'rce', 'takeover', 'wordpress', 'panel', 'config', 'backup', 'token']
const allSeverities = ['critical', 'high', 'medium', 'low', 'info']
const severities = ref(['critical', 'high', 'medium'])
const loading = ref(false)
const error = ref('')
const results = ref([])
const scanned = ref(false)
const scannedTarget = ref('')

const summary = computed(() => results.value.find((r) => r.check_name === 'Nuclei Template Scan'))
const findings = computed(() =>
  results.value.filter((r) => (r.check_name || '').startsWith('Nuclei:'))
)

function details(r) {
  try {
    return JSON.parse(r.details || '{}')
  } catch {
    return {}
  }
}

const sevClass = (s) =>
  ({
    critical: 'bg-red-100 text-red-700 border-red-200',
    high: 'bg-orange-100 text-orange-700 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    low: 'bg-blue-100 text-blue-700 border-blue-200',
    info: 'bg-gray-100 text-gray-600 border-gray-200',
  })[s] || 'bg-gray-100 text-gray-600 border-gray-200'

function toggleSeverity(s) {
  const i = severities.value.indexOf(s)
  if (i >= 0) severities.value.splice(i, 1)
  else severities.value.push(s)
}

function toggleTag(t) {
  const i = tags.value.indexOf(t)
  if (i >= 0) tags.value.splice(i, 1)
  else tags.value.push(t)
}

async function run() {
  const t = target.value.trim()
  if (!t) return
  loading.value = true
  error.value = ''
  results.value = []
  scanned.value = false
  try {
    const { data } = await runNucleiTool({
      target: t,
      severity: severities.value.join(','),
      tags: tags.value.join(','),
    })
    results.value = data.results || []
    scannedTarget.value = data.target || t
    scanned.value = true
  } catch (e) {
    error.value = e.response?.data?.error || 'Scan failed. Check the target and try again.'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="max-w-4xl mx-auto p-4 md:p-6">
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-gray-900 flex items-center gap-2">
        <svg class="w-6 h-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
        Nuclei Scan
      </h1>
      <p class="text-sm text-gray-500 mt-1">
        Run ProjectDiscovery nuclei against a single URL or IP (CVEs, exposures, misconfigurations, default logins).
        Only scan systems you are authorized to test.
      </p>
    </div>

    <!-- Form -->
    <div class="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-6">
      <label class="block text-sm font-medium text-gray-700 mb-1">Target (URL or IP)</label>
      <div class="flex flex-col sm:flex-row gap-2">
        <input
          v-model="target"
          type="text"
          placeholder="https://example.com  or  185.65.62.222"
          class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none"
          @keyup.enter="run"
        />
        <button
          @click="run"
          :disabled="loading || !target.trim()"
          class="px-5 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 whitespace-nowrap"
        >
          <div v-if="loading" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
          {{ loading ? 'Scanning…' : 'Run Scan' }}
        </button>
      </div>

      <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Severity</label>
          <div class="flex flex-wrap gap-1.5">
            <button
              v-for="s in allSeverities"
              :key="s"
              type="button"
              @click="toggleSeverity(s)"
              :class="[
                'px-2.5 py-1 rounded-full text-xs border capitalize transition',
                severities.includes(s) ? sevClass(s) + ' font-semibold' : 'bg-gray-50 text-gray-400 border-gray-200',
              ]"
            >
              {{ s }}
            </button>
          </div>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Tags (optional)</label>
          <div class="flex flex-wrap gap-1.5">
            <button
              v-for="tg in allTags"
              :key="tg"
              type="button"
              @click="toggleTag(tg)"
              :class="[
                'px-2.5 py-1 rounded-full text-xs border transition',
                tags.includes(tg)
                  ? 'bg-indigo-100 text-indigo-700 border-indigo-200 font-semibold'
                  : 'bg-gray-50 text-gray-500 border-gray-200 hover:border-indigo-300',
              ]"
            >
              {{ tg }}
            </button>
          </div>
          <p class="text-[11px] text-gray-400 mt-1">No tags selected = run all templates (slower but thorough).</p>
        </div>
      </div>
      <p class="text-xs text-gray-400 mt-3">Note: a full run can take a couple of minutes depending on the target.</p>
    </div>

    <!-- Error -->
    <div v-if="error" class="mb-6 rounded-lg bg-red-50 border border-red-200 text-red-700 px-4 py-3 text-sm">
      {{ error }}
    </div>

    <!-- Results -->
    <div v-if="scanned">
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-lg font-semibold text-gray-900">
          Results for <span class="text-indigo-600 break-all">{{ scannedTarget }}</span>
        </h2>
        <span class="text-sm text-gray-500">{{ findings.length }} finding(s)</span>
      </div>

      <div v-if="summary" class="mb-4 rounded-lg bg-gray-50 border border-gray-200 px-4 py-3 text-sm text-gray-700">
        {{ details(summary).message }}
      </div>

      <div v-if="findings.length === 0" class="rounded-xl border border-green-200 bg-green-50 px-4 py-6 text-center text-green-700">
        ✓ No nuclei templates matched this target for the selected severities.
      </div>

      <div v-else class="space-y-2">
        <div
          v-for="(f, i) in findings"
          :key="i"
          class="bg-white rounded-lg border border-gray-200 p-4 shadow-sm"
        >
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="font-medium text-gray-900">{{ f.check_name.replace(/^Nuclei:\s*/, '') }}</p>
              <p v-if="details(f).message" class="text-sm text-gray-500 mt-0.5">{{ details(f).message }}</p>
            </div>
            <span :class="['px-2 py-0.5 rounded-full text-xs border capitalize flex-shrink-0', sevClass(f.severity)]">
              {{ f.severity }}
            </span>
          </div>
          <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-400">
            <span v-if="details(f).template_id">template: <code class="text-gray-600">{{ details(f).template_id }}</code></span>
            <span v-if="details(f).matched_at" class="break-all">matched: <code class="text-gray-600">{{ details(f).matched_at }}</code></span>
            <span v-if="details(f).cvss_score">CVSS: <code class="text-gray-600">{{ details(f).cvss_score }}</code></span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
