<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { createTarget, startScan } from '../api'
import { useI18n } from '../i18n'

const { t } = useI18n()
const router = useRouter()

const scope = ref('all')      // 'all' | 'one'
const domain = ref('')
const authorized = ref(false)
const loading = ref(false)
const error = ref('')

const tools = ref({
  enable_nuclei_dast: true,  // SSTI/LFI/XXE/CMDi/SQLi fuzzing
  enable_nuclei: true,       // CVE / exposure templates
  enable_dalfox: true,       // advanced XSS
  enable_oob: true,          // out-of-band SSRF
  enable_login: true,        // login brute / lockout / default creds
})

const toolList = [
  { key: 'enable_nuclei_dast', labelKey: 'vOffensive.toolDast' },
  { key: 'enable_nuclei', labelKey: 'vOffensive.toolNuclei' },
  { key: 'enable_dalfox', labelKey: 'vOffensive.toolDalfox' },
  { key: 'enable_oob', labelKey: 'vOffensive.toolOob' },
  { key: 'enable_login', labelKey: 'vOffensive.toolLogin' },
]

const canLaunch = computed(() =>
  authorized.value && !loading.value && (scope.value === 'all' || /\./.test(domain.value)),
)

function normalize(raw) {
  let u = (raw || '').trim()
  if (!u) return ''
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u
  return u
}

async function launch() {
  error.value = ''
  loading.value = true
  try {
    let targetIds = [] // empty = all of the admin's targets
    if (scope.value === 'one') {
      const url = normalize(domain.value)
      if (!url || !/\./.test(url)) { error.value = t('vOffensive.invalid'); loading.value = false; return }
      const { data: target } = await createTarget({ url, name: url, adhoc: true })
      targetIds = [target.ID || target.id]
    }
    const payload = { target_ids: targetIds, policy: 'deep', authorized: true, ...tools.value }
    await startScan(payload)
    router.push('/scans')
  } catch (e) {
    const code = e.response?.status
    if (code === 402) error.value = t('vOffensive.paymentNeeded')
    else if (code === 403) error.value = e.response?.data?.error || t('vOffensive.forbidden')
    else error.value = e.response?.data?.error || t('vOffensive.failed')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="max-w-2xl mx-auto py-6 px-4">
    <!-- Warning banner -->
    <div class="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 mb-5">
      <div class="flex items-start gap-3">
        <svg class="w-6 h-6 text-rose-500 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <p class="font-semibold text-rose-700 dark:text-rose-300">{{ t('vOffensive.warnTitle') }}</p>
          <p class="text-sm text-rose-600/90 dark:text-rose-300/80 mt-1">{{ t('vOffensive.warnBody') }}</p>
        </div>
      </div>
    </div>

    <div class="card p-8">
      <div class="flex items-center gap-3 mb-1">
        <div class="w-11 h-11 rounded-xl bg-gradient-to-br from-rose-600 to-orange-500 flex items-center justify-center shrink-0 shadow-lg shadow-rose-500/30">
          <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </div>
        <div>
          <h1 class="text-xl font-bold text-slate-900 dark:text-white">{{ t('vOffensive.title') }}</h1>
          <p class="text-sm text-slate-500 dark:text-slate-400">{{ t('vOffensive.subtitle') }}</p>
        </div>
      </div>

      <form @submit.prevent="launch" class="mt-6 space-y-5">
        <!-- Scope -->
        <div>
          <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">{{ t('vOffensive.scope') }}</label>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <button type="button" @click="scope = 'all'"
              :class="scope === 'all' ? 'border-emerald-400/60 bg-emerald-500/10 ring-1 ring-emerald-400/40' : 'border-gray-200 dark:border-white/10'"
              class="text-start p-3 rounded-lg border transition-all">
              <span class="block text-sm font-semibold text-slate-900 dark:text-white">{{ t('vOffensive.allTargets') }}</span>
              <span class="block text-xs text-slate-500 dark:text-slate-400 mt-0.5">{{ t('vOffensive.allTargetsDesc') }}</span>
            </button>
            <button type="button" @click="scope = 'one'"
              :class="scope === 'one' ? 'border-emerald-400/60 bg-emerald-500/10 ring-1 ring-emerald-400/40' : 'border-gray-200 dark:border-white/10'"
              class="text-start p-3 rounded-lg border transition-all">
              <span class="block text-sm font-semibold text-slate-900 dark:text-white">{{ t('vOffensive.oneDomain') }}</span>
              <span class="block text-xs text-slate-500 dark:text-slate-400 mt-0.5">{{ t('vOffensive.oneDomainDesc') }}</span>
            </button>
          </div>
          <input v-if="scope === 'one'" v-model="domain" type="text" dir="ltr" placeholder="app.example.com"
            class="mt-2 w-full px-4 py-3 font-mono text-sm rounded-lg bg-white dark:bg-slate-900/60 border border-gray-300 dark:border-white/15 text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:border-emerald-400/60 focus:outline-none" />
        </div>

        <!-- Tools -->
        <div>
          <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">{{ t('vOffensive.tools') }}</label>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <label v-for="tool in toolList" :key="tool.key" class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 p-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/5">
              <input type="checkbox" v-model="tools[tool.key]" class="rounded border-gray-300 text-emerald-600" />
              {{ t(tool.labelKey) }}
            </label>
          </div>
        </div>

        <!-- Authorization -->
        <label class="flex items-start gap-2 p-3 rounded-lg border border-amber-500/30 bg-amber-500/5">
          <input type="checkbox" v-model="authorized" class="mt-0.5 rounded border-gray-300 text-rose-600" />
          <span class="text-sm text-amber-700 dark:text-amber-300">{{ t('vOffensive.authConfirm') }}</span>
        </label>

        <div v-if="error" class="text-sm rounded-lg px-4 py-3 bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
          {{ error }}
        </div>

        <button type="submit" :disabled="!canLaunch"
          class="w-full py-3 rounded-lg bg-gradient-to-r from-rose-600 to-orange-500 text-white font-semibold hover:brightness-110 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-rose-500/20">
          <svg v-if="loading" class="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
          </svg>
          {{ loading ? t('vOffensive.launching') : t('vOffensive.launch') }}
        </button>
      </form>
    </div>
  </div>
</template>
