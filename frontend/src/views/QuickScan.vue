<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { createTarget, startScan } from '../api'
import { useI18n } from '../i18n'

const { t } = useI18n()
const router = useRouter()

const domain = ref('')
const policy = ref('standard')
const loading = ref(false)
const error = ref('')

const user = computed(() => {
  try { return JSON.parse(localStorage.getItem('user') || '{}') } catch { return {} }
})
const isAdmin = computed(() => user.value?.role === 'admin')

const policies = [
  { id: 'light', labelKey: 'vQuickScan.light', descKey: 'vQuickScan.lightDesc' },
  { id: 'standard', labelKey: 'vQuickScan.standard', descKey: 'vQuickScan.standardDesc' },
  { id: 'deep', labelKey: 'vQuickScan.deep', descKey: 'vQuickScan.deepDesc' },
]

function normalize(raw) {
  let u = (raw || '').trim()
  if (!u) return ''
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u
  return u
}

async function run() {
  error.value = ''
  const url = normalize(domain.value)
  if (!url || !/\./.test(url)) {
    error.value = t('vQuickScan.invalid')
    return
  }
  loading.value = true
  try {
    // Create a hidden ad-hoc target so this one-off scan never clutters the
    // targets list, then run it through the normal scan pipeline.
    const { data: target } = await createTarget({ url, name: url, adhoc: true })
    const tid = target.ID || target.id
    const payload = { target_ids: [tid], policy: policy.value, authorized: true }
    const { data: job } = await startScan(payload)
    const jid = job.ID || job.id
    router.push(`/scans/${jid}`)
  } catch (e) {
    const code = e.response?.status
    if (code === 402) error.value = t('vQuickScan.paymentNeeded')
    else if (code === 403) error.value = e.response?.data?.error || t('vQuickScan.notVerified')
    else error.value = e.response?.data?.error || t('vQuickScan.failed')
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="max-w-2xl mx-auto py-6 px-4">
    <div class="card p-8">
      <div class="flex items-center gap-3 mb-2">
        <div class="w-11 h-11 rounded-xl bg-accent-grad glow-accent flex items-center justify-center shrink-0">
          <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </div>
        <div>
          <h1 class="text-xl font-bold text-slate-900 dark:text-white">{{ t('vQuickScan.title') }}</h1>
          <p class="text-sm text-slate-500 dark:text-slate-400">{{ t('vQuickScan.subtitle') }}</p>
        </div>
      </div>

      <form @submit.prevent="run" class="mt-6 space-y-5">
        <div>
          <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">{{ t('vQuickScan.domainLabel') }}</label>
          <input
            v-model="domain"
            type="text"
            dir="ltr"
            placeholder="example.com"
            autofocus
            class="w-full px-4 py-3 font-mono text-sm rounded-lg bg-white dark:bg-slate-900/60 border border-gray-300 dark:border-white/15 text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:border-emerald-400/60 focus:outline-none transition-colors"
          />
          <p class="text-xs text-slate-400 dark:text-slate-500 mt-1.5">{{ t('vQuickScan.noListNote') }}</p>
        </div>

        <div>
          <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">{{ t('vQuickScan.depthLabel') }}</label>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <button
              v-for="p in policies" :key="p.id" type="button"
              @click="policy = p.id"
              :class="policy === p.id
                ? 'border-emerald-400/60 bg-emerald-500/10 ring-1 ring-emerald-400/40'
                : 'border-gray-200 dark:border-white/10 hover:border-emerald-400/30'"
              class="text-start p-3 rounded-lg border transition-all">
              <span class="block text-sm font-semibold text-slate-900 dark:text-white">{{ t(p.labelKey) }}</span>
              <span class="block text-xs text-slate-500 dark:text-slate-400 mt-0.5">{{ t(p.descKey) }}</span>
            </button>
          </div>
          <p v-if="policy === 'deep' && !isAdmin" class="text-xs text-amber-600 dark:text-amber-400 mt-2">
            {{ t('vQuickScan.deepPaid') }}
          </p>
        </div>

        <div v-if="error" class="text-sm rounded-lg px-4 py-3 bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
          {{ error }}
        </div>

        <button
          type="submit" :disabled="loading"
          class="w-full py-3 rounded-lg bg-accent-grad glow-accent text-white font-semibold hover:brightness-110 transition-all disabled:opacity-50 flex items-center justify-center gap-2">
          <svg v-if="loading" class="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
          </svg>
          {{ loading ? t('vQuickScan.starting') : t('vQuickScan.scanNow') }}
        </button>
      </form>
    </div>
  </div>
</template>
