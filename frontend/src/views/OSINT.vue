<script setup>
import { ref, computed } from 'vue'
import { useI18n } from '../i18n'
import { getOSINT } from '../api'

const { t } = useI18n()

const domain = ref('')
const data = ref(null)
const loading = ref(false)
const error = ref('')

// Map a highlight level → severity chip class from the design system.
const sevMap = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
  info: 'sev-info',
}
function sevClass(level) {
  return sevMap[level] || 'sev-info'
}

// Normalise "example.com" / "https://example.com/x" → bare host.
function cleanDomain(raw) {
  let d = (raw || '').trim().toLowerCase()
  if (!d) return ''
  d = d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '')
  return d
}

const errorSources = computed(() => {
  const errs = data.value?.errors
  if (!errs || typeof errs !== 'object') return []
  return Object.keys(errs).filter((k) => errs[k])
})

async function analyze() {
  const d = cleanDomain(domain.value)
  if (!d || loading.value) return
  loading.value = true
  error.value = ''
  data.value = null
  try {
    const res = await getOSINT(d)
    data.value = res.data || null
  } catch (e) {
    error.value = e.response?.data?.error || t('vOSINT.errorGeneric')
  } finally {
    loading.value = false
  }
}

function fmtNum(n) {
  const v = Number(n)
  return Number.isFinite(v) ? v.toLocaleString('en-US') : (n ?? '')
}
</script>

<template>
  <div class="max-w-5xl mx-auto space-y-6">
    <!-- Search / control bar -->
    <div class="card p-5">
      <div class="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
        <div class="relative flex-1">
          <svg class="w-5 h-5 text-gray-400 dark:text-slate-500 absolute top-1/2 -translate-y-1/2 start-3 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            v-model="domain"
            @keyup.enter="analyze"
            type="text"
            dir="ltr"
            :placeholder="t('vOSINT.placeholder')"
            class="w-full ps-10 pe-3 py-2.5 text-sm font-mono rounded-xl bg-white/70 dark:bg-slate-900/60 border border-gray-300 dark:border-slate-700 text-gray-900 dark:text-slate-100 placeholder:text-gray-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <button
          @click="analyze"
          :disabled="loading || !domain.trim()"
          class="bg-accent-grad glow-accent text-white font-medium text-sm px-6 py-2.5 rounded-xl flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <span v-if="loading" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></span>
          <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
          {{ loading ? t('vOSINT.analyzing') : t('vOSINT.run') }}
        </button>
      </div>
      <p class="text-xs text-gray-500 dark:text-slate-400 mt-3">{{ t('vOSINT.explainer') }}</p>
    </div>

    <!-- Error state -->
    <div v-if="error" class="card p-4 border-s-4 !border-s-rose-500 flex items-center gap-3">
      <svg class="w-5 h-5 text-rose-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
      <p class="text-sm text-gray-700 dark:text-slate-200">{{ error }}</p>
    </div>

    <!-- Loading skeleton note -->
    <div v-else-if="loading" class="card p-10 text-center">
      <span class="animate-spin inline-block rounded-full h-8 w-8 border-b-2 border-indigo-500"></span>
      <p class="text-sm text-gray-500 dark:text-slate-400 mt-4">{{ t('vOSINT.analyzing') }}</p>
    </div>

    <!-- Empty / initial state -->
    <div v-else-if="!data" class="card p-10 text-center">
      <div class="w-14 h-14 mx-auto mb-4 rounded-2xl bg-accent-grad glow-accent flex items-center justify-center">
        <svg class="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M21 21l-4.35-4.35M11 6a5 5 0 015 5m2 0a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      </div>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white">{{ t('vOSINT.emptyTitle') }}</h3>
      <p class="text-sm text-gray-500 dark:text-slate-400 mt-1 max-w-md mx-auto">{{ t('vOSINT.explainer') }}</p>
    </div>

    <!-- Results -->
    <template v-else>
      <!-- Meta row -->
      <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h2 class="text-xl font-bold text-gradient" dir="ltr">{{ data.domain }}</h2>
        <span v-if="data.generated_at" class="text-xs text-gray-400 dark:text-slate-500 font-mono">{{ t('vOSINT.generatedAt') }}: {{ data.generated_at }}</span>
      </div>

      <!-- Partial-source note -->
      <div v-if="errorSources.length" class="card p-3 flex items-center gap-2">
        <svg class="w-4 h-4 text-amber-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p class="text-xs text-gray-500 dark:text-slate-400">
          {{ t('vOSINT.partialNote') }}
          <span class="font-mono text-gray-400 dark:text-slate-500">({{ errorSources.join(', ') }})</span>
        </p>
      </div>

      <!-- Highlights -->
      <div v-if="data.highlights?.length" class="card p-5">
        <h3 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">{{ t('vOSINT.highlights') }}</h3>
        <div class="flex flex-col gap-2">
          <div v-for="(h, i) in data.highlights" :key="i" class="flex items-start gap-2.5">
            <span :class="['sev', sevClass(h.level)]">{{ h.level }}</span>
            <span class="text-sm text-gray-700 dark:text-slate-200">{{ h.text }}</span>
          </div>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- DNS records -->
        <div class="card p-5">
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">{{ t('vOSINT.secDns') }}</h3>
          <div class="space-y-2.5 text-sm">
            <div v-for="rec in [
              { k: 'A', vals: data.dns?.a },
              { k: 'AAAA', vals: data.dns?.aaaa },
              { k: 'MX', vals: data.dns?.mx },
              { k: 'NS', vals: data.dns?.ns },
              { k: 'TXT', vals: data.dns?.txt },
              { k: 'CNAME', vals: data.dns?.cname ? [data.dns.cname] : [] },
            ]" :key="rec.k" class="flex gap-3">
              <span class="w-14 flex-shrink-0 text-xs font-semibold text-gray-400 dark:text-slate-500 pt-0.5">{{ rec.k }}</span>
              <div class="flex-1 min-w-0">
                <div v-if="rec.vals && rec.vals.length" class="flex flex-col gap-1">
                  <code v-for="(v, j) in rec.vals" :key="j" dir="ltr" class="font-mono text-xs text-gray-700 dark:text-slate-200 break-all">{{ v }}</code>
                </div>
                <span v-else class="text-xs text-gray-300 dark:text-slate-600">—</span>
              </div>
            </div>
          </div>
        </div>

        <!-- WHOIS -->
        <div class="card p-5">
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">{{ t('vOSINT.secWhois') }}</h3>
          <dl class="grid grid-cols-3 gap-x-3 gap-y-2 text-sm">
            <dt class="text-gray-400 dark:text-slate-500 text-xs pt-0.5">{{ t('vOSINT.registrar') }}</dt>
            <dd class="col-span-2 text-gray-700 dark:text-slate-200 break-words">{{ data.whois?.registrar || '—' }}</dd>
            <dt class="text-gray-400 dark:text-slate-500 text-xs pt-0.5">{{ t('vOSINT.created') }}</dt>
            <dd class="col-span-2 font-mono text-xs text-gray-700 dark:text-slate-200" dir="ltr">{{ data.whois?.created_at || '—' }}</dd>
            <dt class="text-gray-400 dark:text-slate-500 text-xs pt-0.5">{{ t('vOSINT.updated') }}</dt>
            <dd class="col-span-2 font-mono text-xs text-gray-700 dark:text-slate-200" dir="ltr">{{ data.whois?.updated_at || '—' }}</dd>
            <dt class="text-gray-400 dark:text-slate-500 text-xs pt-0.5">{{ t('vOSINT.expires') }}</dt>
            <dd class="col-span-2 font-mono text-xs text-gray-700 dark:text-slate-200" dir="ltr">{{ data.whois?.expires_at || '—' }}</dd>
            <dt class="text-gray-400 dark:text-slate-500 text-xs pt-0.5">{{ t('vOSINT.nameservers') }}</dt>
            <dd class="col-span-2">
              <div v-if="data.whois?.nameservers?.length" class="flex flex-col gap-1">
                <code v-for="(ns, i) in data.whois.nameservers" :key="i" dir="ltr" class="font-mono text-xs text-gray-700 dark:text-slate-200 break-all">{{ ns }}</code>
              </div>
              <span v-else class="text-xs text-gray-300 dark:text-slate-600">—</span>
            </dd>
            <dt class="text-gray-400 dark:text-slate-500 text-xs pt-0.5">{{ t('vOSINT.statuses') }}</dt>
            <dd class="col-span-2">
              <div v-if="data.whois?.statuses?.length" class="flex flex-wrap gap-1">
                <span v-for="(s, i) in data.whois.statuses" :key="i" class="px-1.5 py-0.5 rounded bg-gray-100 dark:bg-slate-800 text-[10px] font-mono text-gray-600 dark:text-slate-300">{{ s }}</span>
              </div>
              <span v-else class="text-xs text-gray-300 dark:text-slate-600">—</span>
            </dd>
          </dl>
        </div>
      </div>

      <!-- IPs & hosting -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">{{ t('vOSINT.secIps') }}</h3>
        <div v-if="data.ips?.length" class="overflow-x-auto">
          <table class="w-full text-sm min-w-[560px]">
            <thead>
              <tr class="text-xs text-gray-400 dark:text-slate-500 border-b border-gray-200 dark:border-slate-700">
                <th class="text-start font-medium py-2 pe-3">{{ t('vOSINT.ip') }}</th>
                <th class="text-start font-medium py-2 pe-3">{{ t('vOSINT.asn') }}</th>
                <th class="text-start font-medium py-2 pe-3">{{ t('vOSINT.org') }}</th>
                <th class="text-start font-medium py-2 pe-3">{{ t('vOSINT.isp') }}</th>
                <th class="text-start font-medium py-2">{{ t('vOSINT.country') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, i) in data.ips" :key="i" class="border-b border-gray-100 dark:border-slate-800 last:border-0">
                <td class="py-2 pe-3 font-mono text-xs text-gray-700 dark:text-slate-200" dir="ltr">{{ row.ip }}</td>
                <td class="py-2 pe-3 font-mono text-xs text-gray-700 dark:text-slate-200" dir="ltr">{{ row.asn || '—' }}</td>
                <td class="py-2 pe-3 text-gray-700 dark:text-slate-200">{{ row.org || '—' }}</td>
                <td class="py-2 pe-3 text-gray-700 dark:text-slate-200">{{ row.isp || '—' }}</td>
                <td class="py-2 text-gray-700 dark:text-slate-200">{{ row.country || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="text-sm text-gray-400 dark:text-slate-500">—</p>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Subdomains -->
        <div class="card p-5">
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">{{ t('vOSINT.secSubdomains') }}</h3>
          <div class="flex items-baseline gap-2 mb-3">
            <span class="text-4xl font-bold text-gradient">{{ (data.subdomains || []).length }}</span>
            <span class="text-xs text-gray-500 dark:text-slate-400">{{ t('vOSINT.subdomainsFound') }}</span>
          </div>
          <div v-if="data.subdomains?.length" class="max-h-56 overflow-y-auto scrollbar-thin rounded-lg bg-gray-50 dark:bg-slate-900/50 p-3">
            <code v-for="(s, i) in data.subdomains" :key="i" dir="ltr" class="block font-mono text-xs text-gray-700 dark:text-slate-200 break-all py-0.5">{{ s }}</code>
          </div>
        </div>

        <!-- Email security -->
        <div class="card p-5">
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">{{ t('vOSINT.secEmail') }}</h3>
          <div class="space-y-4 text-sm">
            <div>
              <div class="flex items-center gap-2 mb-1">
                <span class="text-xs font-semibold text-gray-500 dark:text-slate-400">SPF</span>
                <span v-if="data.email_security?.has_spf" class="sev sev-low">{{ t('vOSINT.present') }}</span>
                <span v-else class="sev sev-high">{{ t('vOSINT.missing') }}</span>
              </div>
              <code v-if="data.email_security?.spf" dir="ltr" class="block font-mono text-xs text-gray-600 dark:text-slate-300 break-all bg-gray-50 dark:bg-slate-900/50 rounded p-2">{{ data.email_security.spf }}</code>
            </div>
            <div>
              <div class="flex items-center gap-2 mb-1">
                <span class="text-xs font-semibold text-gray-500 dark:text-slate-400">DMARC</span>
                <span v-if="data.email_security?.has_dmarc" class="sev sev-low">{{ t('vOSINT.present') }}</span>
                <span v-else class="sev sev-high">{{ t('vOSINT.missing') }}</span>
                <span v-if="data.email_security?.dmarc_policy" class="text-[11px] text-gray-500 dark:text-slate-400 font-mono">p={{ data.email_security.dmarc_policy }}</span>
              </div>
              <code v-if="data.email_security?.dmarc" dir="ltr" class="block font-mono text-xs text-gray-600 dark:text-slate-300 break-all bg-gray-50 dark:bg-slate-900/50 rounded p-2">{{ data.email_security.dmarc }}</code>
            </div>
          </div>
        </div>
      </div>

      <!-- Certificates -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">{{ t('vOSINT.secCerts') }}</h3>
        <div v-if="data.certificates?.length" class="overflow-x-auto">
          <table class="w-full text-sm min-w-[560px]">
            <thead>
              <tr class="text-xs text-gray-400 dark:text-slate-500 border-b border-gray-200 dark:border-slate-700">
                <th class="text-start font-medium py-2 pe-3">{{ t('vOSINT.issuer') }}</th>
                <th class="text-start font-medium py-2 pe-3">{{ t('vOSINT.commonName') }}</th>
                <th class="text-start font-medium py-2 pe-3">{{ t('vOSINT.notBefore') }}</th>
                <th class="text-start font-medium py-2">{{ t('vOSINT.notAfter') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(c, i) in data.certificates" :key="i" class="border-b border-gray-100 dark:border-slate-800 last:border-0">
                <td class="py-2 pe-3 text-gray-700 dark:text-slate-200">{{ c.issuer || '—' }}</td>
                <td class="py-2 pe-3 font-mono text-xs text-gray-700 dark:text-slate-200" dir="ltr">{{ c.common_name || '—' }}</td>
                <td class="py-2 pe-3 font-mono text-xs text-gray-600 dark:text-slate-300" dir="ltr">{{ c.not_before || '—' }}</td>
                <td class="py-2 font-mono text-xs text-gray-600 dark:text-slate-300" dir="ltr">{{ c.not_after || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="text-sm text-gray-400 dark:text-slate-500">—</p>
      </div>

      <!-- Breaches -->
      <div class="card p-5">
        <h3 class="text-sm font-semibold text-gray-900 dark:text-white mb-3">{{ t('vOSINT.secBreaches') }}</h3>
        <div v-if="data.breaches?.length" class="space-y-2">
          <div v-for="(b, i) in data.breaches" :key="i" class="flex items-center justify-between gap-3 rounded-lg bg-gray-50 dark:bg-slate-900/50 px-3 py-2">
            <div class="min-w-0">
              <p class="text-sm font-medium text-gray-800 dark:text-slate-100 truncate">{{ b.name }}</p>
              <p v-if="b.domain" class="text-xs font-mono text-gray-400 dark:text-slate-500 truncate" dir="ltr">{{ b.domain }}</p>
            </div>
            <div class="text-end flex-shrink-0">
              <p class="text-xs font-mono text-gray-500 dark:text-slate-400" dir="ltr">{{ b.breach_date || '—' }}</p>
              <p v-if="b.pwn_count" class="text-xs text-rose-500 font-medium">{{ fmtNum(b.pwn_count) }} {{ t('vOSINT.accounts') }}</p>
            </div>
          </div>
        </div>
        <p v-else class="text-sm text-gray-400 dark:text-slate-500">{{ t('vOSINT.noBreaches') }}</p>
      </div>
    </template>
  </div>
</template>
