<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getScanActivity } from '../api'
import { useI18n } from '../i18n'

const { t } = useI18n()
const router = useRouter()

const activity = ref([])
const byUser = ref([])
const loading = ref(true)
const error = ref('')

const statusClass = (s) => ({
  completed: 'sev sev-low',
  running: 'sev sev-info',
  pending: 'sev sev-info',
  failed: 'sev sev-high',
}[s] || 'sev sev-info')

async function load() {
  loading.value = true
  error.value = ''
  try {
    const { data } = await getScanActivity({ limit: 300 })
    activity.value = data.activity || []
    byUser.value = (data.by_user || []).sort((a, b) => b.scan_count - a.scan_count)
  } catch (e) {
    error.value = e.response?.data?.error || t('vActivity.failed')
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>

<template>
  <div class="max-w-6xl mx-auto py-6 px-4 space-y-6">
    <div v-if="error" class="text-sm rounded-lg px-4 py-3 bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
      {{ error }}
    </div>

    <div v-if="loading" class="text-center text-slate-500 dark:text-slate-400 py-10">{{ t('common.loading') }}</div>

    <template v-else>
      <!-- Per-user summary -->
      <div>
        <h2 class="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-3">{{ t('vActivity.byUser') }}</h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div v-for="u in byUser" :key="u.user_id" class="card p-4">
            <div class="flex items-center justify-between">
              <div class="min-w-0">
                <p class="font-semibold text-slate-900 dark:text-white truncate">{{ u.username || ('#' + u.user_id) }}</p>
                <p class="text-xs text-slate-500 dark:text-slate-400 truncate">{{ u.full_name || '—' }}</p>
              </div>
              <p class="text-2xl font-bold font-mono text-gradient">{{ u.scan_count }}</p>
            </div>
            <p class="text-xs text-slate-400 dark:text-slate-500 mt-2 font-mono">{{ t('vActivity.lastScan') }}: {{ u.last_scan || '—' }}</p>
          </div>
          <div v-if="!byUser.length" class="text-sm text-slate-500 dark:text-slate-400">{{ t('vActivity.none') }}</div>
        </div>
      </div>

      <!-- Activity table -->
      <div class="card p-0 overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-start text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400 border-b border-gray-200 dark:border-white/10">
                <th class="px-4 py-3 text-start font-semibold">{{ t('vActivity.user') }}</th>
                <th class="px-4 py-3 text-start font-semibold">{{ t('vActivity.targets') }}</th>
                <th class="px-4 py-3 text-start font-semibold">{{ t('vActivity.policy') }}</th>
                <th class="px-4 py-3 text-start font-semibold">{{ t('common.status') }}</th>
                <th class="px-4 py-3 text-start font-semibold">{{ t('common.date') }}</th>
                <th class="px-4 py-3 text-end font-semibold">{{ t('vActivity.results') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in activity" :key="row.job_id"
                  class="border-b border-gray-100 dark:border-white/5 hover:bg-slate-50 dark:hover:bg-white/5 cursor-pointer transition-colors"
                  @click="router.push(`/scans/${row.job_id}`)">
                <td class="px-4 py-3">
                  <div class="flex items-center gap-1.5">
                    <span class="font-medium text-slate-900 dark:text-white">{{ row.username || ('#' + row.user_id) }}</span>
                    <span v-if="row.source && row.source !== 'web'" class="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 uppercase font-mono">{{ row.source }}</span>
                  </div>
                  <div v-if="row.device_info" class="text-[11px] text-slate-400 dark:text-slate-500 font-mono">{{ row.device_info }}</div>
                </td>
                <td class="px-4 py-3 max-w-xs">
                  <span class="font-mono text-xs text-slate-600 dark:text-slate-300 break-all">{{ (row.targets && row.targets[0]) || row.name || '—' }}</span>
                  <span v-if="row.target_count > 1" class="text-xs text-slate-400 dark:text-slate-500"> +{{ row.target_count - 1 }}</span>
                </td>
                <td class="px-4 py-3"><span class="font-mono text-xs text-emerald-600 dark:text-emerald-400 uppercase">{{ row.policy || 'std' }}</span></td>
                <td class="px-4 py-3"><span :class="statusClass(row.status)">{{ row.status }}</span></td>
                <td class="px-4 py-3 font-mono text-xs text-slate-500 dark:text-slate-400">{{ row.created_at }}</td>
                <td class="px-4 py-3 text-end font-mono text-slate-600 dark:text-slate-300">{{ row.result_count }}</td>
              </tr>
              <tr v-if="!activity.length">
                <td colspan="6" class="px-4 py-10 text-center text-slate-500 dark:text-slate-400">{{ t('vActivity.none') }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
