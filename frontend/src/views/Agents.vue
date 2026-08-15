<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { getAgents, createAgent, deleteAgent, enqueueAgentScan, getAgentJobs, getAgentJob } from '../api'

const agents = ref([])
const jobs = ref([])
const loading = ref(true)

// create
const showCreate = ref(false)
const newName = ref('')
const creating = ref(false)
const created = ref(null) // { name, token }
const copied = ref(false)

// assign scan
const scanFor = ref(null)
const scanTarget = ref('')
const scanPolicy = ref('standard')
const scanning = ref(false)

// job detail
const job = ref(null)

const serverUrl = window.location.origin

let timer = null

function fmtDur(s) {
  if (!s) return '—'
  const m = Math.floor(s / 60), ss = s % 60
  return m ? `${m}m ${ss}s` : `${ss}s`
}
function fmtDate(d) {
  if (!d) return '—'
  try { return new Date(d).toLocaleString() } catch { return d }
}
function isOnline(a) {
  return a.online
}
const statusClass = (s) =>
  ({ pending: 'bg-gray-100 text-gray-600', running: 'bg-blue-100 text-blue-700', done: 'bg-green-100 text-green-700', failed: 'bg-red-100 text-red-700' })[s] ||
  'bg-gray-100 text-gray-600'
const sevClass = (s) =>
  ({ critical: 'bg-red-100 text-red-700', high: 'bg-orange-100 text-orange-700', medium: 'bg-yellow-100 text-yellow-700', low: 'bg-blue-100 text-blue-700' })[s] ||
  'bg-gray-100 text-gray-600'

async function load() {
  try {
    const [a, j] = await Promise.all([getAgents(), getAgentJobs()])
    agents.value = a.data || []
    jobs.value = j.data || []
  } catch {
    /* ignore */
  } finally {
    loading.value = false
  }
}

async function doCreate() {
  const name = newName.value.trim() || 'agent'
  creating.value = true
  try {
    const { data } = await createAgent({ name })
    created.value = { name: data.name, token: data.token }
    newName.value = ''
    showCreate.value = false
    await load()
  } catch {
    /* ignore */
  } finally {
    creating.value = false
  }
}

function copyToken() {
  if (!created.value) return
  navigator.clipboard?.writeText(created.value.token)
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}

async function doScan(id) {
  const t = scanTarget.value.trim()
  if (!t) return
  scanning.value = true
  try {
    await enqueueAgentScan(id, { target: t, policy: scanPolicy.value })
    scanFor.value = null
    scanTarget.value = ''
    await load()
  } catch {
    /* ignore */
  } finally {
    scanning.value = false
  }
}

async function removeAgent(id) {
  if (!confirm('حذف هذا الوكيل؟')) return
  try {
    await deleteAgent(id)
    await load()
  } catch {
    /* ignore */
  }
}

async function openJob(id) {
  try {
    const { data } = await getAgentJob(id)
    job.value = data
  } catch {
    /* ignore */
  }
}
function jobFindings(j) {
  if (!j?.results_json) return []
  let arr = []
  try { arr = JSON.parse(j.results_json) } catch { return [] }
  return arr.filter((r) => r.status === 'fail')
}

onMounted(() => {
  load()
  timer = setInterval(load, 15000)
})
onUnmounted(() => timer && clearInterval(timer))
</script>

<template>
  <div class="max-w-4xl mx-auto p-4 md:p-6">
    <div class="flex items-start justify-end gap-3 mb-4">
      <button @click="showCreate = !showCreate" class="flex-shrink-0 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 text-sm font-medium">
        + إنشاء وكيل
      </button>
    </div>

    <!-- create form -->
    <div v-if="showCreate" class="bg-white rounded-xl border border-gray-200 shadow-sm p-4 mb-4 flex flex-col sm:flex-row gap-2">
      <input v-model="newName" type="text" placeholder="اسم الوكيل (مثلاً: مكتب-بغداد)" class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none" @keyup.enter="doCreate" />
      <button @click="doCreate" :disabled="creating" class="px-5 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 text-sm font-medium">
        {{ creating ? 'جارٍ…' : 'إنشاء' }}
      </button>
    </div>

    <!-- token shown once -->
    <div v-if="created" class="bg-emerald-50 border border-emerald-200 rounded-xl p-4 mb-5">
      <div class="flex items-center justify-between">
        <p class="text-sm font-semibold text-emerald-800">تم إنشاء «{{ created.name }}» — انسخ التوكن الآن (يُعرض مرة واحدة)</p>
        <button @click="created = null" class="text-emerald-700 hover:text-emerald-900 text-lg leading-none">×</button>
      </div>
      <div class="mt-2 flex items-center gap-2">
        <code class="flex-1 text-xs bg-white border border-emerald-200 rounded-lg px-3 py-2 break-all">{{ created.token }}</code>
        <button @click="copyToken" class="px-3 py-2 bg-emerald-600 text-white rounded-lg text-xs hover:bg-emerald-700 whitespace-nowrap">
          {{ copied ? 'تم النسخ ✓' : 'نسخ' }}
        </button>
      </div>
      <p class="text-xs text-gray-600 mt-2">شغّل الوكيل:</p>
      <pre class="mt-1 text-xs bg-slate-900 text-slate-100 rounded-lg p-3 overflow-x-auto" dir="ltr"><code>seku-agent -server {{ serverUrl }} -token {{ created.token }}</code></pre>
    </div>

    <!-- agents list -->
    <div v-if="loading" class="text-sm text-gray-400 py-8 text-center">جارٍ التحميل…</div>
    <div v-else-if="agents.length === 0" class="text-sm text-gray-400 py-8 text-center border border-dashed border-gray-200 rounded-xl">
      لا يوجد وكلاء بعد. أنشئ وكيلاً وشغّله على جهاز داخل الشبكة.
    </div>
    <div v-else class="space-y-2 mb-8">
      <div v-for="a in agents" :key="a.id" class="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
        <div class="flex items-center justify-between gap-3">
          <div class="flex items-center gap-2 min-w-0">
            <span :class="['w-2.5 h-2.5 rounded-full flex-shrink-0', isOnline(a) ? 'bg-green-500' : 'bg-gray-300']" :title="isOnline(a) ? 'متصل' : 'غير متصل'"></span>
            <div class="min-w-0">
              <p class="font-medium text-gray-900 truncate">{{ a.name }}</p>
              <p class="text-[11px] text-gray-400">{{ a.os || '—' }} · آخر ظهور: {{ fmtDate(a.last_seen) }}</p>
            </div>
          </div>
          <div class="flex items-center gap-2 flex-shrink-0">
            <button @click="scanFor = scanFor === a.id ? null : a.id" class="px-3 py-1.5 text-sm bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">فحص</button>
            <button @click="removeAgent(a.id)" class="px-2 py-1.5 text-sm text-gray-400 hover:text-red-600" title="حذف">🗑</button>
          </div>
        </div>
        <!-- assign scan -->
        <div v-if="scanFor === a.id" class="mt-3 pt-3 border-t border-gray-100 flex flex-col sm:flex-row gap-2">
          <input v-model="scanTarget" type="text" placeholder="الهدف الداخلي (مثل http://192.168.1.1)" class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm" @keyup.enter="doScan(a.id)" />
          <select v-model="scanPolicy" class="px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none">
            <option value="light">Light</option>
            <option value="standard">Standard</option>
            <option value="deep">Deep</option>
          </select>
          <button @click="doScan(a.id)" :disabled="scanning || !scanTarget.trim()" class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 text-sm whitespace-nowrap">
            {{ scanning ? 'جارٍ…' : 'بدء الفحص' }}
          </button>
        </div>
      </div>
    </div>

    <!-- jobs -->
    <h2 class="text-lg font-semibold text-gray-900 mb-2">مهام الفحص</h2>
    <div v-if="jobs.length === 0" class="text-sm text-gray-400 py-6 text-center border border-dashed border-gray-200 rounded-xl">لا توجد مهام بعد.</div>
    <div v-else class="overflow-x-auto bg-white rounded-xl border border-gray-200 shadow-sm">
      <table class="min-w-full text-sm">
        <thead class="bg-gray-50 text-gray-500 text-xs uppercase">
          <tr>
            <th class="text-right px-4 py-2.5">الهدف</th>
            <th class="text-right px-4 py-2.5">السياسة</th>
            <th class="text-right px-4 py-2.5">الحالة</th>
            <th class="text-right px-4 py-2.5">المدة</th>
            <th class="text-right px-4 py-2.5">النتائج</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100">
          <tr v-for="j in jobs" :key="j.id" @click="openJob(j.id)" class="hover:bg-indigo-50/40 cursor-pointer">
            <td class="px-4 py-2.5 text-gray-800 break-all max-w-[220px]">{{ j.target }}</td>
            <td class="px-4 py-2.5 text-gray-600 capitalize">{{ j.policy }}</td>
            <td class="px-4 py-2.5"><span :class="['px-2 py-0.5 rounded-full text-xs font-medium capitalize', statusClass(j.status)]">{{ j.status }}</span></td>
            <td class="px-4 py-2.5 text-gray-600 whitespace-nowrap">{{ fmtDur(j.duration_sec) }}</td>
            <td class="px-4 py-2.5 text-gray-700">{{ j.findings }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- job detail modal -->
    <div v-if="job" @click.self="job = null" class="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
      <div class="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[85vh] overflow-auto">
        <div class="flex items-center justify-between px-5 py-3 border-b border-gray-100 sticky top-0 bg-white">
          <div>
            <p class="font-semibold text-gray-900 break-all">{{ job.target }}</p>
            <p class="text-xs text-gray-400">{{ job.policy }} · {{ fmtDur(job.duration_sec) }} · {{ jobFindings(job).length }} ثغرة</p>
          </div>
          <button @click="job = null" class="text-gray-400 hover:text-gray-700 text-xl leading-none">×</button>
        </div>
        <div class="p-5">
          <div v-if="job.status !== 'done'" class="text-sm text-gray-500">الحالة: {{ job.status }}<span v-if="job.error"> — {{ job.error }}</span></div>
          <div v-else-if="jobFindings(job).length === 0" class="text-sm text-green-600">✓ لا توجد ثغرات (فشل) في هذا الفحص.</div>
          <div v-else class="space-y-2">
            <div v-for="(f, i) in jobFindings(job)" :key="i" class="border border-gray-200 rounded-lg p-3">
              <div class="flex items-start justify-between gap-2">
                <p class="font-medium text-gray-900 text-sm">{{ f.check_name }}</p>
                <span :class="['px-2 py-0.5 rounded-full text-xs capitalize flex-shrink-0', sevClass(f.severity)]">{{ f.severity }}</span>
              </div>
              <p class="text-[11px] text-gray-400 mt-0.5">{{ f.category }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
