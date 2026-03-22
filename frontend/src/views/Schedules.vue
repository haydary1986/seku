<script setup>
import { ref, computed, onMounted } from 'vue'
import { getSchedules, createSchedule, deleteSchedule, toggleSchedule, getTargets } from '../api'

const schedules = ref([])
const targets = ref([])
const loading = ref(true)
const showCreateForm = ref(false)
const error = ref('')

const form = ref({
  name: '',
  target_ids: [],
  schedule: 'daily',
  day_of_week: 1,
  hour_utc: 8,
})

const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
const hours = Array.from({ length: 24 }, (_, i) => i)

function scheduleDescription(sched) {
  const hour = String(sched.hour_utc).padStart(2, '0') + ':00 UTC'
  switch (sched.schedule) {
    case 'daily':
      return `Daily at ${hour}`
    case 'weekly':
      return `Every ${dayNames[sched.day_of_week] || 'Monday'} at ${hour}`
    case 'monthly':
      return `Monthly on day ${sched.day_of_week} at ${hour}`
    default:
      return sched.schedule
  }
}

function formatDate(dateStr) {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleString()
}

function parseTargetIds(targetIdsJson) {
  try {
    return JSON.parse(targetIdsJson || '[]')
  } catch {
    return []
  }
}

function targetNames(sched) {
  const ids = parseTargetIds(sched.target_ids)
  return ids.map(id => {
    const t = targets.value.find(t => t.ID === id)
    return t ? (t.name || t.url) : `#${id}`
  }).join(', ')
}

async function loadData() {
  loading.value = true
  try {
    const [schedRes, targetRes] = await Promise.all([getSchedules(), getTargets()])
    schedules.value = schedRes.data || []
    targets.value = targetRes.data || []
  } catch (e) {
    console.error('Failed to load data:', e)
  } finally {
    loading.value = false
  }
}

async function submitCreate() {
  error.value = ''
  if (!form.value.name) {
    error.value = 'Name is required'
    return
  }
  if (form.value.target_ids.length === 0) {
    error.value = 'Select at least one target'
    return
  }
  try {
    await createSchedule({
      name: form.value.name,
      target_ids: form.value.target_ids.map(Number),
      schedule: form.value.schedule,
      day_of_week: Number(form.value.day_of_week),
      hour_utc: Number(form.value.hour_utc),
    })
    form.value = { name: '', target_ids: [], schedule: 'daily', day_of_week: 1, hour_utc: 8 }
    showCreateForm.value = false
    await loadData()
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to create schedule'
  }
}

async function handleToggle(sched) {
  try {
    await toggleSchedule(sched.ID)
    await loadData()
  } catch (e) {
    console.error('Failed to toggle schedule:', e)
  }
}

async function handleDelete(sched) {
  if (!confirm(`Delete scheduled scan "${sched.name}"?`)) return
  try {
    await deleteSchedule(sched.ID)
    await loadData()
  } catch (e) {
    console.error('Failed to delete schedule:', e)
  }
}

onMounted(loadData)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">Scheduled Scans</h1>
        <p class="text-gray-500 mt-1">Automate recurring security scans</p>
      </div>
      <button
        @click="showCreateForm = !showCreateForm"
        class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm"
      >
        {{ showCreateForm ? 'Cancel' : 'New Schedule' }}
      </button>
    </div>

    <!-- Create Form -->
    <div v-if="showCreateForm" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-900 mb-4">Create Scheduled Scan</h3>

      <div v-if="error" class="mb-4 p-3 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">
        {{ error }}
      </div>

      <form @submit.prevent="submitCreate" class="space-y-4">
        <!-- Name -->
        <div>
          <label class="block text-sm text-gray-600 mb-1">Name *</label>
          <input
            v-model="form.name"
            type="text"
            placeholder="Weekly Security Scan"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            required
          />
        </div>

        <!-- Target Selection -->
        <div>
          <label class="block text-sm text-gray-600 mb-1">Targets *</label>
          <div class="border border-gray-300 rounded-lg max-h-48 overflow-y-auto p-2 space-y-1">
            <label
              v-for="target in targets"
              :key="target.ID"
              class="flex items-center gap-2 px-2 py-1.5 hover:bg-gray-50 rounded cursor-pointer"
            >
              <input
                type="checkbox"
                :value="target.ID"
                v-model="form.target_ids"
                class="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
              />
              <span class="text-sm text-gray-900">{{ target.name || target.url }}</span>
              <span class="text-xs text-gray-400">{{ target.url }}</span>
            </label>
            <p v-if="targets.length === 0" class="text-sm text-gray-400 text-center py-2">No targets available</p>
          </div>
          <p class="text-xs text-gray-400 mt-1">{{ form.target_ids.length }} target(s) selected</p>
        </div>

        <!-- Schedule Type + Options -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Frequency</label>
            <select
              v-model="form.schedule"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            >
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </div>

          <div v-if="form.schedule === 'weekly'">
            <label class="block text-sm text-gray-600 mb-1">Day of Week</label>
            <select
              v-model="form.day_of_week"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            >
              <option v-for="(name, idx) in dayNames" :key="idx" :value="idx">{{ name }}</option>
            </select>
          </div>

          <div v-if="form.schedule === 'monthly'">
            <label class="block text-sm text-gray-600 mb-1">Day of Month (1-28)</label>
            <input
              v-model.number="form.day_of_week"
              type="number"
              min="1"
              max="28"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
          </div>

          <div>
            <label class="block text-sm text-gray-600 mb-1">Hour (UTC)</label>
            <select
              v-model="form.hour_utc"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            >
              <option v-for="h in hours" :key="h" :value="h">{{ String(h).padStart(2, '0') }}:00</option>
            </select>
          </div>
        </div>

        <div>
          <button type="submit" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
            Create Schedule
          </button>
        </div>
      </form>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <!-- Schedules List -->
    <div v-else class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      <table v-if="schedules.length" class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Name</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Targets</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Schedule</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Status</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Next Run</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Last Run</th>
            <th class="text-center py-3 px-4 text-gray-600 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="sched in schedules" :key="sched.ID" class="border-t border-gray-100 hover:bg-gray-50">
            <td class="py-3 px-4 text-gray-900 font-medium">{{ sched.name }}</td>
            <td class="py-3 px-4 text-gray-600 text-xs max-w-[200px] truncate" :title="targetNames(sched)">
              {{ targetNames(sched) }}
            </td>
            <td class="py-3 px-4 text-gray-600">{{ scheduleDescription(sched) }}</td>
            <td class="py-3 px-4">
              <span
                :class="sched.is_active
                  ? 'bg-green-100 text-green-700'
                  : 'bg-gray-100 text-gray-500'"
                class="px-2 py-0.5 rounded-full text-xs font-medium"
              >
                {{ sched.is_active ? 'Active' : 'Paused' }}
              </span>
            </td>
            <td class="py-3 px-4 text-gray-600 text-xs">{{ formatDate(sched.next_run_at) }}</td>
            <td class="py-3 px-4 text-gray-600 text-xs">{{ formatDate(sched.last_run_at) }}</td>
            <td class="py-3 px-4 text-center space-x-2">
              <button
                @click="handleToggle(sched)"
                :class="sched.is_active
                  ? 'text-yellow-600 hover:text-yellow-800'
                  : 'text-green-600 hover:text-green-800'"
                class="text-sm"
              >
                {{ sched.is_active ? 'Pause' : 'Activate' }}
              </button>
              <button @click="handleDelete(sched)" class="text-red-500 hover:text-red-700 text-sm">
                Delete
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else class="text-center py-16 text-gray-400">
        <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <p class="text-lg">No scheduled scans yet</p>
        <p class="text-sm mt-1">Create a schedule to automate your security scans</p>
      </div>
    </div>
  </div>
</template>
