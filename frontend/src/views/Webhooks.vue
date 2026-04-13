<script setup>
import { ref, computed, onMounted } from 'vue'
import { getWebhooks, createWebhook, updateWebhook, deleteWebhook, testWebhook } from '../api'
import PasswordInput from '../components/PasswordInput.vue'

const webhooks = ref([])
const loading = ref(true)
const showCreateForm = ref(false)
const error = ref('')
const testStatus = ref({})

const form = ref({
  name: '',
  type: 'slack',
  url: '',
  secret: '',
  events: ['scan_completed'],
  min_severity: 'all',
})

const webhookTypes = [
  { value: 'slack', label: 'Slack', icon: 'slack', placeholder: 'https://hooks.slack.com/services/...' },
  { value: 'telegram', label: 'Telegram', icon: 'telegram', placeholder: 'Chat ID (e.g., -1001234567890)' },
  { value: 'discord', label: 'Discord', icon: 'discord', placeholder: 'https://discord.com/api/webhooks/...' },
  { value: 'custom', label: 'Custom', icon: 'custom', placeholder: 'https://your-server.com/webhook' },
]

const eventOptions = [
  { value: 'scan_completed', label: 'Scan Completed' },
  { value: 'score_drop', label: 'Score Drop' },
  { value: 'critical_found', label: 'Critical Found' },
]

const severityOptions = [
  { value: 'all', label: 'All' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
]

const currentType = computed(() => {
  return webhookTypes.find(t => t.value === form.value.type) || webhookTypes[0]
})

function showsSecret(type) {
  return type === 'telegram' || type === 'custom'
}

function secretLabel(type) {
  if (type === 'telegram') return 'Bot Token'
  return 'Auth Token (optional)'
}

function typeLabel(type) {
  const t = webhookTypes.find(wt => wt.value === type)
  return t ? t.label : type
}

function parseEvents(eventsStr) {
  if (!eventsStr) return []
  return eventsStr.split(',').map(e => e.trim())
}

function toggleEvent(eventValue) {
  const idx = form.value.events.indexOf(eventValue)
  if (idx >= 0) {
    form.value.events = form.value.events.filter(e => e !== eventValue)
  } else {
    form.value.events = [...form.value.events, eventValue]
  }
}

async function loadData() {
  loading.value = true
  try {
    const res = await getWebhooks()
    webhooks.value = res.data || []
  } catch (e) {
    console.error('Failed to load webhooks:', e)
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
  if (!form.value.url) {
    error.value = 'URL is required'
    return
  }
  if (form.value.events.length === 0) {
    error.value = 'Select at least one event'
    return
  }
  try {
    await createWebhook({
      name: form.value.name,
      type: form.value.type,
      url: form.value.url,
      secret: form.value.secret,
      events: form.value.events.join(','),
      min_severity: form.value.min_severity,
    })
    form.value = { name: '', type: 'slack', url: '', secret: '', events: ['scan_completed'], min_severity: 'all' }
    showCreateForm.value = false
    await loadData()
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to create webhook'
  }
}

async function handleToggle(wh) {
  try {
    await updateWebhook(wh.ID, { is_active: !wh.is_active })
    await loadData()
  } catch (e) {
    console.error('Failed to toggle webhook:', e)
  }
}

async function handleDelete(wh) {
  if (!confirm(`Delete webhook "${wh.name}"?`)) return
  try {
    await deleteWebhook(wh.ID)
    await loadData()
  } catch (e) {
    console.error('Failed to delete webhook:', e)
  }
}

async function handleTest(wh) {
  testStatus.value = { ...testStatus.value, [wh.ID]: 'sending' }
  try {
    await testWebhook(wh.ID)
    testStatus.value = { ...testStatus.value, [wh.ID]: 'success' }
    setTimeout(() => {
      testStatus.value = { ...testStatus.value, [wh.ID]: null }
    }, 3000)
  } catch (e) {
    testStatus.value = { ...testStatus.value, [wh.ID]: 'failed' }
    setTimeout(() => {
      testStatus.value = { ...testStatus.value, [wh.ID]: null }
    }, 3000)
  }
}

onMounted(loadData)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900 dark:text-white">Webhooks</h1>
        <p class="text-gray-500 dark:text-gray-400 mt-1">Send scan notifications to Slack, Telegram, Discord, or custom endpoints</p>
      </div>
      <button
        @click="showCreateForm = !showCreateForm"
        class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm"
      >
        {{ showCreateForm ? 'Cancel' : 'Add Webhook' }}
      </button>
    </div>

    <!-- Create Form -->
    <div v-if="showCreateForm" class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Add Webhook</h3>

      <div v-if="error" class="mb-4 p-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 rounded-lg text-sm">
        {{ error }}
      </div>

      <form @submit.prevent="submitCreate" class="space-y-4">
        <!-- Name -->
        <div>
          <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1">Name *</label>
          <input
            v-model="form.name"
            type="text"
            placeholder="My Slack Notifications"
            class="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-white rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            required
          />
        </div>

        <!-- Type Selector -->
        <div>
          <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1">Type *</label>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
            <button
              v-for="wt in webhookTypes"
              :key="wt.value"
              type="button"
              @click="form.type = wt.value"
              :class="[
                form.type === wt.value
                  ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-400'
                  : 'border-gray-200 dark:border-slate-600 text-gray-600 dark:text-gray-400 hover:border-gray-300'
              ]"
              class="flex items-center gap-2 px-4 py-3 border-2 rounded-lg transition-colors"
            >
              <!-- Slack icon -->
              <svg v-if="wt.value === 'slack'" class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/>
              </svg>
              <!-- Telegram icon -->
              <svg v-else-if="wt.value === 'telegram'" class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>
              </svg>
              <!-- Discord icon -->
              <svg v-else-if="wt.value === 'discord'" class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189z"/>
              </svg>
              <!-- Custom icon -->
              <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
              </svg>
              <span class="text-sm font-medium">{{ wt.label }}</span>
            </button>
          </div>
        </div>

        <!-- URL -->
        <div>
          <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1">
            {{ form.type === 'telegram' ? 'Chat ID' : 'Webhook URL' }} *
          </label>
          <input
            v-model="form.url"
            type="text"
            :placeholder="currentType.placeholder"
            class="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-white rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            required
          />
        </div>

        <!-- Secret / Token -->
        <div v-if="showsSecret(form.type)">
          <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1">{{ secretLabel(form.type) }}</label>
          <PasswordInput
            v-model="form.secret"
            :placeholder="form.type === 'telegram' ? 'Bot token from @BotFather' : 'Bearer token for Authorization header'"
            input-class="w-full px-3 py-2 pl-10 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-white rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>

        <!-- Events -->
        <div>
          <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1">Events *</label>
          <div class="flex flex-wrap gap-3">
            <label
              v-for="ev in eventOptions"
              :key="ev.value"
              class="flex items-center gap-2 px-3 py-2 border rounded-lg cursor-pointer transition-colors"
              :class="[
                form.events.includes(ev.value)
                  ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-400'
                  : 'border-gray-200 dark:border-slate-600 text-gray-600 dark:text-gray-400 hover:border-gray-300'
              ]"
            >
              <input
                type="checkbox"
                :checked="form.events.includes(ev.value)"
                @change="toggleEvent(ev.value)"
                class="rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
              />
              <span class="text-sm">{{ ev.label }}</span>
            </label>
          </div>
        </div>

        <!-- Min Severity -->
        <div>
          <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1">Minimum Severity</label>
          <select
            v-model="form.min_severity"
            class="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 dark:bg-slate-800 dark:text-white rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          >
            <option v-for="sev in severityOptions" :key="sev.value" :value="sev.value">{{ sev.label }}</option>
          </select>
        </div>

        <div>
          <button type="submit" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors">
            Create Webhook
          </button>
        </div>
      </form>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <!-- Webhooks List -->
    <div v-else class="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-gray-200 dark:border-slate-700 overflow-hidden">
      <table v-if="webhooks.length" class="w-full text-sm">
        <thead class="bg-gray-50 dark:bg-slate-800">
          <tr>
            <th class="text-right py-3 px-4 text-gray-600 dark:text-gray-400 font-medium">Name</th>
            <th class="text-right py-3 px-4 text-gray-600 dark:text-gray-400 font-medium">Type</th>
            <th class="text-right py-3 px-4 text-gray-600 dark:text-gray-400 font-medium">Events</th>
            <th class="text-right py-3 px-4 text-gray-600 dark:text-gray-400 font-medium">Status</th>
            <th class="text-center py-3 px-4 text-gray-600 dark:text-gray-400 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="wh in webhooks" :key="wh.ID" class="border-t border-gray-100 dark:border-slate-700 hover:bg-gray-50 dark:hover:bg-slate-800">
            <td class="py-3 px-4 text-gray-900 dark:text-white font-medium">{{ wh.name }}</td>
            <td class="py-3 px-4">
              <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
                :class="{
                  'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400': wh.type === 'slack',
                  'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400': wh.type === 'telegram',
                  'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400': wh.type === 'discord',
                  'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400': wh.type === 'custom',
                }"
              >
                <!-- Slack mini icon -->
                <svg v-if="wh.type === 'slack'" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313z"/>
                </svg>
                <!-- Telegram mini icon -->
                <svg v-else-if="wh.type === 'telegram'" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>
                </svg>
                <!-- Discord mini icon -->
                <svg v-else-if="wh.type === 'discord'" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189z"/>
                </svg>
                <!-- Custom mini icon -->
                <svg v-else class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
                </svg>
                {{ typeLabel(wh.type) }}
              </span>
            </td>
            <td class="py-3 px-4 text-gray-600 dark:text-gray-400 text-xs">
              <div class="flex flex-wrap gap-1">
                <span
                  v-for="ev in parseEvents(wh.events)"
                  :key="ev"
                  class="px-1.5 py-0.5 bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-gray-400 rounded text-xs"
                >
                  {{ ev.replace('_', ' ') }}
                </span>
              </div>
            </td>
            <td class="py-3 px-4">
              <button
                @click="handleToggle(wh)"
                :class="wh.is_active
                  ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                  : 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-500'"
                class="px-2 py-0.5 rounded-full text-xs font-medium cursor-pointer hover:opacity-80 transition-opacity"
              >
                {{ wh.is_active ? 'Active' : 'Inactive' }}
              </button>
            </td>
            <td class="py-3 px-4 text-center">
              <div class="flex items-center justify-center gap-2">
                <button
                  @click="handleTest(wh)"
                  :disabled="testStatus[wh.ID] === 'sending'"
                  class="text-sm px-2 py-1 rounded transition-colors"
                  :class="{
                    'text-indigo-600 hover:bg-indigo-50 dark:text-indigo-400 dark:hover:bg-indigo-900/20': !testStatus[wh.ID],
                    'text-yellow-600 dark:text-yellow-400': testStatus[wh.ID] === 'sending',
                    'text-green-600 dark:text-green-400': testStatus[wh.ID] === 'success',
                    'text-red-600 dark:text-red-400': testStatus[wh.ID] === 'failed',
                  }"
                >
                  <span v-if="testStatus[wh.ID] === 'sending'">Sending...</span>
                  <span v-else-if="testStatus[wh.ID] === 'success'">Sent!</span>
                  <span v-else-if="testStatus[wh.ID] === 'failed'">Failed</span>
                  <span v-else>Test</span>
                </button>
                <button @click="handleDelete(wh)" class="text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 text-sm px-2 py-1 rounded hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors">
                  Delete
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else class="text-center py-16 text-gray-400 dark:text-gray-500">
        <svg class="w-16 h-16 mx-auto mb-4 text-gray-300 dark:text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/>
        </svg>
        <p class="text-lg">No webhooks configured</p>
        <p class="text-sm mt-1">Add a webhook to receive scan notifications on Slack, Telegram, Discord, or a custom endpoint</p>
      </div>
    </div>
  </div>
</template>
