<script setup>
import { ref, onMounted } from 'vue'
import { getSettings, updateSettings, getEmailConfig, updateEmailConfig, testEmailConfig, getProxyStats, refreshProxies } from '../api'

const settings = ref({
  ai_provider: 'deepseek',
  ai_api_key: '',
  ai_model: '',
  ai_base_url: '',
})
const loading = ref(true)
const saving = ref(false)
const message = ref('')

// Email config state
const emailConfig = ref({
  smtp_host: '',
  smtp_port: 587,
  smtp_user: '',
  smtp_pass: '',
  from_email: '',
  from_name: 'Seku',
})
const emailSaving = ref(false)
const emailMessage = ref('')
const emailTesting = ref(false)
const testEmailAddress = ref('')

// Proxy state
const proxyStats = ref(null)
const proxyRefreshing = ref(false)
const proxyToggling = ref(false)

const providers = [
  { value: 'deepseek', label: 'DeepSeek', defaultModel: 'deepseek-chat', defaultUrl: 'https://api.deepseek.com/v1' },
  { value: 'openai', label: 'OpenAI', defaultModel: 'gpt-4o-mini', defaultUrl: 'https://api.openai.com/v1' },
  { value: 'anthropic', label: 'Anthropic Claude', defaultModel: 'claude-sonnet-4-6-20250514', defaultUrl: 'https://api.anthropic.com/v1' },
  { value: 'google', label: 'Google Gemini', defaultModel: 'gemini-2.0-flash', defaultUrl: 'https://generativelanguage.googleapis.com/v1beta' },
  { value: 'ollama', label: 'Ollama (Local)', defaultModel: 'llama3', defaultUrl: 'http://localhost:11434/v1' },
  { value: 'custom', label: 'Custom (OpenAI-compatible)', defaultModel: '', defaultUrl: '' },
]

function onProviderChange() {
  const provider = providers.find(p => p.value === settings.value.ai_provider)
  if (provider) {
    settings.value.ai_model = provider.defaultModel
    settings.value.ai_base_url = provider.defaultUrl
  }
}

async function loadSettings() {
  loading.value = true
  try {
    const [settingsRes, emailRes] = await Promise.all([getSettings(), getEmailConfig()])
    const data = settingsRes.data
    if (data.ai_provider) settings.value.ai_provider = data.ai_provider
    if (data.ai_api_key) settings.value.ai_api_key = data.ai_api_key
    if (data.ai_model) settings.value.ai_model = data.ai_model
    if (data.ai_base_url) settings.value.ai_base_url = data.ai_base_url

    if (emailRes.data) {
      const ec = emailRes.data
      if (ec.smtp_host) emailConfig.value.smtp_host = ec.smtp_host
      if (ec.smtp_port) emailConfig.value.smtp_port = ec.smtp_port
      if (ec.smtp_user) emailConfig.value.smtp_user = ec.smtp_user
      if (ec.smtp_pass) emailConfig.value.smtp_pass = ec.smtp_pass
      if (ec.from_email) emailConfig.value.from_email = ec.from_email
      if (ec.from_name) emailConfig.value.from_name = ec.from_name
    }
  } catch (e) {
    console.error('Failed to load settings:', e)
  } finally {
    loading.value = false
  }
}

async function saveSettings() {
  saving.value = true
  message.value = ''
  try {
    await updateSettings(settings.value)
    message.value = 'Settings saved successfully!'
    setTimeout(() => message.value = '', 3000)
  } catch (e) {
    message.value = 'Failed to save: ' + (e.response?.data?.error || e.message)
  } finally {
    saving.value = false
  }
}

async function saveEmailConfig() {
  emailSaving.value = true
  emailMessage.value = ''
  try {
    await updateEmailConfig(emailConfig.value)
    emailMessage.value = 'Email settings saved successfully!'
    setTimeout(() => emailMessage.value = '', 3000)
  } catch (e) {
    emailMessage.value = 'Failed to save: ' + (e.response?.data?.error || e.message)
  } finally {
    emailSaving.value = false
  }
}

async function sendTestEmail() {
  if (!testEmailAddress.value) {
    emailMessage.value = 'Failed to save: Enter an email address to send a test'
    return
  }
  emailTesting.value = true
  emailMessage.value = ''
  try {
    await testEmailConfig(testEmailAddress.value)
    emailMessage.value = 'Test email sent successfully!'
    setTimeout(() => emailMessage.value = '', 3000)
  } catch (e) {
    emailMessage.value = 'Failed to save: ' + (e.response?.data?.error || e.message)
  } finally {
    emailTesting.value = false
  }
}

async function loadProxyStats() {
  try {
    const { data } = await getProxyStats()
    proxyStats.value = data
  } catch { /* proxy stats not available */ }
}

async function toggleProxy() {
  proxyToggling.value = true
  const newState = !(proxyStats.value?.enabled)
  try {
    await updateSettings({ proxy_enabled: newState ? 'true' : 'false' })
    await loadProxyStats()
    // If enabling, poll for stats every 3s until proxies appear
    if (newState) {
      proxyRefreshing.value = true
      const poll = setInterval(async () => {
        await loadProxyStats()
        if (proxyStats.value?.healthy_count > 0 || proxyStats.value?.total_proxies > 0) {
          proxyRefreshing.value = false
          clearInterval(poll)
        }
      }, 3000)
      // Stop polling after 2 minutes max
      setTimeout(() => { clearInterval(poll); proxyRefreshing.value = false }, 120000)
    }
  } catch (e) {
    console.error('Failed to toggle proxy:', e)
  } finally {
    proxyToggling.value = false
  }
}

async function doRefreshProxies() {
  proxyRefreshing.value = true
  try {
    await refreshProxies()
    // Wait a bit for refresh to start, then poll
    setTimeout(async () => {
      await loadProxyStats()
      proxyRefreshing.value = false
    }, 5000)
  } catch (e) {
    proxyRefreshing.value = false
    console.error('Proxy refresh failed:', e)
  }
}

onMounted(() => {
  loadSettings()
  loadProxyStats()
})
</script>

<template>
  <div>
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Settings</h1>
      <p class="text-gray-500 mt-1">Configure AI analysis, email alerts, and system settings</p>
    </div>

    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else class="max-w-2xl">
      <!-- AI Configuration -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
            <svg class="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
            </svg>
          </div>
          <div>
            <h3 class="text-lg font-semibold text-gray-900">AI Analysis Configuration</h3>
            <p class="text-sm text-gray-500">Configure AI to analyze scan results and suggest fixes</p>
          </div>
        </div>

        <form @submit.prevent="saveSettings" class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">AI Provider</label>
            <select v-model="settings.ai_provider" @change="onProviderChange"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500">
              <option v-for="p in providers" :key="p.value" :value="p.value">{{ p.label }}</option>
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">API Key</label>
            <input v-model="settings.ai_api_key" type="password"
              placeholder="sk-..."
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            <p class="text-xs text-gray-400 mt-1">Your API key is stored securely on the server</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Model</label>
            <input v-model="settings.ai_model" type="text"
              placeholder="deepseek-chat"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Base URL</label>
            <input v-model="settings.ai_base_url" type="text"
              placeholder="https://api.deepseek.com/v1"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
          </div>

          <div v-if="message" :class="['px-4 py-3 rounded-lg text-sm', message.includes('Failed') ? 'bg-red-50 text-red-700' : 'bg-green-50 text-green-700']">
            {{ message }}
          </div>

          <button type="submit" :disabled="saving"
            class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50">
            {{ saving ? 'Saving...' : 'Save Settings' }}
          </button>
        </form>
      </div>

      <!-- Email / SMTP Configuration -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
            <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
            </svg>
          </div>
          <div>
            <h3 class="text-lg font-semibold text-gray-900">Email Notifications (SMTP)</h3>
            <p class="text-sm text-gray-500">Configure SMTP to send scan completion emails to users</p>
          </div>
        </div>

        <form @submit.prevent="saveEmailConfig" class="space-y-4">
          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">SMTP Host</label>
              <input v-model="emailConfig.smtp_host" type="text"
                placeholder="smtp.gmail.com"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">SMTP Port</label>
              <input v-model.number="emailConfig.smtp_port" type="number"
                placeholder="587"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">SMTP Username</label>
              <input v-model="emailConfig.smtp_user" type="text"
                placeholder="user@example.com"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">SMTP Password</label>
              <input v-model="emailConfig.smtp_pass" type="password"
                placeholder="App password..."
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">From Email</label>
              <input v-model="emailConfig.from_email" type="email"
                placeholder="noreply@example.com"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 font-mono text-sm" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">From Name</label>
              <input v-model="emailConfig.from_name" type="text"
                placeholder="Seku"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
            </div>
          </div>

          <div v-if="emailMessage" :class="['px-4 py-3 rounded-lg text-sm', emailMessage.includes('Failed') ? 'bg-red-50 text-red-700' : 'bg-green-50 text-green-700']">
            {{ emailMessage }}
          </div>

          <div class="flex items-center gap-3">
            <button type="submit" :disabled="emailSaving"
              class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50">
              {{ emailSaving ? 'Saving...' : 'Save Email Settings' }}
            </button>
          </div>

          <!-- Test email -->
          <div class="border-t border-gray-200 pt-4 mt-4">
            <label class="block text-sm font-medium text-gray-700 mb-1">Send Test Email</label>
            <div class="flex gap-2">
              <input v-model="testEmailAddress" type="email"
                placeholder="your@email.com"
                class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 text-sm" />
              <button type="button" @click="sendTestEmail" :disabled="emailTesting"
                class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 text-sm whitespace-nowrap">
                {{ emailTesting ? 'Sending...' : 'Send Test' }}
              </button>
            </div>
            <p class="text-xs text-gray-400 mt-1">Save SMTP settings first, then send a test to verify the configuration</p>
          </div>
        </form>
      </div>

      <!-- How it works -->
      <div class="bg-blue-50 border border-blue-200 rounded-xl p-6">
        <h4 class="font-semibold text-blue-900 mb-3">How AI Analysis Works</h4>
        <ol class="list-decimal list-inside space-y-2 text-sm text-blue-800">
          <li>Configure your AI provider above (DeepSeek is recommended - affordable and capable)</li>
          <li>Run a security scan on your target websites</li>
          <li>Open any scan result and click <strong>"AI Analysis"</strong></li>
          <li>The AI will analyze all findings and provide:
            <ul class="list-disc list-inside mr-4 mt-1 text-blue-700">
              <li>Executive summary of security posture</li>
              <li>Detailed fix instructions for each vulnerability</li>
              <li>Step-by-step roadmap to achieve 100% score</li>
              <li>Configuration examples and code snippets</li>
            </ul>
          </li>
        </ol>
      </div>
    </div>

    <!-- Proxy Rotation Configuration -->
    <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mt-6">
      <div class="flex items-center gap-3 mb-6">
        <div class="w-10 h-10 bg-orange-100 rounded-lg flex items-center justify-center">
          <svg class="w-5 h-5 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
        </div>
        <div>
          <h3 class="text-lg font-semibold text-gray-900">Proxy Rotation</h3>
          <p class="text-sm text-gray-500">Route scan requests through rotating proxies to avoid IP blocking</p>
        </div>
      </div>

      <!-- Toggle -->
      <div class="flex items-center justify-between p-4 bg-gray-50 rounded-lg mb-4">
        <div>
          <p class="font-medium text-gray-900">Enable Proxy Rotation</p>
          <p class="text-sm text-gray-500">Uses free open-source proxy lists, auto-refreshed every 30 minutes</p>
        </div>
        <button @click="toggleProxy" :disabled="proxyToggling"
          :class="proxyStats?.enabled ? 'bg-green-500' : 'bg-gray-300'"
          class="relative w-14 h-7 rounded-full transition-colors duration-200 focus:outline-none">
          <span :class="proxyStats?.enabled ? 'translate-x-7' : 'translate-x-1'"
            class="absolute top-1 w-5 h-5 bg-white rounded-full shadow transition-transform duration-200"></span>
        </button>
      </div>

      <!-- Stats -->
      <div v-if="proxyStats" class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        <div class="bg-indigo-50 rounded-lg p-3 text-center">
          <p class="text-2xl font-bold text-indigo-700">{{ proxyStats.total_proxies }}</p>
          <p class="text-xs text-indigo-500">Total Proxies</p>
        </div>
        <div class="bg-green-50 rounded-lg p-3 text-center">
          <p class="text-2xl font-bold text-green-700">{{ proxyStats.healthy_count }}</p>
          <p class="text-xs text-green-500">Healthy</p>
        </div>
        <div class="bg-red-50 rounded-lg p-3 text-center">
          <p class="text-2xl font-bold text-red-700">{{ proxyStats.dead_count }}</p>
          <p class="text-xs text-red-500">Dead</p>
        </div>
        <div class="bg-gray-50 rounded-lg p-3 text-center">
          <p class="text-sm font-medium text-gray-700">{{ proxyStats.mode }}</p>
          <p class="text-xs text-gray-500">Mode</p>
        </div>
      </div>

      <div v-if="proxyStats?.last_refresh" class="text-xs text-gray-400 mb-3">
        Last refresh: {{ new Date(proxyStats.last_refresh).toLocaleString() }}
      </div>

      <!-- Actions -->
      <button @click="doRefreshProxies" :disabled="proxyRefreshing"
        class="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 transition-colors text-sm flex items-center gap-2">
        <div v-if="proxyRefreshing" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
        <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
        </svg>
        {{ proxyRefreshing ? 'Refreshing...' : 'Refresh Proxy List' }}
      </button>
    </div>
  </div>
</template>
