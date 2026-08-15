<script setup>
import { ref, onMounted, computed } from 'vue'
import { generateAPIKey, listAPIKeys, revokeAPIKey, getMyOrganization } from '../api'

const apiKeys = ref([])
const loading = ref(true)
const showGenerateForm = ref(false)
const newKeyName = ref('')
const newlyGeneratedKey = ref(null)
const org = ref(null)
const error = ref('')

const hasAPIAccess = computed(() => {
  return org.value && (org.value.plan === 'pro' || org.value.plan === 'enterprise')
})

async function loadOrg() {
  try {
    const { data } = await getMyOrganization()
    org.value = data
  } catch (e) {
    console.error('Failed to load org:', e)
  }
}

async function loadKeys() {
  loading.value = true
  try {
    const { data } = await listAPIKeys()
    apiKeys.value = data || []
  } catch (e) {
    console.error('Failed to load API keys:', e)
  } finally {
    loading.value = false
  }
}

async function createKey() {
  error.value = ''
  newlyGeneratedKey.value = null
  try {
    const { data } = await generateAPIKey({ name: newKeyName.value || 'API Key' })
    newlyGeneratedKey.value = data.key
    newKeyName.value = ''
    showGenerateForm.value = false
    await loadKeys()
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to generate API key'
    console.error('Failed to generate API key:', e)
  }
}

async function removeKey(id) {
  if (!confirm('Are you sure you want to revoke this API key? This cannot be undone.')) return
  try {
    await revokeAPIKey(id)
    await loadKeys()
  } catch (e) {
    console.error('Failed to revoke API key:', e)
  }
}

function copyKey() {
  if (newlyGeneratedKey.value) {
    navigator.clipboard.writeText(newlyGeneratedKey.value)
  }
}

onMounted(async () => {
  await loadOrg()
  if (hasAPIAccess.value) {
    await loadKeys()
  } else {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <div class="flex items-center justify-end mb-8">
      <button
        v-if="hasAPIAccess"
        @click="showGenerateForm = !showGenerateForm"
        class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm"
      >
        Generate API Key
      </button>
    </div>

    <!-- No access banner -->
    <div v-if="!hasAPIAccess && !loading" class="bg-yellow-50 border border-yellow-200 rounded-xl p-8 text-center">
      <svg class="w-16 h-16 mx-auto mb-4 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
      </svg>
      <h3 class="text-xl font-semibold text-gray-900 mb-2">API Access Requires Pro or Enterprise Plan</h3>
      <p class="text-gray-600 mb-4">Upgrade your plan to access the Seku API and automate your security scanning workflow.</p>
      <router-link to="/upgrade" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 inline-block">
        Upgrade Now
      </router-link>
    </div>

    <template v-if="hasAPIAccess">
      <!-- Error message -->
      <div v-if="error" class="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4 mb-6">
        {{ error }}
      </div>

      <!-- Newly generated key (show once) -->
      <div v-if="newlyGeneratedKey" class="bg-green-50 border border-green-200 rounded-xl p-6 mb-6">
        <div class="flex items-start gap-3">
          <svg class="w-6 h-6 text-green-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          <div class="flex-1">
            <h3 class="font-semibold text-green-800 mb-2">API Key Generated Successfully</h3>
            <p class="text-sm text-green-700 mb-3">Copy this key now. You will not be able to see it again!</p>
            <div class="flex items-center gap-2">
              <code class="bg-white text-gray-800 px-4 py-2 rounded border border-green-200 text-sm font-mono flex-1 break-all">
                {{ newlyGeneratedKey }}
              </code>
              <button
                @click="copyKey"
                class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm flex-shrink-0"
              >
                Copy
              </button>
            </div>
          </div>
        </div>
        <button @click="newlyGeneratedKey = null" class="mt-3 text-sm text-green-600 hover:text-green-800 underline">
          Dismiss
        </button>
      </div>

      <!-- Generate form -->
      <div v-if="showGenerateForm" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Generate New API Key</h3>
        <form @submit.prevent="createKey" class="flex gap-4 items-end">
          <div class="flex-1">
            <label class="block text-sm text-gray-600 mb-1">Key Name</label>
            <input
              v-model="newKeyName"
              type="text"
              placeholder="e.g., CI/CD Pipeline, Monitoring Script"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
          </div>
          <button type="submit" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
            Generate
          </button>
        </form>
      </div>

      <!-- Loading -->
      <div v-if="loading" class="flex justify-center py-20">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>

      <!-- Keys list -->
      <div v-else class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden mb-8">
        <table v-if="apiKeys.length" class="w-full text-sm">
          <thead class="bg-gray-50">
            <tr>
              <th class="text-right py-3 px-4 text-gray-600 font-medium">Name</th>
              <th class="text-right py-3 px-4 text-gray-600 font-medium">Key</th>
              <th class="text-right py-3 px-4 text-gray-600 font-medium">Created</th>
              <th class="text-right py-3 px-4 text-gray-600 font-medium">Last Used</th>
              <th class="text-center py-3 px-4 text-gray-600 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="key in apiKeys" :key="key.id" class="border-t border-gray-100 hover:bg-gray-50">
              <td class="py-3 px-4 text-gray-900 font-medium">{{ key.name }}</td>
              <td class="py-3 px-4">
                <code class="bg-gray-100 text-gray-600 px-2 py-1 rounded text-xs font-mono">{{ key.key_prefix }}</code>
              </td>
              <td class="py-3 px-4 text-gray-500 text-xs">
                {{ key.created_at ? new Date(key.created_at).toLocaleDateString() : '-' }}
              </td>
              <td class="py-3 px-4 text-gray-500 text-xs">
                {{ key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never' }}
              </td>
              <td class="py-3 px-4 text-center">
                <button @click="removeKey(key.id)" class="text-red-500 hover:text-red-700 text-sm">
                  Revoke
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="text-center py-12 text-gray-400">
          <svg class="w-12 h-12 mx-auto mb-3 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
          </svg>
          <p>No API keys yet</p>
          <p class="text-sm mt-1">Generate your first key to start using the API</p>
        </div>
      </div>

      <!-- API Documentation section -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 class="text-xl font-semibold text-gray-900 mb-4">API Quick Reference</h3>
        <p class="text-gray-600 mb-6">Use your API key in the <code class="bg-gray-100 px-1 rounded text-sm">X-API-Key</code> header for all requests.</p>

        <div class="space-y-4">
          <!-- Example: List targets -->
          <div class="bg-gray-50 rounded-lg p-4">
            <h4 class="text-sm font-semibold text-gray-700 mb-2">List Targets</h4>
            <code class="text-xs text-gray-600 block whitespace-pre-wrap font-mono">curl -H 'X-API-Key: vsk_your_key_here' https://sec.erticaz.com/api/targets</code>
          </div>

          <!-- Example: Start a scan -->
          <div class="bg-gray-50 rounded-lg p-4">
            <h4 class="text-sm font-semibold text-gray-700 mb-2">Start a Scan</h4>
            <code class="text-xs text-gray-600 block whitespace-pre-wrap font-mono">curl -X POST -H 'X-API-Key: vsk_your_key_here' \
  -H 'Content-Type: application/json' \
  -d '{"name":"My Scan"}' \
  https://sec.erticaz.com/api/scans/start</code>
          </div>

          <!-- Example: Get results -->
          <div class="bg-gray-50 rounded-lg p-4">
            <h4 class="text-sm font-semibold text-gray-700 mb-2">Get Scan Results</h4>
            <code class="text-xs text-gray-600 block whitespace-pre-wrap font-mono">curl -H 'X-API-Key: vsk_your_key_here' https://sec.erticaz.com/api/results/1</code>
          </div>

          <!-- Example: Download PDF -->
          <div class="bg-gray-50 rounded-lg p-4">
            <h4 class="text-sm font-semibold text-gray-700 mb-2">Download PDF Report</h4>
            <code class="text-xs text-gray-600 block whitespace-pre-wrap font-mono">curl -H 'X-API-Key: vsk_your_key_here' -o report.pdf https://sec.erticaz.com/api/results/1/pdf</code>
          </div>
        </div>

        <div class="mt-6 pt-4 border-t border-gray-200">
          <a href="/api/docs" target="_blank" class="text-indigo-600 hover:text-indigo-800 text-sm font-medium">
            View Full API Documentation &rarr;
          </a>
        </div>
      </div>
    </template>
  </div>
</template>
