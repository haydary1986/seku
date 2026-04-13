<script setup>
import { ref } from 'vue'
import { discoverDomains, createBulkTargets } from '../api'

const domainQuery = ref('')
const results = ref(null)
const loading = ref(false)
const error = ref('')

const selected = ref([])
const adding = ref(false)
const addSuccess = ref('')

const presets = [
  { label: '.edu.iq', desc: 'جامعات العراق' },
  { label: '.gov.iq', desc: 'حكومي عراقي' },
  { label: '.edu.sa', desc: 'جامعات السعودية' },
  { label: '.edu.eg', desc: 'جامعات مصر' },
  { label: '.edu.jo', desc: 'جامعات الأردن' },
  { label: '.ac.uk', desc: 'جامعات بريطانيا' },
  { label: '.edu.tr', desc: 'جامعات تركيا' },
  { label: '.edu.my', desc: 'جامعات ماليزيا' },
  { label: '.ac.ir', desc: 'جامعات إيران' },
  { label: '.edu', desc: 'جامعات عالمية' },
]

async function search(domain) {
  if (domain) domainQuery.value = domain
  if (!domainQuery.value) return

  loading.value = true
  error.value = ''
  results.value = null
  selected.value = []
  addSuccess.value = ''

  try {
    const { data } = await discoverDomains(domainQuery.value)
    results.value = data
  } catch (e) {
    error.value = e.response?.data?.error || 'Discovery failed. Please try again.'
  } finally {
    loading.value = false
  }
}

function toggleSelectAll() {
  if (!results.value?.results) return
  const newSites = results.value.results.filter(r => !r.already_added)
  if (selected.value.length === newSites.length) {
    selected.value = []
  } else {
    selected.value = newSites.map(r => r.domain)
  }
}

function selectAllNew() {
  if (!results.value?.results) return
  selected.value = results.value.results.filter(r => !r.already_added).map(r => r.domain)
}

async function addToTargets() {
  if (selected.value.length === 0) return
  adding.value = true
  addSuccess.value = ''
  try {
    const targets = selected.value.map(domain => ({
      url: 'https://' + domain,
      name: domain,
      institution: '',
    }))
    await createBulkTargets(targets)
    addSuccess.value = `تمت إضافة ${targets.length} موقع بنجاح!`
    selected.value = []
    // Refresh to update already_added status
    await search()
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to add targets'
  } finally {
    adding.value = false
  }
}
</script>

<template>
  <div>
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Domain Discovery</h1>
      <p class="text-gray-500 mt-1">Search the internet for websites by domain extension and add them to your targets</p>
    </div>

    <!-- Search Section -->
    <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
      <!-- Presets -->
      <div class="flex flex-wrap gap-2 mb-4">
        <button v-for="p in presets" :key="p.label" @click="search(p.label)"
          :class="domainQuery === p.label ? 'bg-indigo-600 text-white shadow-md' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'"
          class="px-4 py-2 rounded-lg text-sm transition-all">
          <span class="font-mono font-medium">{{ p.label }}</span>
          <span class="text-xs opacity-75 mr-1">{{ p.desc }}</span>
        </button>
      </div>

      <!-- Custom Search -->
      <div class="flex gap-3">
        <div class="relative flex-1">
          <svg class="w-5 h-5 text-gray-400 absolute left-3 top-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/>
          </svg>
          <input v-model="domainQuery" @keyup.enter="search()" type="text"
            placeholder="Enter domain extension (e.g., .edu.iq, .gov.sa)"
            class="w-full pl-10 pr-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm font-mono" dir="ltr" />
        </div>
        <button @click="search()" :disabled="!domainQuery || loading"
          class="px-8 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors flex items-center gap-2 text-sm font-medium">
          <div v-if="loading" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
          <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          Discover
        </button>
      </div>

      <p v-if="loading" class="text-sm text-gray-500 mt-3 flex items-center gap-2">
        <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-indigo-600"></div>
        Searching Certificate Transparency logs... This may take a few seconds.
      </p>
    </div>

    <!-- Error -->
    <div v-if="error" class="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4 mb-6 flex items-center gap-2">
      <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
      </svg>
      {{ error }}
    </div>

    <!-- Success -->
    <div v-if="addSuccess" class="bg-green-50 border border-green-200 text-green-700 rounded-lg p-4 mb-6 flex items-center gap-2">
      <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
      </svg>
      {{ addSuccess }}
    </div>

    <!-- Results -->
    <div v-if="results" class="space-y-6">
      <!-- Summary Cards -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 text-center">
          <p class="text-4xl font-bold text-indigo-600">{{ results.total_found }}</p>
          <p class="text-sm text-gray-500 mt-1">Total Discovered</p>
          <p class="text-xs text-gray-400 mt-1">from SSL certificate records</p>
        </div>
        <div class="bg-white rounded-xl shadow-sm border border-emerald-200 p-6 text-center">
          <p class="text-4xl font-bold text-emerald-600">{{ results.new_sites }}</p>
          <p class="text-sm text-gray-500 mt-1">New Sites</p>
          <p class="text-xs text-gray-400 mt-1">not in your targets yet</p>
        </div>
        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 text-center">
          <p class="text-4xl font-bold text-gray-400">{{ results.already_added }}</p>
          <p class="text-sm text-gray-500 mt-1">Already Added</p>
          <p class="text-xs text-gray-400 mt-1">already in your targets</p>
        </div>
      </div>

      <!-- Action Bar -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-4 flex items-center justify-between flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <button @click="selectAllNew"
            class="px-4 py-2 bg-gray-100 text-gray-700 hover:bg-gray-200 rounded-lg text-sm transition-colors">
            Select All New ({{ results.new_sites }})
          </button>
          <button v-if="selected.length > 0" @click="selected = []"
            class="px-4 py-2 text-gray-500 hover:text-gray-700 text-sm">
            Clear Selection
          </button>
          <span v-if="selected.length > 0" class="text-sm text-indigo-600 font-medium">
            {{ selected.length }} selected
          </span>
        </div>
        <button @click="addToTargets" :disabled="selected.length === 0 || adding"
          class="px-6 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors flex items-center gap-2 text-sm font-medium">
          <div v-if="adding" class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
          <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
          </svg>
          Add {{ selected.length || '' }} to Targets
        </button>
      </div>

      <!-- Results Table -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-gray-50">
            <tr>
              <th class="py-3 px-3 w-10">
                <input type="checkbox" @change="toggleSelectAll"
                  :checked="selected.length > 0 && selected.length === results.results.filter(r => !r.already_added).length"
                  class="rounded text-indigo-600" />
              </th>
              <th class="text-right py-3 px-3 text-gray-600 font-medium">#</th>
              <th class="text-right py-3 px-4 text-gray-600 font-medium">Domain</th>
              <th class="text-center py-3 px-4 text-gray-600 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(r, i) in results.results" :key="r.domain"
              class="border-t border-gray-100 hover:bg-gray-50 transition-colors"
              :class="selected.includes(r.domain) ? 'bg-indigo-50' : r.already_added ? 'opacity-60' : ''">
              <td class="py-3 px-3">
                <input v-if="!r.already_added" type="checkbox" v-model="selected" :value="r.domain" class="rounded text-indigo-600" />
                <svg v-else class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
              </td>
              <td class="py-3 px-3 text-gray-400">{{ i + 1 }}</td>
              <td class="py-3 px-4">
                <a :href="r.url" target="_blank" class="font-mono text-gray-900 hover:text-indigo-600 transition-colors" dir="ltr">
                  {{ r.domain }}
                </a>
              </td>
              <td class="py-3 px-4 text-center">
                <span v-if="r.already_added" class="px-3 py-1 bg-green-100 text-green-700 rounded-full text-xs font-medium">
                  Already Added
                </span>
                <span v-else class="px-3 py-1 bg-blue-100 text-blue-700 rounded-full text-xs font-medium">
                  New
                </span>
              </td>
            </tr>
          </tbody>
        </table>

        <div v-if="results.results.length === 0" class="text-center py-12 text-gray-400">
          <p>No domains found for this extension</p>
        </div>
      </div>
    </div>
  </div>
</template>
