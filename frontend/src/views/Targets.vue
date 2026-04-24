<script setup>
import { ref, computed, onMounted } from 'vue'
import { getTargets, createTarget, createBulkTargets, deleteTarget, cleanupDeadTargets, cleanupDuplicateTargets, initiateVerification, getVerificationStatus, checkVerification, getTags, createTag, deleteTag, tagTarget, untagTarget, getTargetTags } from '../api'

const targets = ref([])
const loading = ref(true)
const showAddForm = ref(false)
const showBulkForm = ref(false)
const searchQuery = ref('')
const currentPage = ref(1)
let searchTimer = null
function debouncedSearch() {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => { currentPage.value = 1; loadTargets() }, 400)
}
const totalPages = ref(1)
const totalTargets = ref(0)
const cleanupLoading = ref(false)
const cleanupResult = ref(null)
const verificationStatuses = ref({})
const verifyingTarget = ref(null)
const verificationMessage = ref('')
const verificationError = ref('')

const newTarget = ref({ url: '', name: '', institution: '' })
const bulkText = ref('')

// --- Tag Management (Feature 3) ---
const allTags = ref([])
const targetTags = ref({}) // { targetId: [tag, ...] }
const showManageTags = ref(false)
const newTagName = ref('')
const newTagColor = ref('#6366f1')
const tagFilterId = ref('all')
const tagDropdownTarget = ref(null) // which target's "Add Tag" dropdown is open

const tagColors = ['#6366f1', '#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316', '#64748b']

const filteredTargets = computed(() => {
  if (tagFilterId.value === 'all') return targets.value
  return targets.value.filter(t => {
    const tags = targetTags.value[t.ID] || []
    return tags.some(tag => tag.ID === parseInt(tagFilterId.value))
  })
})

// Check if current user is admin (admins skip domain verification)
const user = JSON.parse(localStorage.getItem('user') || '{}')
const isAdmin = user.role === 'admin'

async function loadTargets() {
  loading.value = true
  try {
    const { data } = await getTargets({ page: currentPage.value, limit: 50, search: searchQuery.value || undefined })
    targets.value = data.data || data
    totalPages.value = data.pages || 1
    totalTargets.value = data.total || targets.value.length
    // Only load verification status for non-admin users
    if (!isAdmin) {
      for (const target of targets.value) {
        await loadVerificationStatus(target.ID)
      }
    }
  } catch (e) {
    console.error('Failed to load targets:', e)
  } finally {
    loading.value = false
  }
}

async function loadVerificationStatus(targetId) {
  try {
    const { data } = await getVerificationStatus(targetId)
    verificationStatuses.value[targetId] = data
  } catch (e) {
    verificationStatuses.value[targetId] = { verified: false, initiated: false }
  }
}

async function startVerification(targetId) {
  verificationMessage.value = ''
  verificationError.value = ''
  try {
    const { data } = await initiateVerification(targetId)
    verificationStatuses.value[targetId] = {
      verified: false,
      initiated: true,
      verification: data.verification,
      txt_record: data.txt_record,
      domain: data.domain,
      instructions: data.instructions,
    }
    verifyingTarget.value = targetId
  } catch (e) {
    console.error('Failed to initiate verification:', e)
    verificationError.value = 'Failed to initiate verification'
  }
}

async function verifyDomain(targetId) {
  verificationMessage.value = ''
  verificationError.value = ''
  try {
    const { data } = await checkVerification(targetId)
    if (data.verified) {
      verificationMessage.value = 'Domain verified successfully!'
      await loadVerificationStatus(targetId)
    } else {
      verificationError.value = data.message || 'Verification failed. TXT record not found.'
    }
  } catch (e) {
    console.error('Failed to verify domain:', e)
    verificationError.value = 'Verification check failed. Please try again.'
  }
}

function isVerified(targetId) {
  return verificationStatuses.value[targetId]?.verified === true
}

function isInitiated(targetId) {
  return verificationStatuses.value[targetId]?.initiated === true
}

function getTxtRecord(targetId) {
  return verificationStatuses.value[targetId]?.txt_record || ''
}

function getDomain(targetId) {
  return verificationStatuses.value[targetId]?.domain || ''
}

async function addTarget() {
  if (!newTarget.value.url) return
  try {
    await createTarget(newTarget.value)
    newTarget.value = { url: '', name: '', institution: '' }
    showAddForm.value = false
    await loadTargets()
  } catch (e) {
    console.error('Failed to add target:', e)
  }
}

async function addBulkTargets() {
  const lines = bulkText.value.trim().split('\n').filter(l => l.trim())
  if (lines.length === 0) return

  const bulkTargets = lines.map(line => {
    const parts = line.split(',').map(p => p.trim())
    return {
      url: parts[0] || '',
      name: parts[1] || '',
      institution: parts[2] || '',
    }
  }).filter(t => t.url)

  try {
    await createBulkTargets(bulkTargets)
    bulkText.value = ''
    showBulkForm.value = false
    await loadTargets()
  } catch (e) {
    console.error('Failed to add bulk targets:', e)
  }
}

async function removeTarget(id) {
  if (!confirm('Are you sure you want to delete this target?')) return
  try {
    await deleteTarget(id)
    await loadTargets()
  } catch (e) {
    console.error('Failed to delete target:', e)
  }
}

// --- Tag Functions ---

async function loadAllTags() {
  try {
    const { data } = await getTags()
    allTags.value = data || []
  } catch (e) {
    console.error('Failed to load tags:', e)
  }
}

async function loadTargetTagsForAll() {
  for (const target of targets.value) {
    try {
      const { data } = await getTargetTags(target.ID)
      targetTags.value = { ...targetTags.value, [target.ID]: data || [] }
    } catch {
      targetTags.value = { ...targetTags.value, [target.ID]: [] }
    }
  }
}

function getTagsForTarget(targetId) {
  return targetTags.value[targetId] || []
}

function getAvailableTagsForTarget(targetId) {
  const assigned = getTagsForTarget(targetId).map(t => t.ID)
  return allTags.value.filter(t => !assigned.includes(t.ID))
}

async function addNewTag() {
  if (!newTagName.value.trim()) return
  try {
    await createTag({ name: newTagName.value.trim(), color: newTagColor.value })
    newTagName.value = ''
    newTagColor.value = '#6366f1'
    await loadAllTags()
  } catch (e) {
    alert(e.response?.data?.error || 'Failed to create tag')
  }
}

async function removeTag(tagId) {
  if (!confirm('Delete this tag? It will be removed from all targets.')) return
  try {
    await deleteTag(tagId)
    await loadAllTags()
    await loadTargetTagsForAll()
  } catch (e) {
    console.error('Failed to delete tag:', e)
  }
}

async function assignTag(targetId, tagId) {
  try {
    await tagTarget(targetId, tagId)
    const { data } = await getTargetTags(targetId)
    targetTags.value = { ...targetTags.value, [targetId]: data || [] }
    tagDropdownTarget.value = null
  } catch (e) {
    alert(e.response?.data?.error || 'Failed to assign tag')
  }
}

async function removeTagFromTarget(targetId, tagId) {
  try {
    await untagTarget(targetId, tagId)
    const { data } = await getTargetTags(targetId)
    targetTags.value = { ...targetTags.value, [targetId]: data || [] }
  } catch (e) {
    console.error('Failed to remove tag:', e)
  }
}

async function scanDeadTargets() {
  cleanupLoading.value = true
  cleanupResult.value = null
  try {
    const { data } = await cleanupDeadTargets(true) // dry run first
    cleanupResult.value = data
  } catch (e) {
    alert(e.response?.data?.error || 'Cleanup check failed')
  } finally {
    cleanupLoading.value = false
  }
}

async function confirmDeleteDead() {
  if (!cleanupResult.value?.dead_count) return
  if (!confirm(`Are you sure you want to delete ${cleanupResult.value.dead_count} dead targets and all their scan results?`)) return
  cleanupLoading.value = true
  try {
    const { data } = await cleanupDeadTargets(false) // actual delete
    cleanupResult.value = data
    await loadTargets()
  } catch (e) {
    alert(e.response?.data?.error || 'Delete failed')
  } finally {
    cleanupLoading.value = false
  }
}

const duplicatesResult = ref(null)
const duplicatesLoading = ref(false)

async function scanDuplicates() {
  duplicatesLoading.value = true
  duplicatesResult.value = null
  try {
    const { data } = await cleanupDuplicateTargets(true)
    duplicatesResult.value = data
  } catch (e) {
    alert(e.response?.data?.error || 'Duplicates check failed')
  } finally {
    duplicatesLoading.value = false
  }
}

async function confirmDeleteDuplicates() {
  if (!duplicatesResult.value?.duplicate_count) return
  if (!confirm(`حذف ${duplicatesResult.value.duplicate_count} هدف مكرر؟\n\nسيتم الاحتفاظ بالنسخة الأقدم (أقل ID) من كل موقع مكرر.\nلا يمكن التراجع عن هذا الإجراء.`)) return
  duplicatesLoading.value = true
  try {
    const { data } = await cleanupDuplicateTargets(false)
    duplicatesResult.value = data
    await loadTargets()
  } catch (e) {
    alert(e.response?.data?.error || 'Delete failed')
  } finally {
    duplicatesLoading.value = false
  }
}

onMounted(async () => {
  await loadTargets()
  await loadAllTags()
  await loadTargetTagsForAll()
})
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">Targets</h1>
        <p class="text-gray-500 mt-1">Manage websites to scan ({{ totalTargets }} total)</p>
      </div>
      <div class="flex gap-2 flex-wrap">
        <button @click="scanDeadTargets" :disabled="cleanupLoading"
          class="px-3 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors text-sm flex items-center gap-1.5">
          <div v-if="cleanupLoading" class="animate-spin rounded-full h-3.5 w-3.5 border-b-2 border-white"></div>
          <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
          </svg>
          Cleanup Dead
        </button>
        <button @click="scanDuplicates" :disabled="duplicatesLoading"
          class="px-3 py-2 bg-amber-600 text-white rounded-lg hover:bg-amber-700 disabled:opacity-50 transition-colors text-sm flex items-center gap-1.5"
          title="البحث عن المواقع المكررة">
          <div v-if="duplicatesLoading" class="animate-spin rounded-full h-3.5 w-3.5 border-b-2 border-white"></div>
          <svg v-else class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2"/>
          </svg>
          Remove Duplicates
        </button>
        <button
          @click="showManageTags = !showManageTags; showAddForm = false; showBulkForm = false"
          class="px-3 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors text-sm"
        >
          Manage Tags
        </button>
        <button
          @click="showBulkForm = !showBulkForm; showAddForm = false; showManageTags = false"
          class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors text-sm"
        >
          Bulk Add
        </button>
        <button
          @click="showAddForm = !showAddForm; showBulkForm = false; showManageTags = false"
          class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm"
        >
          Add Target
        </button>
      </div>
    </div>

    <!-- Search Bar -->
    <div class="mb-4">
      <div class="relative">
        <input v-model="searchQuery" @input="debouncedSearch" type="text" placeholder="Search targets by URL, name, or institution..."
          class="w-full pl-10 pr-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-sm" />
        <svg class="w-5 h-5 text-gray-400 absolute left-3 top-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
        </svg>
      </div>
    </div>

    <!-- Cleanup Dead Targets Result -->
    <div v-if="cleanupResult" class="mb-4 bg-white rounded-xl shadow-sm border border-gray-200 p-5">
      <div class="flex items-center justify-between mb-3">
        <div class="flex items-center gap-2">
          <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
          </svg>
          <h3 class="font-semibold text-gray-900">Cleanup Results</h3>
        </div>
        <button @click="cleanupResult = null" class="text-gray-400 hover:text-gray-600">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
        </button>
      </div>

      <div class="grid grid-cols-3 gap-3 mb-3">
        <div class="bg-gray-50 rounded-lg p-3 text-center">
          <p class="text-xl font-bold text-gray-700">{{ cleanupResult.total_checked }}</p>
          <p class="text-xs text-gray-500">Checked</p>
        </div>
        <div class="bg-green-50 rounded-lg p-3 text-center">
          <p class="text-xl font-bold text-green-600">{{ cleanupResult.alive_count }}</p>
          <p class="text-xs text-green-600">Alive</p>
        </div>
        <div class="bg-red-50 rounded-lg p-3 text-center">
          <p class="text-xl font-bold text-red-600">{{ cleanupResult.dead_count }}</p>
          <p class="text-xs text-red-600">Dead</p>
        </div>
      </div>

      <div v-if="cleanupResult.dead_count > 0 && cleanupResult.dry_run" class="space-y-2">
        <div v-for="d in cleanupResult.dead_targets" :key="d.id" class="flex items-center gap-2 text-sm py-1 border-b border-gray-100 last:border-0">
          <span class="w-2 h-2 rounded-full bg-red-400 flex-shrink-0"></span>
          <span class="text-gray-700 truncate">{{ d.name || d.url }}</span>
          <span class="text-xs text-gray-400 truncate" dir="ltr">{{ d.url }}</span>
        </div>
        <button @click="confirmDeleteDead"
          class="w-full mt-3 px-4 py-2.5 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors text-sm font-medium flex items-center justify-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
          </svg>
          Delete {{ cleanupResult.dead_count }} Dead Targets
        </button>
      </div>

      <div v-else-if="cleanupResult.dead_count === 0" class="text-center py-2">
        <p class="text-green-600 font-medium">All targets are alive!</p>
      </div>

      <div v-else-if="!cleanupResult.dry_run" class="text-center py-2">
        <p class="text-green-600 font-medium">{{ cleanupResult.message }}</p>
      </div>
    </div>

    <!-- Duplicates Result -->
    <div v-if="duplicatesResult" class="mb-4 bg-white rounded-xl shadow-sm border border-gray-200 p-5">
      <div class="flex items-center justify-between mb-3">
        <div class="flex items-center gap-2">
          <svg class="w-5 h-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2"/>
          </svg>
          <h3 class="font-semibold text-gray-900">Duplicate Targets</h3>
        </div>
        <button @click="duplicatesResult = null" class="text-gray-400 hover:text-gray-600">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
        </button>
      </div>

      <div class="grid grid-cols-3 gap-3 mb-3">
        <div class="bg-gray-50 rounded-lg p-3 text-center">
          <p class="text-xl font-bold text-gray-700">{{ duplicatesResult.total_checked }}</p>
          <p class="text-xs text-gray-500">Checked</p>
        </div>
        <div class="bg-green-50 rounded-lg p-3 text-center">
          <p class="text-xl font-bold text-green-600">{{ duplicatesResult.unique_count }}</p>
          <p class="text-xs text-green-600">Unique</p>
        </div>
        <div class="bg-amber-50 rounded-lg p-3 text-center">
          <p class="text-xl font-bold text-amber-600">{{ duplicatesResult.duplicate_count }}</p>
          <p class="text-xs text-amber-600">Duplicates</p>
        </div>
      </div>

      <div v-if="duplicatesResult.duplicate_count > 0 && duplicatesResult.dry_run" class="space-y-2">
        <div v-for="d in duplicatesResult.duplicates" :key="d.id" class="flex items-center gap-2 text-sm py-1 border-b border-gray-100 last:border-0">
          <span class="w-2 h-2 rounded-full bg-amber-400 flex-shrink-0"></span>
          <span class="text-gray-700 truncate">{{ d.name || d.url }}</span>
          <span class="text-xs text-gray-400 truncate" dir="ltr">{{ d.url }}</span>
          <span class="text-xs text-gray-400 ml-auto">→ keep #{{ d.kept_id }}</span>
        </div>
        <button @click="confirmDeleteDuplicates"
          class="w-full mt-3 px-4 py-2.5 bg-amber-600 text-white rounded-lg hover:bg-amber-700 transition-colors text-sm font-medium flex items-center justify-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
          </svg>
          Delete {{ duplicatesResult.duplicate_count }} Duplicate Targets
        </button>
      </div>

      <div v-else-if="duplicatesResult.duplicate_count === 0" class="text-center py-2">
        <p class="text-green-600 font-medium">No duplicates found!</p>
      </div>

      <div v-else-if="!duplicatesResult.dry_run" class="text-center py-2">
        <p class="text-green-600 font-medium">{{ duplicatesResult.message }}</p>
      </div>
    </div>

    <!-- Add Single Target Form -->
    <div v-if="showAddForm" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-900 mb-4">Add New Target</h3>
      <form @submit.prevent="addTarget" class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label class="block text-sm text-gray-600 mb-1">URL *</label>
          <input
            v-model="newTarget.url"
            type="text"
            placeholder="example.edu.iq"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            required
          />
        </div>
        <div>
          <label class="block text-sm text-gray-600 mb-1">Name</label>
          <input
            v-model="newTarget.name"
            type="text"
            placeholder="University of Baghdad"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
        <div>
          <label class="block text-sm text-gray-600 mb-1">Institution</label>
          <input
            v-model="newTarget.institution"
            type="text"
            placeholder="University"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
        <div class="md:col-span-3">
          <button type="submit" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
            Add Target
          </button>
        </div>
      </form>
    </div>

    <!-- Bulk Add Form -->
    <div v-if="showBulkForm" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-900 mb-2">Bulk Add Targets</h3>
      <p class="text-sm text-gray-500 mb-4">Enter one target per line: URL, Name, Institution (comma separated)</p>
      <textarea
        v-model="bulkText"
        rows="8"
        placeholder="uobaghdad.edu.iq, University of Baghdad, University
uomosul.edu.iq, University of Mosul, University
uobasrah.edu.iq, University of Basrah, University"
        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-mono text-sm"
      ></textarea>
      <button @click="addBulkTargets" class="mt-3 px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
        Add All Targets
      </button>
    </div>

    <!-- Manage Tags Panel -->
    <div v-if="showManageTags" class="bg-white rounded-xl shadow-sm border border-purple-200 p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-900 mb-4">Manage Tags</h3>
      <div class="flex gap-3 mb-4">
        <input
          v-model="newTagName"
          type="text"
          placeholder="Tag name..."
          class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent text-sm"
          @keyup.enter="addNewTag"
        />
        <div class="flex items-center gap-2">
          <label class="text-xs text-gray-500">Color:</label>
          <div class="flex gap-1">
            <button
              v-for="color in tagColors"
              :key="color"
              @click="newTagColor = color"
              :class="newTagColor === color ? 'ring-2 ring-offset-1 ring-gray-400' : ''"
              :style="{ backgroundColor: color }"
              class="w-6 h-6 rounded-full cursor-pointer"
            ></button>
          </div>
        </div>
        <button @click="addNewTag" class="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 text-sm">
          Create Tag
        </button>
      </div>
      <div v-if="allTags.length" class="flex flex-wrap gap-2">
        <span
          v-for="tag in allTags"
          :key="tag.ID"
          class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm text-white"
          :style="{ backgroundColor: tag.color || '#6366f1' }"
        >
          {{ tag.name }}
          <button @click="removeTag(tag.ID)" class="hover:bg-white/20 rounded-full p-0.5" title="Delete tag">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </span>
      </div>
      <p v-else class="text-sm text-gray-400">No tags created yet. Create one above.</p>
    </div>

    <!-- Tag Filter -->
    <div v-if="allTags.length" class="flex items-center gap-3 mb-4">
      <span class="text-sm text-gray-500">Filter by tag:</span>
      <button
        @click="tagFilterId = 'all'"
        :class="tagFilterId === 'all' ? 'bg-indigo-600 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'"
        class="px-3 py-1 rounded-full text-xs transition-colors"
      >
        All
      </button>
      <button
        v-for="tag in allTags"
        :key="tag.ID"
        @click="tagFilterId = String(tag.ID)"
        :class="tagFilterId === String(tag.ID) ? 'text-white' : 'text-gray-700 bg-gray-100 hover:bg-gray-200'"
        :style="tagFilterId === String(tag.ID) ? { backgroundColor: tag.color || '#6366f1' } : {}"
        class="px-3 py-1 rounded-full text-xs transition-colors"
      >
        {{ tag.name }}
      </button>
    </div>

    <!-- Verification Messages -->
    <div v-if="!isAdmin && verificationMessage" class="bg-green-50 border border-green-200 text-green-700 rounded-lg p-4 mb-6">
      {{ verificationMessage }}
    </div>
    <div v-if="!isAdmin && verificationError" class="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4 mb-6">
      {{ verificationError }}
    </div>

    <!-- Loading -->
    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <!-- Targets Table -->
    <div v-else class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      <table v-if="filteredTargets.length" class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">#</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">URL</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Name</th>
            <th class="text-right py-3 px-4 text-gray-600 font-medium">Institution</th>
            <th class="text-left py-3 px-4 text-gray-600 font-medium">Tags</th>
            <th v-if="!isAdmin" class="text-center py-3 px-4 text-gray-600 font-medium">Verification</th>
            <th class="text-center py-3 px-4 text-gray-600 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(target, i) in filteredTargets" :key="target.ID" class="border-t border-gray-100 hover:bg-gray-50">
            <td class="py-3 px-4 text-gray-400">{{ i + 1 }}</td>
            <td class="py-3 px-4">
              <a :href="'https://' + target.url" target="_blank" class="text-indigo-600 hover:underline">
                {{ target.url }}
              </a>
            </td>
            <td class="py-3 px-4 text-gray-900">{{ target.name || '-' }}</td>
            <td class="py-3 px-4 text-gray-600">{{ target.institution || '-' }}</td>
            <td class="py-3 px-4">
              <div class="flex flex-wrap items-center gap-1">
                <span
                  v-for="tag in getTagsForTarget(target.ID)"
                  :key="tag.ID"
                  class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs text-white"
                  :style="{ backgroundColor: tag.color || '#6366f1' }"
                >
                  {{ tag.name }}
                  <button @click.stop="removeTagFromTarget(target.ID, tag.ID)" class="hover:bg-white/20 rounded-full" title="Remove tag">
                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                  </button>
                </span>
                <div class="relative">
                  <button
                    @click.stop="tagDropdownTarget = tagDropdownTarget === target.ID ? null : target.ID"
                    class="px-1.5 py-0.5 text-xs text-gray-400 border border-dashed border-gray-300 rounded hover:border-gray-400 hover:text-gray-600 transition-colors"
                    title="Add tag"
                  >
                    + Tag
                  </button>
                  <div
                    v-if="tagDropdownTarget === target.ID && getAvailableTagsForTarget(target.ID).length"
                    class="absolute z-10 mt-1 left-0 bg-white rounded-lg shadow-lg border border-gray-200 py-1 min-w-[140px]"
                  >
                    <button
                      v-for="tag in getAvailableTagsForTarget(target.ID)"
                      :key="tag.ID"
                      @click="assignTag(target.ID, tag.ID)"
                      class="w-full text-left px-3 py-1.5 text-sm hover:bg-gray-50 flex items-center gap-2"
                    >
                      <span class="w-3 h-3 rounded-full inline-block" :style="{ backgroundColor: tag.color || '#6366f1' }"></span>
                      {{ tag.name }}
                    </button>
                  </div>
                  <div
                    v-if="tagDropdownTarget === target.ID && !getAvailableTagsForTarget(target.ID).length"
                    class="absolute z-10 mt-1 left-0 bg-white rounded-lg shadow-lg border border-gray-200 py-2 px-3 min-w-[140px]"
                  >
                    <p class="text-xs text-gray-400">No more tags available</p>
                  </div>
                </div>
              </div>
            </td>
            <td v-if="!isAdmin" class="py-3 px-4 text-center">
              <!-- Verified -->
              <span v-if="isVerified(target.ID)" class="inline-flex items-center gap-1 text-green-600 font-medium text-xs">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
                Verified
              </span>
              <!-- Not initiated -->
              <button
                v-else-if="!isInitiated(target.ID)"
                @click="startVerification(target.ID)"
                class="text-xs px-3 py-1 bg-yellow-100 text-yellow-700 rounded-full hover:bg-yellow-200 transition-colors"
              >
                Verify Domain
              </button>
              <!-- Initiated but not verified -->
              <div v-else class="text-xs">
                <span class="inline-flex items-center gap-1 text-yellow-600 font-medium">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                  Pending
                </span>
                <button
                  @click="verifyingTarget = verifyingTarget === target.ID ? null : target.ID"
                  class="block mt-1 text-indigo-600 hover:text-indigo-800 underline"
                >
                  {{ verifyingTarget === target.ID ? 'Hide Instructions' : 'Show Instructions' }}
                </button>
              </div>
            </td>
            <td class="py-3 px-4 text-center">
              <button @click="removeTarget(target.ID)" class="text-red-500 hover:text-red-700 text-sm">
                Delete
              </button>
            </td>
          </tr>

          <!-- Verification instructions row (expandable) - hidden for admin -->
          <tr v-if="!isAdmin" v-for="target in filteredTargets" :key="'verify-' + target.ID" v-show="verifyingTarget === target.ID && isInitiated(target.ID) && !isVerified(target.ID)">
            <td colspan="7" class="px-4 py-4 bg-blue-50 border-t border-blue-100">
              <div class="max-w-2xl">
                <h4 class="font-semibold text-gray-900 mb-3">Domain Verification for {{ getDomain(target.ID) }}</h4>
                <div class="bg-white rounded-lg border border-blue-200 p-4 mb-4">
                  <p class="text-sm text-gray-600 mb-2">Add this TXT record to your DNS:</p>
                  <div class="flex items-center gap-2">
                    <code class="bg-gray-100 text-gray-800 px-3 py-2 rounded text-sm font-mono flex-1">
                      {{ getTxtRecord(target.ID) }}
                    </code>
                    <button
                      @click="navigator.clipboard.writeText(getTxtRecord(target.ID))"
                      class="px-3 py-2 text-xs bg-gray-200 hover:bg-gray-300 rounded transition-colors"
                      title="Copy to clipboard"
                    >
                      Copy
                    </button>
                  </div>
                </div>
                <div class="text-sm text-gray-600 space-y-1 mb-4">
                  <p class="font-medium text-gray-700">Steps:</p>
                  <ol class="list-decimal list-inside space-y-1 mr-4">
                    <li>Log in to your DNS provider for {{ getDomain(target.ID) }}</li>
                    <li>Add a new TXT record to the root domain</li>
                    <li>Set the value to: <code class="bg-gray-100 px-1 rounded text-xs">{{ getTxtRecord(target.ID) }}</code></li>
                    <li>Wait for DNS propagation (may take up to 24 hours)</li>
                    <li>Click "Check Verification" below</li>
                  </ol>
                </div>
                <button
                  @click="verifyDomain(target.ID)"
                  class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm"
                >
                  Check Verification
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else class="text-center py-16 text-gray-400">
        <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/>
        </svg>
        <p class="text-lg">No targets added yet</p>
        <p class="text-sm mt-1">Add websites to start scanning</p>
      </div>
    </div>

    <!-- Pagination -->
    <div v-if="totalPages > 1" class="flex items-center justify-between mt-4">
      <p class="text-sm text-gray-500">Page {{ currentPage }} of {{ totalPages }} ({{ totalTargets }} targets)</p>
      <div class="flex gap-2">
        <button @click="currentPage--; loadTargets()" :disabled="currentPage <= 1"
          class="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed">Previous</button>
        <button @click="currentPage++; loadTargets()" :disabled="currentPage >= totalPages"
          class="px-3 py-1.5 text-sm border rounded-lg hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed">Next</button>
      </div>
    </div>
  </div>
</template>
