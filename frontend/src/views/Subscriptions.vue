<script setup>
import { ref, onMounted, computed } from 'vue'
import { getAllUpgradeRequests, approveUpgrade, rejectUpgrade } from '../api'

const requests = ref([])
const loading = ref(true)
const filter = ref('all')
const rejectModal = ref(null) // holds the request being rejected
const rejectNotes = ref('')
const processing = ref(null) // holds the ID being processed

const filteredRequests = computed(() => {
  if (filter.value === 'all') return requests.value
  return requests.value.filter(r => r.status === filter.value)
})

const counts = computed(() => {
  const all = requests.value.length
  const pending = requests.value.filter(r => r.status === 'pending').length
  const approved = requests.value.filter(r => r.status === 'approved').length
  const rejected = requests.value.filter(r => r.status === 'rejected').length
  return { all, pending, approved, rejected }
})

function planLabel(plan) {
  return { free: 'المجانية', basic: 'الأساسية', pro: 'الاحترافية', enterprise: 'المؤسسية' }[plan] || plan
}

function planBadge(plan) {
  return {
    free: 'bg-gray-100 text-gray-700',
    basic: 'bg-blue-100 text-blue-700',
    pro: 'bg-indigo-100 text-indigo-700',
    enterprise: 'bg-amber-100 text-amber-700',
  }[plan] || 'bg-gray-100 text-gray-700'
}

function statusLabel(status) {
  return { pending: 'قيد المراجعة', approved: 'تمت الموافقة', rejected: 'مرفوض' }[status] || status
}

function statusColor(status) {
  return {
    pending: 'bg-yellow-100 text-yellow-800',
    approved: 'bg-green-100 text-green-800',
    rejected: 'bg-red-100 text-red-800',
  }[status] || 'bg-gray-100 text-gray-800'
}

async function handleApprove(req) {
  if (!confirm(`هل تريد الموافقة على ترقية "${req.organization?.name || 'المؤسسة'}" إلى خطة ${planLabel(req.requested_plan)}؟`)) return
  processing.value = req.ID
  try {
    await approveUpgrade(req.ID, '')
    await loadRequests()
  } catch (e) {
    alert(e.response?.data?.error || 'فشل في الموافقة')
  } finally {
    processing.value = null
  }
}

function openRejectModal(req) {
  rejectModal.value = req
  rejectNotes.value = ''
}

async function handleReject() {
  if (!rejectNotes.value.trim()) return
  processing.value = rejectModal.value.ID
  try {
    await rejectUpgrade(rejectModal.value.ID, rejectNotes.value)
    rejectModal.value = null
    rejectNotes.value = ''
    await loadRequests()
  } catch (e) {
    alert(e.response?.data?.error || 'فشل في الرفض')
  } finally {
    processing.value = null
  }
}

async function loadRequests() {
  try {
    const { data } = await getAllUpgradeRequests()
    requests.value = data || []
  } catch (e) {
    // ignore
  }
}

onMounted(async () => {
  await loadRequests()
  loading.value = false
})
</script>

<template>
  <div>
    <h1 class="text-2xl font-bold text-gray-900 mb-6">إدارة الاشتراكات</h1>

    <div v-if="loading" class="text-center py-12 text-gray-500">جارٍ التحميل...</div>

    <div v-else>
      <!-- Stats -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <button @click="filter = 'all'"
          :class="filter === 'all' ? 'ring-2 ring-indigo-500' : ''"
          class="bg-white rounded-xl border border-gray-200 p-4 text-center hover:shadow-md transition-all">
          <div class="text-2xl font-bold text-gray-900">{{ counts.all }}</div>
          <div class="text-sm text-gray-500">الكل</div>
        </button>
        <button @click="filter = 'pending'"
          :class="filter === 'pending' ? 'ring-2 ring-yellow-500' : ''"
          class="bg-white rounded-xl border border-gray-200 p-4 text-center hover:shadow-md transition-all">
          <div class="text-2xl font-bold text-yellow-600">{{ counts.pending }}</div>
          <div class="text-sm text-gray-500">قيد المراجعة</div>
        </button>
        <button @click="filter = 'approved'"
          :class="filter === 'approved' ? 'ring-2 ring-green-500' : ''"
          class="bg-white rounded-xl border border-gray-200 p-4 text-center hover:shadow-md transition-all">
          <div class="text-2xl font-bold text-green-600">{{ counts.approved }}</div>
          <div class="text-sm text-gray-500">تمت الموافقة</div>
        </button>
        <button @click="filter = 'rejected'"
          :class="filter === 'rejected' ? 'ring-2 ring-red-500' : ''"
          class="bg-white rounded-xl border border-gray-200 p-4 text-center hover:shadow-md transition-all">
          <div class="text-2xl font-bold text-red-600">{{ counts.rejected }}</div>
          <div class="text-sm text-gray-500">مرفوض</div>
        </button>
      </div>

      <!-- Table -->
      <div class="bg-white rounded-2xl border border-gray-200 overflow-hidden">
        <div v-if="filteredRequests.length === 0" class="text-center py-12 text-gray-400">
          لا توجد طلبات {{ filter !== 'all' ? statusLabel(filter) : '' }}
        </div>
        <div v-else class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="bg-gray-50 border-b border-gray-200 text-gray-500">
                <th class="text-right py-3 px-4">المؤسسة</th>
                <th class="text-right py-3 px-4">الخطة الحالية</th>
                <th class="text-right py-3 px-4">الخطة المطلوبة</th>
                <th class="text-right py-3 px-4">جهة التواصل</th>
                <th class="text-right py-3 px-4">التاريخ</th>
                <th class="text-right py-3 px-4">الحالة</th>
                <th class="text-right py-3 px-4">إجراء</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="req in filteredRequests" :key="req.ID" class="border-b border-gray-100 hover:bg-gray-50">
                <td class="py-3 px-4">
                  <div class="font-medium text-gray-900">{{ req.organization?.name || '-' }}</div>
                </td>
                <td class="py-3 px-4">
                  <span :class="planBadge(req.organization?.plan)" class="px-2 py-1 rounded-full text-xs font-medium">
                    {{ planLabel(req.organization?.plan) }}
                  </span>
                </td>
                <td class="py-3 px-4">
                  <span :class="planBadge(req.requested_plan)" class="px-2 py-1 rounded-full text-xs font-medium">
                    {{ planLabel(req.requested_plan) }}
                  </span>
                </td>
                <td class="py-3 px-4">
                  <div class="text-gray-900">{{ req.contact_name }}</div>
                  <div class="text-gray-400 text-xs">{{ req.contact_email }}</div>
                  <div v-if="req.contact_phone" class="text-gray-400 text-xs">{{ req.contact_phone }}</div>
                </td>
                <td class="py-3 px-4 text-gray-500 text-xs">
                  {{ new Date(req.CreatedAt).toLocaleDateString('ar-IQ') }}
                </td>
                <td class="py-3 px-4">
                  <span :class="statusColor(req.status)" class="px-2 py-1 rounded-full text-xs font-medium">
                    {{ statusLabel(req.status) }}
                  </span>
                  <div v-if="req.admin_notes" class="text-xs text-gray-400 mt-1">{{ req.admin_notes }}</div>
                </td>
                <td class="py-3 px-4">
                  <div v-if="req.status === 'pending'" class="flex gap-2">
                    <button
                      @click="handleApprove(req)"
                      :disabled="processing === req.ID"
                      class="px-3 py-1.5 bg-green-600 text-white text-xs rounded-lg hover:bg-green-700 transition-colors disabled:opacity-50">
                      {{ processing === req.ID ? '...' : 'موافقة' }}
                    </button>
                    <button
                      @click="openRejectModal(req)"
                      :disabled="processing === req.ID"
                      class="px-3 py-1.5 bg-red-600 text-white text-xs rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50">
                      رفض
                    </button>
                  </div>
                  <span v-else class="text-xs text-gray-400">تم المعالجة</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Message column for requests with messages -->
      <div v-for="req in filteredRequests.filter(r => r.message)" :key="'msg-' + req.ID" class="mt-4">
        <div class="bg-gray-50 rounded-lg p-3 border border-gray-200 text-sm">
          <span class="font-medium text-gray-700">رسالة من {{ req.contact_name }}:</span>
          <p class="text-gray-600 mt-1">{{ req.message }}</p>
        </div>
      </div>
    </div>

    <!-- Reject Modal -->
    <div v-if="rejectModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" @click.self="rejectModal = null">
      <div class="bg-white rounded-2xl p-6 w-full max-w-md shadow-2xl" dir="rtl">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">رفض طلب الترقية</h3>
        <p class="text-sm text-gray-500 mb-4">
          رفض طلب ترقية "{{ rejectModal.organization?.name }}" إلى خطة {{ planLabel(rejectModal.requested_plan) }}
        </p>
        <div>
          <label class="block text-sm text-gray-700 mb-1">سبب الرفض *</label>
          <textarea v-model="rejectNotes" rows="3"
            class="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent"
            placeholder="يرجى ذكر سبب الرفض..."></textarea>
        </div>
        <div class="flex gap-3 mt-4">
          <button @click="handleReject" :disabled="!rejectNotes.trim() || processing"
            class="px-5 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors font-medium disabled:opacity-50">
            {{ processing ? 'جارٍ الرفض...' : 'تأكيد الرفض' }}
          </button>
          <button @click="rejectModal = null"
            class="px-5 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors font-medium">
            إلغاء
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
