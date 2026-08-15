<script setup>
import { ref, onMounted } from 'vue'
import { getAllOrders, approveOrder, rejectOrder } from '../api'

const loading = ref(true)
const orders = ref([])
const statusFilter = ref('')
const message = ref('')
const rejectNotes = ref({}) // orderId -> reason text

async function load() {
  loading.value = true
  try {
    const { data } = await getAllOrders(statusFilter.value || undefined)
    orders.value = data || []
  } catch (e) {
    console.error('Failed to load orders:', e)
  } finally {
    loading.value = false
  }
}

async function approve(o) {
  try {
    await approveOrder(o.ID, '')
    message.value = `تم تأكيد الدفع للطلب #${o.ID} (${o.domain}). أصبح للمستخدم رصيد فحص عميق.`
    await load()
  } catch (e) {
    message.value = e.response?.data?.error || 'تعذّر التأكيد.'
  }
}

async function reject(o) {
  const notes = (rejectNotes.value[o.ID] || '').trim()
  if (!notes) { message.value = 'اكتب سبب الرفض أولاً.'; return }
  try {
    await rejectOrder(o.ID, notes)
    message.value = `تم رفض الطلب #${o.ID}.`
    rejectNotes.value[o.ID] = ''
    await load()
  } catch (e) {
    message.value = e.response?.data?.error || 'تعذّر الرفض.'
  }
}

const statusMeta = {
  pending:  { label: 'بانتظار المراجعة', cls: 'bg-amber-100 text-amber-700' },
  paid:     { label: 'مدفوع',           cls: 'bg-green-100 text-green-700' },
  used:     { label: 'مُستخدم',          cls: 'bg-gray-100 text-gray-600' },
  rejected: { label: 'مرفوض',            cls: 'bg-red-100 text-red-700' },
}
const fmtDate = (s) => s ? new Date(s).toLocaleString('ar-IQ') : ''
const fmtMoney = (n) => new Intl.NumberFormat('en-US').format(n || 0) + ' د.ع'

onMounted(load)
</script>

<template>
  <div class="max-w-5xl mx-auto">
    <div class="flex items-center justify-between mb-6">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">طلبات الفحص العميق</h1>
        <p class="text-gray-500 mt-1">تأكيد الحوالات الداخلية ومنح رصيد الفحص العميق.</p>
      </div>
      <select v-model="statusFilter" @change="load" class="border border-gray-300 rounded-lg px-3 py-2 text-sm">
        <option value="">كل الحالات</option>
        <option value="pending">بانتظار المراجعة</option>
        <option value="paid">مدفوع</option>
        <option value="used">مُستخدم</option>
        <option value="rejected">مرفوض</option>
      </select>
    </div>

    <div v-if="message" class="bg-blue-50 border border-blue-200 text-blue-800 rounded-lg p-4 mb-6">{{ message }}</div>

    <div v-if="loading" class="text-center py-10 text-gray-400">جارٍ التحميل…</div>
    <div v-else-if="!orders.length" class="text-center py-10 text-gray-400 bg-white rounded-xl border border-gray-200">لا توجد طلبات.</div>
    <div v-else class="space-y-3">
      <div v-for="o in orders" :key="o.ID" class="bg-white rounded-xl border border-gray-200 p-4">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <p class="font-semibold text-gray-900">#{{ o.ID }} · {{ o.domain }}</p>
            <p class="text-xs text-gray-400">{{ fmtDate(o.CreatedAt) }} · {{ fmtMoney(o.amount_iqd) }}</p>
            <p class="text-xs text-gray-500 mt-1">
              <span v-if="o.contact_name">جهة الاتصال: {{ o.contact_name }} </span>
              <span v-if="o.contact_phone">· {{ o.contact_phone }}</span>
            </p>
            <p v-if="o.payment_ref" class="text-sm text-gray-700 mt-1">رقم الحوالة: <code class="bg-gray-100 px-1 rounded">{{ o.payment_ref }}</code></p>
            <p v-else-if="o.status === 'pending'" class="text-xs text-amber-600 mt-1">المستخدم لم يُدخل رقم الحوالة بعد.</p>
            <p v-if="o.payment_proof_url" class="text-sm mt-1">
              <a :href="o.payment_proof_url" target="_blank" class="text-indigo-600 hover:underline">عرض إثبات الحوالة المرفق ↗</a>
            </p>
          </div>
          <span class="text-xs px-3 py-1 rounded-full font-medium" :class="(statusMeta[o.status] || statusMeta.pending).cls">
            {{ (statusMeta[o.status] || statusMeta.pending).label }}
          </span>
        </div>

        <div v-if="o.status === 'pending'" class="mt-3 pt-3 border-t border-gray-100 flex flex-wrap items-end gap-2">
          <button @click="approve(o)" class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm">تأكيد استلام الحوالة</button>
          <div class="flex-1 min-w-[220px]">
            <input v-model="rejectNotes[o.ID]" type="text" placeholder="سبب الرفض (اختياري للتأكيد، مطلوب للرفض)"
              class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" />
          </div>
          <button @click="reject(o)" class="px-4 py-2 bg-red-100 text-red-700 rounded-lg hover:bg-red-200 text-sm">رفض</button>
        </div>
        <p v-else-if="o.admin_notes" class="mt-2 text-sm text-gray-600">ملاحظة: {{ o.admin_notes }}</p>
      </div>
    </div>
  </div>
</template>
