<script setup>
import { ref, onMounted, computed } from 'vue'
import { getPaymentInfo, getMyOrders, createDeepScanOrder, submitOrderPayment, uploadOrderProof, getTargets } from '../api'
import { useI18n } from '../i18n'

const { t } = useI18n()

const loading = ref(true)
const payment = ref({})
const orders = ref([])
const targets = ref([])

const newOrder = ref({ target_id: '', contact_name: '', contact_phone: '' })
const creating = ref(false)
const createError = ref('')
const refInputs = ref({})   // orderId -> payment_ref text
const message = ref('')

const priceLabel = computed(() =>
  payment.value.deep_scan_price_iqd
    ? new Intl.NumberFormat('en-US').format(payment.value.deep_scan_price_iqd) + ' د.ع'
    : '—'
)

async function loadAll() {
  loading.value = true
  try {
    const [pRes, oRes, tRes] = await Promise.all([getPaymentInfo(), getMyOrders(), getTargets({ limit: 1000 })])
    payment.value = pRes.data || {}
    orders.value = oRes.data || []
    const t = tRes.data
    targets.value = Array.isArray(t) ? t : (t.data || [])
  } catch (e) {
    console.error('Failed to load orders:', e)
  } finally {
    loading.value = false
  }
}

async function create() {
  if (!newOrder.value.target_id) { createError.value = t('vOrders.selectDomainFirst'); return }
  creating.value = true
  createError.value = ''
  message.value = ''
  try {
    await createDeepScanOrder({
      target_id: Number(newOrder.value.target_id),
      contact_name: newOrder.value.contact_name,
      contact_phone: newOrder.value.contact_phone,
    })
    newOrder.value = { target_id: '', contact_name: '', contact_phone: '' }
    message.value = t('vOrders.orderCreated')
    await loadAll()
  } catch (e) {
    const d = e.response?.data
    if (d?.error === 'verify_domain_first') createError.value = d.message || t('vOrders.verifyDomainFirst')
    else if (d?.error === 'order_exists') createError.value = d.message || t('vOrders.orderExists')
    else createError.value = d?.message || d?.error || t('vOrders.createFailed')
  } finally {
    creating.value = false
  }
}

async function sendRef(order) {
  const ref = (refInputs.value[order.ID] || '').trim()
  if (!ref) return
  try {
    await submitOrderPayment(order.ID, ref)
    message.value = t('vOrders.refSent')
    refInputs.value[order.ID] = ''
    await loadAll()
  } catch (e) {
    createError.value = e.response?.data?.error || t('vOrders.refFailed')
  }
}

async function uploadProof(order, event) {
  const file = event.target.files?.[0]
  if (!file) return
  try {
    await uploadOrderProof(order.ID, file)
    message.value = t('vOrders.proofUploaded')
    await loadAll()
  } catch (e) {
    createError.value = e.response?.data?.error || t('vOrders.proofFailed')
  }
}

const statusMeta = {
  pending:  { label: t('vOrders.statusPending'),  cls: 'bg-amber-100 text-amber-700' },
  paid:     { label: t('vOrders.statusPaid'),     cls: 'bg-green-100 text-green-700' },
  used:     { label: t('vOrders.statusUsed'),     cls: 'bg-gray-100 text-gray-600' },
  rejected: { label: t('vOrders.statusRejected'), cls: 'bg-red-100 text-red-700' },
}
const fmtDate = (s) => s ? new Date(s).toLocaleString('ar-IQ') : ''

onMounted(loadAll)
</script>

<template>
  <div class="max-w-5xl mx-auto">
    <div class="mb-6">
      <h1 class="text-3xl font-bold text-gray-900">{{ t('vOrders.title') }}</h1>
      <p class="text-gray-500 mt-1">{{ t('vOrders.subtitle') }}</p>
    </div>

    <div v-if="message" class="bg-green-50 border border-green-200 text-green-700 rounded-lg p-4 mb-6">{{ message }}</div>

    <!-- Price + payment method banner -->
    <div class="grid md:grid-cols-3 gap-4 mb-6">
      <div class="bg-white rounded-xl border border-gray-200 p-5">
        <p class="text-sm text-gray-500">{{ t('vOrders.priceLabel') }}</p>
        <p class="text-2xl font-bold text-indigo-600 mt-1">{{ priceLabel }}</p>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 p-5">
        <p class="text-sm text-gray-500">{{ t('vOrders.paymentMethod') }}</p>
        <p class="text-lg font-semibold text-gray-900 mt-1">{{ payment.payment_method || t('vOrders.internalTransfer') }}</p>
      </div>
      <div class="bg-white rounded-xl border border-gray-200 p-5">
        <p class="text-sm text-gray-500">{{ t('vOrders.receivingAccount') }}</p>
        <p class="text-lg font-semibold text-gray-900 mt-1 break-all">{{ payment.payment_account || '—' }}</p>
      </div>
    </div>

    <div v-if="payment.payment_instructions_ar" class="bg-blue-50 border border-blue-200 text-blue-900 rounded-lg p-4 mb-6 whitespace-pre-line text-sm">
      {{ payment.payment_instructions_ar }}
    </div>

    <!-- Create order -->
    <div class="bg-white rounded-xl border border-gray-200 p-5 mb-8">
      <h2 class="font-semibold text-gray-900 mb-4">{{ t('vOrders.requestDeepScan') }}</h2>
      <div v-if="createError" class="bg-red-50 border border-red-200 text-red-700 rounded-lg p-3 mb-4 text-sm">{{ createError }}</div>
      <div class="grid md:grid-cols-3 gap-3">
        <div>
          <label class="block text-xs text-gray-500 mb-1">{{ t('vOrders.domainLabel') }}</label>
          <select v-model="newOrder.target_id" class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm">
            <option value="">{{ t('vOrders.selectDomainOption') }}</option>
            <option v-for="t in targets" :key="t.ID" :value="t.ID">{{ t.url }}</option>
          </select>
        </div>
        <div>
          <label class="block text-xs text-gray-500 mb-1">{{ t('vOrders.contactName') }}</label>
          <input v-model="newOrder.contact_name" type="text" class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" />
        </div>
        <div>
          <label class="block text-xs text-gray-500 mb-1">{{ t('vOrders.contactPhone') }}</label>
          <input v-model="newOrder.contact_phone" type="text" class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" />
        </div>
      </div>
      <button @click="create" :disabled="creating"
        class="mt-4 px-5 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 text-sm font-medium">
        {{ creating ? '...' : `${t('vOrders.createOrder')} (${priceLabel})` }}
      </button>
      <p class="text-xs text-gray-400 mt-2">{{ t('vOrders.notVerifiedYet') }}
        <router-link to="/targets" class="text-indigo-600 hover:underline">{{ t('vOrders.sitesPage') }}</router-link>{{ t('vOrders.toVerify') }}</p>
    </div>

    <!-- My orders -->
    <h2 class="font-semibold text-gray-900 mb-3">{{ t('vOrders.myOrders') }}</h2>
    <div v-if="loading" class="text-center py-10 text-gray-400">{{ t('vOrders.loading') }}</div>
    <div v-else-if="!orders.length" class="text-center py-10 text-gray-400 bg-white rounded-xl border border-gray-200">{{ t('vOrders.noOrdersYet') }}</div>
    <div v-else class="space-y-3">
      <div v-for="o in orders" :key="o.ID" class="bg-white rounded-xl border border-gray-200 p-4">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p class="font-semibold text-gray-900">{{ o.domain }}</p>
            <p class="text-xs text-gray-400">{{ fmtDate(o.CreatedAt) }} · {{ new Intl.NumberFormat('en-US').format(o.amount_iqd) }} د.ع</p>
          </div>
          <span class="text-xs px-3 py-1 rounded-full font-medium" :class="(statusMeta[o.status] || statusMeta.pending).cls">
            {{ (statusMeta[o.status] || statusMeta.pending).label }}
          </span>
        </div>

        <!-- pending: enter transfer reference -->
        <div v-if="o.status === 'pending'" class="mt-3 pt-3 border-t border-gray-100 space-y-3">
          <p v-if="o.payment_ref" class="text-sm text-gray-600">{{ t('vOrders.sentRefLabel') }} <code class="bg-gray-100 px-1 rounded">{{ o.payment_ref }}</code> {{ t('vOrders.awaitingAdminReview') }}</p>
          <div v-else class="flex flex-wrap items-end gap-2">
            <div class="flex-1 min-w-[220px]">
              <label class="block text-xs text-gray-500 mb-1">{{ t('vOrders.enterRefLabel') }}</label>
              <input v-model="refInputs[o.ID]" type="text" :placeholder="t('vOrders.refPlaceholder')"
                class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" />
            </div>
            <button @click="sendRef(o)" class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 text-sm">{{ t('vOrders.sentTransfer') }}</button>
          </div>
          <!-- optional proof screenshot -->
          <div class="text-xs text-gray-500">
            <span v-if="o.payment_proof_url" class="text-green-600">✓ {{ t('vOrders.proofAttached') }}</span>
            <label v-else class="inline-flex items-center gap-2 cursor-pointer text-indigo-600 hover:underline">
              <input type="file" accept="image/*,.pdf" class="hidden" @change="uploadProof(o, $event)" />
              {{ t('vOrders.attachProof') }}
            </label>
          </div>
        </div>

        <!-- paid: ready to scan -->
        <div v-else-if="o.status === 'paid'" class="mt-3 pt-3 border-t border-gray-100 flex items-center justify-between">
          <p class="text-sm text-green-700">{{ t('vOrders.paymentConfirmed') }}</p>
          <router-link to="/scans" class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 text-sm">{{ t('vOrders.startDeepScan') }}</router-link>
        </div>

        <!-- rejected -->
        <div v-else-if="o.status === 'rejected' && o.admin_notes" class="mt-3 pt-3 border-t border-gray-100">
          <p class="text-sm text-red-600">{{ t('vOrders.rejectReason') }} {{ o.admin_notes }}</p>
        </div>
      </div>
    </div>
  </div>
</template>
