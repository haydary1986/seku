<script setup>
import { ref, onMounted, computed } from 'vue'
import { getMyOrganization, requestUpgrade, getMyUpgradeRequests } from '../api'

const org = ref(null)
const requests = ref([])
const loading = ref(true)
const submitting = ref(false)
const error = ref('')
const success = ref('')
const selectedPlan = ref(null)
const showForm = ref(false)

const form = ref({
  contact_name: '',
  contact_email: '',
  contact_phone: '',
  message: '',
})

const plans = [
  {
    key: 'basic',
    name: 'Basic',
    nameAr: 'الأساسية',
    price: '$49/شهرياً',
    targets: 25,
    scans: 50,
    categories: 12,
    color: 'from-blue-500 to-blue-600',
    border: 'border-blue-500/50',
    bg: 'bg-blue-500/10',
    features: [
      '25 موقع',
      '50 فحص شهرياً',
      '12 فئة فحص',
      'تقارير PDF',
      'تحليل SSL و Headers و Cookies',
      'فحص DNS و CORS و HTTP Methods',
    ],
  },
  {
    key: 'pro',
    name: 'Pro',
    nameAr: 'الاحترافية',
    price: '$149/شهرياً',
    targets: 100,
    scans: 200,
    categories: 17,
    color: 'from-indigo-500 to-purple-600',
    border: 'border-indigo-500/50',
    bg: 'bg-indigo-500/10',
    popular: true,
    features: [
      '100 موقع',
      '200 فحص شهرياً',
      '17 فئة فحص',
      'تحليل بالذكاء الاصطناعي',
      'كشف تسريب المعلومات',
      'فحص المحتوى والاستضافة',
      'مكتبات JavaScript والسكربتات الخارجية',
    ],
  },
  {
    key: 'enterprise',
    name: 'Enterprise',
    nameAr: 'المؤسسية',
    price: 'تواصل معنا',
    targets: 'غير محدود',
    scans: 'غير محدود',
    categories: 20,
    color: 'from-amber-500 to-orange-600',
    border: 'border-amber-500/50',
    bg: 'bg-amber-500/10',
    features: [
      'مواقع غير محدودة',
      'فحوصات غير محدودة',
      '20 فئة فحص (كامل)',
      'فحص الأمان المتقدم',
      'كشف الفايروسات والبرمجيات الخبيثة',
      'استخبارات التهديدات',
      'جدولة فحوصات تلقائية',
      'دعم فني مخصص',
    ],
  },
]

const currentPlanInfo = computed(() => {
  if (!org.value) return null
  const p = org.value.plan
  return {
    free: { name: 'المجانية', color: 'text-gray-400' },
    basic: { name: 'الأساسية', color: 'text-blue-400' },
    pro: { name: 'الاحترافية', color: 'text-indigo-400' },
    enterprise: { name: 'المؤسسية', color: 'text-amber-400' },
  }[p] || { name: p, color: 'text-gray-400' }
})

const hasPending = computed(() => requests.value.some(r => r.status === 'pending'))

function selectPlan(plan) {
  selectedPlan.value = plan.key
  showForm.value = true
  error.value = ''
  success.value = ''
}

async function submitRequest() {
  error.value = ''
  success.value = ''
  submitting.value = true
  try {
    await requestUpgrade({
      requested_plan: selectedPlan.value,
      ...form.value,
    })
    success.value = 'تم إرسال طلب الترقية بنجاح! سيتم مراجعته من قبل الإدارة.'
    showForm.value = false
    form.value = { contact_name: '', contact_email: '', contact_phone: '', message: '' }
    selectedPlan.value = null
    // Reload requests
    const { data } = await getMyUpgradeRequests()
    requests.value = data
  } catch (e) {
    error.value = e.response?.data?.error || 'فشل إرسال الطلب'
  } finally {
    submitting.value = false
  }
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

function planLabel(plan) {
  return { basic: 'الأساسية', pro: 'الاحترافية', enterprise: 'المؤسسية' }[plan] || plan
}

onMounted(async () => {
  try {
    const [orgRes, reqRes] = await Promise.all([getMyOrganization(), getMyUpgradeRequests()])
    org.value = orgRes.data
    requests.value = reqRes.data
  } catch (e) {
    // ignore
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div>
    <h1 class="text-2xl font-bold text-gray-900 mb-6">ترقية الخطة</h1>

    <div v-if="loading" class="text-center py-12 text-gray-500">جارٍ التحميل...</div>

    <div v-else>
      <!-- Current Plan -->
      <div v-if="org" class="bg-white rounded-2xl border border-gray-200 p-6 mb-8">
        <div class="flex items-center justify-between">
          <div>
            <h2 class="text-lg font-semibold text-gray-900">خطتك الحالية</h2>
            <p class="text-gray-500 text-sm mt-1">{{ org.name }}</p>
          </div>
          <div class="text-left">
            <span :class="currentPlanInfo.color" class="text-2xl font-bold">{{ currentPlanInfo.name }}</span>
            <div class="text-sm text-gray-500 mt-1">
              {{ org.max_targets }} مواقع | {{ org.max_scans }} فحص/شهرياً
            </div>
          </div>
        </div>
      </div>

      <!-- Success / Error messages -->
      <div v-if="success" class="bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded-lg mb-6 text-sm">
        {{ success }}
      </div>
      <div v-if="error" class="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg mb-6 text-sm">
        {{ error }}
      </div>

      <!-- Plan Cards -->
      <div v-if="org && org.plan !== 'enterprise'" class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div
          v-for="plan in plans"
          :key="plan.key"
          :class="[
            'rounded-2xl border-2 p-6 transition-all relative',
            plan.key === org?.plan ? 'opacity-50 cursor-not-allowed border-gray-200' : 'hover:shadow-xl cursor-pointer',
            selectedPlan === plan.key ? plan.border + ' shadow-xl' : 'border-gray-200 hover:' + plan.border,
          ]"
          @click="plan.key !== org?.plan && !hasPending && selectPlan(plan)"
        >
          <!-- Popular badge -->
          <div v-if="plan.popular" class="absolute -top-3 right-4 bg-gradient-to-r from-indigo-500 to-purple-600 text-white text-xs font-bold px-3 py-1 rounded-full">
            الأكثر طلباً
          </div>

          <!-- Current plan badge -->
          <div v-if="plan.key === org?.plan" class="absolute -top-3 right-4 bg-gray-500 text-white text-xs font-bold px-3 py-1 rounded-full">
            خطتك الحالية
          </div>

          <div :class="'bg-gradient-to-r ' + plan.color + ' bg-clip-text text-transparent'">
            <h3 class="text-xl font-bold">{{ plan.nameAr }}</h3>
            <p class="text-3xl font-black mt-2">{{ plan.price }}</p>
          </div>

          <div class="mt-4 space-y-1 text-sm text-gray-600">
            <div class="flex items-center gap-2 font-semibold text-gray-900">
              <span class="text-lg">{{ plan.categories }}</span> فئة فحص
            </div>
            <div class="text-gray-400 text-xs">{{ plan.targets }} موقع | {{ plan.scans }} فحص/شهرياً</div>
          </div>

          <ul class="mt-5 space-y-2">
            <li v-for="f in plan.features" :key="f" class="flex items-start gap-2 text-sm text-gray-600">
              <svg class="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
              </svg>
              <span>{{ f }}</span>
            </li>
          </ul>

          <button
            v-if="plan.key !== org?.plan"
            :disabled="hasPending"
            :class="[
              'mt-6 w-full py-2.5 rounded-lg font-medium text-sm transition-colors',
              hasPending ? 'bg-gray-200 text-gray-400 cursor-not-allowed' : 'bg-gradient-to-r ' + plan.color + ' text-white hover:opacity-90',
            ]"
          >
            {{ hasPending ? 'لديك طلب قيد المراجعة' : 'اختر هذه الخطة' }}
          </button>
        </div>
      </div>

      <!-- Enterprise notice -->
      <div v-if="org && org.plan === 'enterprise'" class="bg-amber-50 border border-amber-200 text-amber-800 px-6 py-4 rounded-xl mb-8 text-center">
        <p class="font-semibold">أنت على الخطة المؤسسية - جميع الميزات مفعّلة!</p>
      </div>

      <!-- Upgrade Request Form -->
      <div v-if="showForm" class="bg-white rounded-2xl border border-gray-200 p-6 mb-8">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">
          طلب الترقية إلى خطة {{ planLabel(selectedPlan) }}
        </h3>
        <form @submit.prevent="submitRequest" class="space-y-4">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm text-gray-700 mb-1">اسم المسؤول *</label>
              <input v-model="form.contact_name" type="text" required
                class="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
            </div>
            <div>
              <label class="block text-sm text-gray-700 mb-1">البريد الإلكتروني *</label>
              <input v-model="form.contact_email" type="email" required
                class="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
            </div>
          </div>
          <div>
            <label class="block text-sm text-gray-700 mb-1">رقم الهاتف</label>
            <input v-model="form.contact_phone" type="tel"
              class="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <div>
            <label class="block text-sm text-gray-700 mb-1">رسالة إضافية</label>
            <textarea v-model="form.message" rows="3"
              class="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              placeholder="أي ملاحظات أو متطلبات خاصة..."></textarea>
          </div>
          <div class="flex gap-3">
            <button type="submit" :disabled="submitting"
              class="px-6 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors font-medium disabled:opacity-50">
              {{ submitting ? 'جارٍ الإرسال...' : 'إرسال الطلب' }}
            </button>
            <button type="button" @click="showForm = false; selectedPlan = null"
              class="px-6 py-2.5 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors font-medium">
              إلغاء
            </button>
          </div>
        </form>
      </div>

      <!-- Previous Requests -->
      <div v-if="requests.length > 0" class="bg-white rounded-2xl border border-gray-200 p-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">طلبات الترقية السابقة</h3>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200 text-gray-500">
                <th class="text-right py-3 px-2">الخطة المطلوبة</th>
                <th class="text-right py-3 px-2">التاريخ</th>
                <th class="text-right py-3 px-2">الحالة</th>
                <th class="text-right py-3 px-2">ملاحظات الإدارة</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="req in requests" :key="req.ID" class="border-b border-gray-100">
                <td class="py-3 px-2 font-medium">{{ planLabel(req.requested_plan) }}</td>
                <td class="py-3 px-2 text-gray-500">{{ new Date(req.CreatedAt).toLocaleDateString('ar-IQ') }}</td>
                <td class="py-3 px-2">
                  <span :class="statusColor(req.status)" class="px-2 py-1 rounded-full text-xs font-medium">
                    {{ statusLabel(req.status) }}
                  </span>
                </td>
                <td class="py-3 px-2 text-gray-500">{{ req.admin_notes || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>
