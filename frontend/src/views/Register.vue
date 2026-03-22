<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { register } from '../api'

const router = useRouter()
const form = ref({
  username: '',
  password: '',
  full_name: '',
  email: '',
  phone: '',
  org_name: '',
  org_type: 'university',
  country: 'العراق'
})
const error = ref('')
const loading = ref(false)

const orgTypes = [
  { value: 'university', label: 'جامعة / مؤسسة تعليمية' },
  { value: 'government', label: 'جهة حكومية' },
  { value: 'company', label: 'شركة / مؤسسة خاصة' },
  { value: 'freelancer', label: 'فريلانسر / مستقل' },
  { value: 'hosting', label: 'مزود خدمات استضافة' },
  { value: 'agency', label: 'وكالة تصميم وتطوير' },
  { value: 'other', label: 'أخرى' },
]

async function handleRegister() {
  error.value = ''
  loading.value = true
  try {
    const { data } = await register(form.value)
    localStorage.setItem('token', data.token)
    localStorage.setItem('user', JSON.stringify(data.user))
    router.push('/dashboard')
  } catch (e) {
    error.value = e.response?.data?.error || 'Registration failed'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="min-h-screen bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 flex items-center justify-center p-4" dir="rtl">
    <div class="w-full max-w-lg">
      <!-- Logo -->
      <div class="text-center mb-8">
        <div class="inline-flex items-center justify-center w-16 h-16 bg-indigo-600 rounded-2xl mb-4">
          <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
        </div>
        <h1 class="text-3xl font-bold text-white">VScan-MOHESR</h1>
        <p class="text-indigo-300 mt-2">إنشاء حساب جديد</p>
      </div>

      <!-- Register Form -->
      <div class="bg-white/10 backdrop-blur-lg rounded-2xl p-8 border border-white/20 shadow-2xl">
        <h2 class="text-xl font-semibold text-white mb-6 text-center">تسجيل حساب جديد</h2>

        <!-- Free plan notice -->
        <div class="bg-indigo-500/20 border border-indigo-500/50 text-indigo-200 px-4 py-3 rounded-lg mb-5 text-sm text-center">
          ستبدأ بالخطة المجانية - 5 مواقع، 10 فحوصات شهريا
        </div>

        <div v-if="error" class="bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-lg mb-4 text-sm text-center">
          {{ error }}
        </div>

        <form @submit.prevent="handleRegister" class="space-y-4">
          <!-- Row: Username + Password -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm text-indigo-200 mb-1">اسم المستخدم *</label>
              <input
                v-model="form.username"
                type="text"
                placeholder="اسم المستخدم"
                class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                required
              />
            </div>
            <div>
              <label class="block text-sm text-indigo-200 mb-1">كلمة المرور *</label>
              <input
                v-model="form.password"
                type="password"
                placeholder="6 أحرف على الأقل"
                class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                required
                minlength="6"
              />
            </div>
          </div>

          <!-- Row: Full Name + Email -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm text-indigo-200 mb-1">الاسم الكامل</label>
              <input
                v-model="form.full_name"
                type="text"
                placeholder="الاسم الكامل"
                class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              />
            </div>
            <div>
              <label class="block text-sm text-indigo-200 mb-1">البريد الإلكتروني *</label>
              <input
                v-model="form.email"
                type="email"
                placeholder="email@example.com"
                class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                required
              />
            </div>
          </div>

          <!-- Phone -->
          <div>
            <label class="block text-sm text-indigo-200 mb-1">رقم الهاتف</label>
            <input
              v-model="form.phone"
              type="tel"
              placeholder="+964 xxx xxx xxxx"
              class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
          </div>

          <!-- Row: Org Name + Org Type -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm text-indigo-200 mb-1">اسم المؤسسة *</label>
              <input
                v-model="form.org_name"
                type="text"
                placeholder="اسم الجامعة أو المؤسسة"
                class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                required
              />
            </div>
            <div>
              <label class="block text-sm text-indigo-200 mb-1">نوع المؤسسة</label>
              <select
                v-model="form.org_type"
                class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              >
                <option v-for="t in orgTypes" :key="t.value" :value="t.value" class="bg-slate-800">{{ t.label }}</option>
              </select>
            </div>
          </div>

          <!-- Country -->
          <div>
            <label class="block text-sm text-indigo-200 mb-1">البلد</label>
            <input
              v-model="form.country"
              type="text"
              placeholder="البلد"
              class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
          </div>

          <button
            type="submit"
            :disabled="loading"
            class="w-full py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors font-medium disabled:opacity-50 mt-2"
          >
            {{ loading ? 'جارٍ التسجيل...' : 'إنشاء حساب' }}
          </button>
        </form>

        <!-- Link to login -->
        <div class="mt-6 text-center">
          <router-link to="/login" class="text-indigo-300 hover:text-indigo-100 text-sm transition-colors">
            لديك حساب؟ تسجيل الدخول
          </router-link>
        </div>
      </div>

      <p class="text-center text-indigo-400 text-xs mt-6">Ministry of Higher Education & Scientific Research</p>
    </div>
  </div>
</template>
