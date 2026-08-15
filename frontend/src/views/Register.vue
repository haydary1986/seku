<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { register } from '../api'
import PasswordInput from '../components/PasswordInput.vue'
import { useI18n } from '../i18n'

const router = useRouter()
const { t } = useI18n()
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
        <h1 class="text-3xl font-bold text-white">Seku</h1>
        <p class="text-indigo-300 mt-2">{{ t('vRegister.subtitle') }}</p>
      </div>

      <!-- Register Form -->
      <div class="bg-white/10 backdrop-blur-lg rounded-2xl p-8 border border-white/20 shadow-2xl">
        <h2 class="text-xl font-semibold text-white mb-6 text-center">{{ t('vRegister.title') }}</h2>

        <!-- Free plan notice -->
        <div class="bg-indigo-500/20 border border-indigo-500/50 text-indigo-200 px-4 py-3 rounded-lg mb-5 text-sm text-center">
          {{ t('vRegister.freePlanNotice') }}
        </div>

        <div v-if="error" class="bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-lg mb-4 text-sm text-center">
          {{ error }}
        </div>

        <form @submit.prevent="handleRegister" class="space-y-4">
          <!-- Row: Username + Password -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm text-indigo-200 mb-1">{{ t('vRegister.usernameLabel') }}</label>
              <input
                v-model="form.username"
                type="text"
                :placeholder="t('vRegister.usernamePlaceholder')"
                class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                required
              />
            </div>
            <div>
              <label class="block text-sm text-indigo-200 mb-1">{{ t('vRegister.passwordLabel') }}</label>
              <PasswordInput
                v-model="form.password"
                :placeholder="t('vRegister.passwordPlaceholder')"
                :required="true"
                input-class="w-full px-4 py-3 pl-12 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                icon-class="absolute left-3 top-1/2 -translate-y-1/2 text-indigo-300 hover:text-white transition-colors p-1"
              />
            </div>
          </div>

          <!-- Row: Full Name + Email -->
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm text-indigo-200 mb-1">{{ t('vRegister.fullNameLabel') }}</label>
              <input
                v-model="form.full_name"
                type="text"
                :placeholder="t('vRegister.fullNameLabel')"
                class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              />
            </div>
            <div>
              <label class="block text-sm text-indigo-200 mb-1">{{ t('vRegister.emailLabel') }}</label>
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
            <label class="block text-sm text-indigo-200 mb-1">{{ t('vRegister.phoneLabel') }}</label>
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
              <label class="block text-sm text-indigo-200 mb-1">{{ t('vRegister.orgNameLabel') }}</label>
              <input
                v-model="form.org_name"
                type="text"
                :placeholder="t('vRegister.orgNamePlaceholder')"
                class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                required
              />
            </div>
            <div>
              <label class="block text-sm text-indigo-200 mb-1">{{ t('vRegister.orgTypeLabel') }}</label>
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
            <label class="block text-sm text-indigo-200 mb-1">{{ t('vRegister.countryLabel') }}</label>
            <input
              v-model="form.country"
              type="text"
              :placeholder="t('vRegister.countryLabel')"
              class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            />
          </div>

          <button
            type="submit"
            :disabled="loading"
            class="w-full py-3 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors font-medium disabled:opacity-50 mt-2"
          >
            {{ loading ? t('vRegister.submitting') : t('vRegister.submit') }}
          </button>
        </form>

        <!-- Link to login -->
        <div class="mt-6 text-center">
          <router-link to="/login" class="text-indigo-300 hover:text-indigo-100 text-sm transition-colors">
            {{ t('vRegister.haveAccount') }}
          </router-link>
        </div>
      </div>

      <p class="text-center text-indigo-400 text-xs mt-6">{{ t('vRegister.footer') }}</p>
    </div>
  </div>
</template>
