<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { login } from '../api'
import { useI18n } from '../i18n'

const router = useRouter()
const { t } = useI18n()
const form = ref({ username: '', password: '' })
const error = ref('')
const loading = ref(false)
const showPassword = ref(false)

async function handleLogin() {
  error.value = ''
  loading.value = true
  try {
    const { data } = await login(form.value)
    localStorage.setItem('token', data.token)
    localStorage.setItem('user', JSON.stringify(data.user))
    router.push('/dashboard')
  } catch (e) {
    error.value = e.response?.data?.error || 'Login failed'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="public-shell min-h-screen flex items-center justify-center p-4" dir="rtl">
    <div class="w-full max-w-md">
      <!-- Logo -->
      <div class="text-center mb-8">
        <div class="inline-flex items-center justify-center w-16 h-16 bg-accent-grad glow-accent rounded-2xl mb-4">
          <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
        </div>
        <h1 class="text-3xl font-bold text-gradient">Seku</h1>
        <p class="text-slate-300 mt-2">{{ t('vLogin.tagline') }}</p>
      </div>

      <!-- Login Form -->
      <div class="glass rounded-2xl p-8 shadow-2xl">
        <h2 class="text-xl font-semibold text-white mb-6 text-center">{{ t('vLogin.signIn') }}</h2>

        <div v-if="error" class="bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-lg mb-4 text-sm text-center">
          {{ error }}
        </div>

        <form @submit.prevent="handleLogin" class="space-y-5">
          <div>
            <label class="block text-sm text-slate-300 mb-1">{{ t('vLogin.username') }}</label>
            <input
              v-model="form.username"
              type="text"
              placeholder="admin"
              class="w-full px-4 py-3 rounded-lg bg-slate-900/60 border border-white/15 text-slate-100 placeholder-slate-500 focus:border-emerald-400/50 focus:outline-none"
              required
            />
          </div>
          <div>
            <label class="block text-sm text-slate-300 mb-1">{{ t('vLogin.password') }}</label>
            <div class="relative">
              <input
                v-model="form.password"
                :type="showPassword ? 'text' : 'password'"
                placeholder="********"
                class="w-full px-4 py-3 pl-12 rounded-lg bg-slate-900/60 border border-white/15 text-slate-100 placeholder-slate-500 focus:border-emerald-400/50 focus:outline-none"
                required
              />
              <button type="button" @click="showPassword = !showPassword"
                class="absolute left-3 top-1/2 -translate-y-1/2 text-indigo-300 hover:text-white transition-colors p-1">
                <svg v-if="!showPassword" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                </svg>
                <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
                </svg>
              </button>
            </div>
          </div>
          <button
            type="submit"
            :disabled="loading"
            class="w-full py-3 bg-accent-grad glow-accent text-white rounded-lg hover:opacity-90 transition-opacity font-medium disabled:opacity-50"
          >
            {{ loading ? t('vLogin.signingIn') : t('vLogin.signIn') }}
          </button>
        </form>
        <!-- Link to register -->
        <div class="mt-6 text-center">
          <router-link to="/register" class="text-indigo-300 hover:text-indigo-100 text-sm transition-colors">
            {{ t('vLogin.noAccount') }}
          </router-link>
        </div>
      </div>

      <p class="text-center text-slate-400 text-xs mt-6">{{ t('vLogin.footer') }}</p>
      <p class="text-center text-slate-500 text-[10px] mt-1">{{ t('vLogin.poweredBy') }}</p>
    </div>
  </div>
</template>
