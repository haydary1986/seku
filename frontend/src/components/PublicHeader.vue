<script setup>
// Shared marketing/public navigation header — rendered on all public pages
// (Pricing, Methodology, Docs, Downloads…) so they have a consistent menu,
// language toggle, and Login / My Dashboard entry point.
import { ref, computed } from 'vue'
import { useI18n } from '../i18n'

const { t, lang, toggleLang } = useI18n()
const isLoggedIn = computed(() => !!localStorage.getItem('token'))
const mobileOpen = ref(false)
const methodologyPath = computed(() => (lang.value === 'ar' ? '/methodology-ar' : '/methodology'))

const links = computed(() => [
  { label: t('nav.home'), to: '/' },
  { label: t('nav.pricing'), to: '/pricing' },
  { label: t('nav.methodology'), to: methodologyPath.value },
  { label: t('nav.docs'), to: '/docs' },
])
</script>

<template>
  <header class="sticky top-0 z-50 border-b border-white/10 bg-slate-950/70 backdrop-blur-xl" dir="ltr">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div class="flex items-center justify-between h-16" :dir="lang === 'ar' ? 'rtl' : 'ltr'">
        <!-- Brand -->
        <router-link to="/" class="flex items-center gap-2.5 shrink-0">
          <span class="w-9 h-9 bg-accent-grad glow-accent rounded-xl flex items-center justify-center text-white">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
          </span>
          <span class="text-xl font-extrabold tracking-tight text-gradient">Seku</span>
        </router-link>

        <!-- Desktop links -->
        <nav class="hidden md:flex items-center gap-1">
          <router-link v-for="l in links" :key="l.to" :to="l.to"
            class="px-3 py-2 text-sm font-medium text-slate-300 hover:text-white rounded-lg hover:bg-white/5 transition-colors">
            {{ l.label }}
          </router-link>
        </nav>

        <!-- Actions -->
        <div class="hidden md:flex items-center gap-2">
          <button @click="toggleLang" class="px-3 py-2 text-sm font-medium text-slate-300 hover:text-white border border-white/15 rounded-lg hover:border-emerald-400/40 transition-colors">
            {{ lang === 'ar' ? 'EN' : 'عربي' }}
          </button>
          <template v-if="!isLoggedIn">
            <router-link to="/login" class="px-4 py-2 text-sm font-medium text-emerald-300 border border-emerald-400/30 rounded-lg hover:bg-emerald-400/10 transition-colors">{{ t('nav.login') }}</router-link>
            <router-link to="/register" class="px-4 py-2 text-sm font-semibold text-white bg-accent-grad glow-accent rounded-lg hover:brightness-110 transition-all">{{ t('nav.register') }}</router-link>
          </template>
          <router-link v-else to="/dashboard" class="px-4 py-2 text-sm font-semibold text-white bg-accent-grad glow-accent rounded-lg hover:brightness-110 transition-all inline-flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h5v16H6a2 2 0 01-2-2V6zM13 4h5a2 2 0 012 2v4h-7V4zM13 12h7v6a2 2 0 01-2 2h-5v-8z"/></svg>
            {{ t('nav.myDashboard') }}
          </router-link>
        </div>

        <!-- Mobile toggle -->
        <button @click="mobileOpen = !mobileOpen" class="md:hidden w-10 h-10 flex items-center justify-center rounded-lg text-slate-200 hover:bg-white/5 transition-colors">
          <svg v-if="!mobileOpen" class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
          <svg v-else class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
        </button>
      </div>

      <!-- Mobile menu -->
      <div v-if="mobileOpen" class="md:hidden pb-4 space-y-1" :dir="lang === 'ar' ? 'rtl' : 'ltr'">
        <router-link v-for="l in links" :key="l.to" :to="l.to" @click="mobileOpen = false"
          class="block px-4 py-2.5 text-sm font-medium text-slate-300 hover:bg-white/5 hover:text-white rounded-lg transition-colors">{{ l.label }}</router-link>
        <button @click="toggleLang" class="block w-full text-start px-4 py-2.5 text-sm font-medium text-slate-300 hover:bg-white/5 rounded-lg transition-colors">{{ lang === 'ar' ? 'English' : 'عربي' }}</button>
        <div class="pt-2 border-t border-white/10 space-y-2">
          <template v-if="!isLoggedIn">
            <router-link to="/login" @click="mobileOpen = false" class="block w-full text-center px-4 py-2.5 text-sm font-medium text-emerald-300 border border-emerald-400/30 rounded-lg">{{ t('nav.login') }}</router-link>
            <router-link to="/register" @click="mobileOpen = false" class="block w-full text-center px-4 py-2.5 text-sm font-semibold text-white bg-accent-grad rounded-lg">{{ t('nav.register') }}</router-link>
          </template>
          <router-link v-else to="/dashboard" @click="mobileOpen = false" class="block w-full text-center px-4 py-2.5 text-sm font-semibold text-white bg-accent-grad rounded-lg">{{ t('nav.myDashboard') }}</router-link>
        </div>
      </div>
    </div>
  </header>
</template>
