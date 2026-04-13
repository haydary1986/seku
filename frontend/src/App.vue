<script setup>
import { ref, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from './i18n'
import { useTheme } from './stores/theme'

const { t, lang, dir, toggleLang } = useI18n()
const { theme, toggleTheme } = useTheme()
const router = useRouter()
const route = useRoute()
const sidebarOpen = ref(false)

const user = computed(() => {
  try { return JSON.parse(localStorage.getItem('user') || '{}') } catch { return {} }
})
const isAdmin = computed(() => user.value?.role === 'admin')
const isLoggedIn = computed(() => !!localStorage.getItem('token'))

const mainNav = computed(() => [
  { name: t('nav.dashboard'), path: '/dashboard', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { name: 'Discovery', path: '/discovery', icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7' },
  { name: t('nav.targets'), path: '/targets', icon: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9' },
  { name: t('nav.scans'), path: '/scans', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
  { name: t('nav.leaderboard'), path: '/leaderboard', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
])

const toolsNav = computed(() => [
  { name: t('nav.schedules'), path: '/schedules', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
  { name: t('nav.aiChat'), path: '/ai-chat', icon: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z' },
  { name: t('nav.compare'), path: '/compare', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
  { name: 'Data Leak', path: '/data-leak', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
  { name: 'Directives', path: '/directives', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
  { name: t('nav.webhooks'), path: '/webhooks', icon: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9' },
  { name: t('nav.docs'), path: '/docs', icon: 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253' },
])

const accountNav = computed(() => {
  const items = []
  if (!isAdmin.value) {
    items.push(
      { name: t('nav.apiKeys'), path: '/api-keys', icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z' },
      { name: t('nav.upgrade'), path: '/upgrade', icon: 'M5 10l7-7m0 0l7 7m-7-7v18' },
    )
  }
  if (isAdmin.value) {
    items.push(
      { name: t('nav.users'), path: '/users', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z' },
      { name: t('nav.settings'), path: '/settings', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z' },
      { name: t('nav.subscriptions'), path: '/subscriptions', icon: 'M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z' },
    )
  }
  return items
})

function logout() {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  router.push('/')
}
</script>

<template>
  <!-- Public pages - no sidebar (landing, login, methodology) -->
  <router-view v-if="route.meta?.public" />

  <!-- Main layout with sidebar (authenticated pages) -->
  <div v-else class="min-h-screen bg-gray-50 dark:bg-slate-800" :dir="dir">
    <!-- Mobile sidebar toggle -->
    <button
      @click="sidebarOpen = !sidebarOpen"
      class="lg:hidden fixed top-4 right-4 z-50 bg-indigo-600 text-white p-2 rounded-lg shadow-lg"
    >
      <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
      </svg>
    </button>

    <!-- Sidebar -->
    <aside
      :class="[sidebarOpen ? 'translate-x-0' : 'translate-x-full lg:translate-x-0']"
      class="fixed inset-y-0 right-0 w-64 bg-gradient-to-b from-slate-900 to-slate-800 dark:from-slate-950 dark:to-slate-900 text-white z-40 transition-transform duration-300 dark:border-l dark:border-slate-700 flex flex-col"
    >
      <!-- Logo -->
      <div class="p-5 border-b border-slate-700 flex-shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 bg-indigo-500 rounded-lg flex items-center justify-center">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
          </div>
          <div>
            <h1 class="text-lg font-bold">Seku</h1>
            <p class="text-xs text-slate-400">Web Security</p>
          </div>
        </div>
      </div>

      <!-- Navigation (scrollable) -->
      <nav class="flex-1 overflow-y-auto p-3 space-y-4 scrollbar-thin">
        <!-- Main -->
        <div>
          <p class="px-3 mb-1 text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Main</p>
          <div class="space-y-0.5">
            <router-link v-for="item in mainNav" :key="item.path" :to="item.path" @click="sidebarOpen = false"
              :class="[route.path === item.path ? 'bg-indigo-600 text-white' : 'text-slate-300 hover:bg-slate-700/60 hover:text-white']"
              class="flex items-center gap-3 px-3 py-2 rounded-lg transition-colors text-sm">
              <svg class="w-[18px] h-[18px] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="item.icon"/>
              </svg>
              <span>{{ item.name }}</span>
            </router-link>
          </div>
        </div>

        <!-- Tools -->
        <div>
          <p class="px-3 mb-1 text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Tools</p>
          <div class="space-y-0.5">
            <router-link v-for="item in toolsNav" :key="item.path" :to="item.path" @click="sidebarOpen = false"
              :class="[route.path === item.path ? 'bg-indigo-600 text-white' : 'text-slate-300 hover:bg-slate-700/60 hover:text-white']"
              class="flex items-center gap-3 px-3 py-2 rounded-lg transition-colors text-sm">
              <svg class="w-[18px] h-[18px] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="item.icon"/>
              </svg>
              <span>{{ item.name }}</span>
            </router-link>
          </div>
        </div>

        <!-- Account / Admin -->
        <div v-if="accountNav.length">
          <p class="px-3 mb-1 text-[10px] font-semibold text-slate-500 uppercase tracking-wider">{{ isAdmin ? 'Admin' : 'Account' }}</p>
          <div class="space-y-0.5">
            <router-link v-for="item in accountNav" :key="item.path" :to="item.path" @click="sidebarOpen = false"
              :class="[route.path === item.path ? 'bg-indigo-600 text-white' : 'text-slate-300 hover:bg-slate-700/60 hover:text-white']"
              class="flex items-center gap-3 px-3 py-2 rounded-lg transition-colors text-sm">
              <svg class="w-[18px] h-[18px] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="item.icon"/>
              </svg>
              <span>{{ item.name }}</span>
            </router-link>
          </div>
        </div>
      </nav>

      <!-- User info & controls (fixed bottom) -->
      <div class="flex-shrink-0 p-3 border-t border-slate-700 space-y-2">
        <div class="flex items-center justify-between">
          <router-link to="/profile" class="hover:opacity-80 transition-opacity min-w-0">
            <p class="text-sm text-white truncate">{{ user.full_name || user.username }}</p>
            <p class="text-[11px] text-slate-400">{{ user.role }}</p>
          </router-link>
          <button @click="logout" class="text-slate-400 hover:text-red-400 transition-colors flex-shrink-0" title="Logout">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
            </svg>
          </button>
        </div>
        <div class="flex gap-2">
          <button @click="toggleTheme"
            class="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-lg bg-slate-700/60 hover:bg-slate-600 text-slate-300 text-[11px] transition-colors">
            <svg v-if="theme === 'light'" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
            </svg>
            <svg v-else class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>
            </svg>
            {{ theme === 'dark' ? 'Light' : 'Dark' }}
          </button>
          <button @click="toggleLang"
            class="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-lg bg-slate-700/60 hover:bg-slate-600 text-slate-300 text-[11px] transition-colors">
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"/>
            </svg>
            {{ lang === 'ar' ? 'EN' : 'عربي' }}
          </button>
        </div>
      </div>
    </aside>

    <!-- Main content -->
    <main class="lg:mr-64 min-h-screen dark:text-gray-200">
      <div class="p-6 lg:p-8">
        <router-view />
      </div>
    </main>
  </div>
</template>
