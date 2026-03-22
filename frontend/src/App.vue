<script setup>
import { ref, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()
const sidebarOpen = ref(false)

const user = computed(() => {
  try { return JSON.parse(localStorage.getItem('user') || '{}') } catch { return {} }
})
const isAdmin = computed(() => user.value?.role === 'admin')
const isLoggedIn = computed(() => !!localStorage.getItem('token'))

const navItems = computed(() => {
  const items = [
    { name: 'Dashboard', path: '/dashboard', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
    { name: 'Targets', path: '/targets', icon: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9' },
    { name: 'Scans', path: '/scans', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
    { name: 'Leaderboard', path: '/leaderboard', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
    { name: 'Schedules', path: '/schedules', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
  ]
  if (!isAdmin.value) {
    items.push(
      { name: 'Upgrade', path: '/upgrade', icon: 'M5 10l7-7m0 0l7 7m-7-7v18' },
    )
  }
  if (isAdmin.value) {
    items.push(
      { name: 'Users', path: '/users', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z' },
      { name: 'Settings', path: '/settings', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z' },
      { name: 'Subscriptions', path: '/subscriptions', icon: 'M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z' },
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
  <div v-else class="min-h-screen bg-gray-50" dir="rtl">
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
      class="fixed inset-y-0 right-0 w-64 bg-gradient-to-b from-slate-900 to-slate-800 text-white z-40 transition-transform duration-300"
    >
      <!-- Logo -->
      <div class="p-6 border-b border-slate-700">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 bg-indigo-500 rounded-lg flex items-center justify-center">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
          </div>
          <div>
            <h1 class="text-lg font-bold">VScan</h1>
            <p class="text-xs text-slate-400">MOHESR Security</p>
          </div>
        </div>
      </div>

      <!-- Navigation -->
      <nav class="p-4 space-y-1">
        <router-link
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          @click="sidebarOpen = false"
          :class="[
            route.path === item.path
              ? 'bg-indigo-600 text-white'
              : 'text-slate-300 hover:bg-slate-700 hover:text-white'
          ]"
          class="flex items-center gap-3 px-4 py-3 rounded-lg transition-colors"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="item.icon"/>
          </svg>
          <span>{{ item.name }}</span>
        </router-link>
      </nav>

      <!-- User info & Logout -->
      <div class="absolute bottom-0 right-0 left-0 p-4 border-t border-slate-700">
        <div class="flex items-center justify-between mb-3">
          <div>
            <p class="text-sm text-white">{{ user.full_name || user.username }}</p>
            <p class="text-xs text-slate-400">{{ user.role }}</p>
          </div>
          <button @click="logout" class="text-slate-400 hover:text-red-400 transition-colors" title="Logout">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
            </svg>
          </button>
        </div>
        <p class="text-xs text-slate-600 text-center">VScan-MOHESR v1.0</p>
      </div>
    </aside>

    <!-- Main content -->
    <main class="lg:mr-64 min-h-screen">
      <div class="p-6 lg:p-8">
        <router-view />
      </div>
    </main>
  </div>
</template>
