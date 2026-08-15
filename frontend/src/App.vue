<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from './i18n'
import { useTheme } from './stores/theme'
import { refreshAuth } from './api'
import Toast from './components/Toast.vue'
import PublicHeader from './components/PublicHeader.vue'

const { t, lang, dir, toggleLang } = useI18n()
const { theme, toggleTheme } = useTheme()
const router = useRouter()
const route = useRoute()
const sidebarOpen = ref(false)

// Sliding session: refresh the token while the user is active so it doesn't
// expire mid-use (fixes intermittent logout, esp. on auto-refreshing pages).
let refreshTimer = null
async function keepSessionAlive() {
  if (!localStorage.getItem('token')) return
  try {
    const { data } = await refreshAuth()
    if (data?.token) localStorage.setItem('token', data.token)
  } catch {
    /* a genuine 401 is handled by the axios interceptor */
  }
}
function onVisible() {
  if (document.visibilityState === 'visible') keepSessionAlive()
}
onMounted(() => {
  keepSessionAlive()
  refreshTimer = setInterval(keepSessionAlive, 6 * 60 * 60 * 1000)
  document.addEventListener('visibilitychange', onVisible)
})
onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
  document.removeEventListener('visibilitychange', onVisible)
})

const user = computed(() => {
  try { return JSON.parse(localStorage.getItem('user') || '{}') } catch { return {} }
})
const isAdmin = computed(() => user.value?.role === 'admin')
const isLoggedIn = computed(() => !!localStorage.getItem('token'))

// Public marketing pages get the shared PublicHeader menu — except Landing
// (has its own hero nav) and the standalone auth/report pages.
const showPublicHeader = computed(() =>
  route.meta?.public && !['Login', 'Register', 'PublicReport'].includes(route.name),
)

// Icon paths (reused across nav items)
const ic = {
  dashboard: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6',
  targets: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9',
  scans: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
  orders: 'M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z',
  leaderboard: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
  compare: 'M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4',
  correlations: 'M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z',
  discovery: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7',
  dataLeak: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
  schedules: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
  webhooks: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9',
  aiChat: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z',
  apiKeys: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
  nuclei: 'M13 10V3L4 14h7v7l9-11h-7z',
  agents: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01',
  directives: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  users: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z',
  subscriptions: 'M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z',
  settings: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z',
  seo: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v6m-3-3h6',
  downloads: 'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4',
  docs: 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253',
  upgrade: 'M5 10l7-7m0 0l7 7m-7-7v18',
  profile: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z',
}

// Navigation grouped by logical section, ordered by workflow, admin isolated.
// Every feature/page is represented here (no orphan routes).
const navGroups = computed(() => {
  const groups = [
    {
      label: t('navGroup.main'),
      items: [
        { name: t('nav.dashboard'), path: '/dashboard', icon: ic.dashboard },
        { name: t('nav.targets'), path: '/targets', icon: ic.targets },
        { name: t('nav.scans'), path: '/scans', icon: ic.scans },
        { name: t('nav.orders'), path: '/orders', icon: ic.orders },
        { name: t('nav.leaderboard'), path: '/leaderboard', icon: ic.leaderboard },
      ],
    },
    {
      label: t('navGroup.analysis'),
      items: [
        { name: t('nav.compare'), path: '/compare', icon: ic.compare },
        { name: t('nav.correlations'), path: '/correlations', icon: ic.correlations },
        { name: t('nav.discovery'), path: '/discovery', icon: ic.discovery },
        { name: t('nav.dataLeak'), path: '/data-leak', icon: ic.dataLeak },
      ],
    },
    {
      label: t('navGroup.automation'),
      items: [
        { name: t('nav.schedules'), path: '/schedules', icon: ic.schedules },
        { name: t('nav.webhooks'), path: '/webhooks', icon: ic.webhooks },
        { name: t('nav.aiChat'), path: '/ai-chat', icon: ic.aiChat },
        { name: t('nav.apiKeys'), path: '/api-keys', icon: ic.apiKeys },
      ],
    },
  ]
  if (isAdmin.value) {
    groups.push({
      label: t('navGroup.admin'),
      items: [
        { name: t('nav.orderQueue'), path: '/admin/orders', icon: ic.orders },
        { name: t('nav.nuclei'), path: '/tools/nuclei', icon: ic.nuclei },
        { name: t('nav.agents'), path: '/agents', icon: ic.agents },
        { name: t('nav.directives'), path: '/directives', icon: ic.directives },
        { name: t('nav.users'), path: '/users', icon: ic.users },
        { name: t('nav.subscriptions'), path: '/subscriptions', icon: ic.subscriptions },
        { name: t('nav.settings'), path: '/settings', icon: ic.settings },
        { name: t('nav.seo'), path: '/seo', icon: ic.seo },
      ],
    })
  }
  const account = [
    { name: t('nav.profile'), path: '/profile', icon: ic.profile },
    { name: t('nav.downloads'), path: '/downloads', icon: ic.downloads },
    { name: t('nav.docs'), path: '/docs', icon: ic.docs },
  ]
  if (!isAdmin.value) account.splice(1, 0, { name: t('nav.upgrade'), path: '/upgrade', icon: ic.upgrade })
  groups.push({ label: t('navGroup.account'), items: account })
  return groups
})

// Unified page title/subtitle driven by the route (one consistent header).
const pageTitles = computed(() => ({
  Dashboard: [t('nav.dashboard'), t('dashboard.subtitle')],
  Targets: [t('nav.targets'), t('targets.subtitle')],
  Scans: [t('nav.scans'), t('scans.subtitle')],
  Orders: [t('nav.orders'), ''],
  AdminOrders: [t('nav.orderQueue'), ''],
  Leaderboard: [t('nav.leaderboard'), t('leaderboard.subtitle')],
  Compare: [t('nav.compare'), ''],
  Correlations: [t('nav.correlations'), ''],
  Discovery: [t('nav.discovery'), ''],
  DataLeak: [t('nav.dataLeak'), ''],
  Schedules: [t('nav.schedules'), ''],
  Webhooks: [t('nav.webhooks'), ''],
  AIChat: [t('nav.aiChat'), ''],
  APIKeys: [t('nav.apiKeys'), ''],
  NucleiTool: [t('nav.nuclei'), ''],
  Agents: [t('nav.agents'), ''],
  Directives: [t('nav.directives'), ''],
  Users: [t('nav.users'), ''],
  Subscriptions: [t('nav.subscriptions'), ''],
  Settings: [t('nav.settings'), ''],
  SEOSettings: [t('nav.seo'), ''],
  Downloads: [t('nav.downloads'), ''],
  Docs: [t('nav.docs'), ''],
  Profile: [t('nav.profile'), ''],
  Upgrade: [t('nav.upgrade'), ''],
  ScanDetail: [t('nav.scans'), ''],
  ResultDetail: [t('results.title'), ''],
}))
const pageTitle = computed(() => (pageTitles.value[route.name] || [route.name || '', ''])[0])
const pageSubtitle = computed(() => (pageTitles.value[route.name] || ['', ''])[1])

const userMenuOpen = ref(false)

function logout() {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  router.push('/')
}
</script>

<template>
  <!-- Global toast notifications (app-wide) -->
  <Toast />

  <!-- Public pages - no sidebar. Marketing pages get a shared PublicHeader menu. -->
  <div v-if="route.meta?.public" class="min-h-screen bg-white">
    <PublicHeader v-if="showPublicHeader" />
    <router-view />
  </div>

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

      <!-- Navigation (scrollable, grouped) -->
      <nav class="flex-1 overflow-y-auto p-3 space-y-4 scrollbar-thin">
        <div v-for="group in navGroups" :key="group.label">
          <p class="px-3 mb-1 text-[10px] font-semibold text-slate-500 uppercase tracking-wider">{{ group.label }}</p>
          <div class="space-y-0.5">
            <router-link v-for="item in group.items" :key="item.path" :to="item.path" @click="sidebarOpen = false"
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

      <!-- Compact brand footer -->
      <div class="flex-shrink-0 p-3 border-t border-slate-700 text-[11px] text-slate-500">
        Seku · sec.erticaz.com
      </div>
    </aside>

    <!-- Main content -->
    <main class="lg:mr-64 min-h-screen dark:text-gray-200 flex flex-col">
      <!-- Unified top header (consistent across every page) -->
      <header class="sticky top-0 z-30 bg-white/90 dark:bg-slate-900/90 backdrop-blur border-b border-gray-200 dark:border-slate-700">
        <div class="flex items-center gap-3 px-4 lg:px-8 h-16">
          <div class="min-w-0">
            <h1 class="text-lg font-bold text-gray-900 dark:text-white truncate">{{ pageTitle }}</h1>
            <p v-if="pageSubtitle" class="text-xs text-gray-500 dark:text-slate-400 truncate">{{ pageSubtitle }}</p>
          </div>

          <!-- Per-page action buttons teleport here -->
          <div id="page-actions" class="flex items-center gap-2 ms-auto"></div>

          <!-- Global controls -->
          <div class="flex items-center gap-1 ps-2 border-s border-gray-200 dark:border-slate-700">
            <button @click="toggleTheme" :title="theme === 'dark' ? 'Light' : 'Dark'"
              class="w-9 h-9 flex items-center justify-center rounded-lg text-gray-500 hover:bg-gray-100 dark:text-slate-300 dark:hover:bg-slate-800 transition-colors">
              <svg v-if="theme === 'light'" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
              <svg v-else class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
            </button>
            <button @click="toggleLang" class="h-9 px-2.5 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-100 dark:text-slate-300 dark:hover:bg-slate-800 transition-colors">
              {{ lang === 'ar' ? 'EN' : 'عربي' }}
            </button>
            <!-- User menu -->
            <div class="relative">
              <button @click="userMenuOpen = !userMenuOpen" class="flex items-center gap-2 h-9 ps-1 pe-2 rounded-lg hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors">
                <span class="w-7 h-7 rounded-full bg-indigo-600 text-white text-xs font-bold flex items-center justify-center">{{ (user.full_name || user.username || '?').charAt(0).toUpperCase() }}</span>
                <span class="hidden sm:block text-sm text-gray-700 dark:text-slate-200 max-w-[120px] truncate">{{ user.full_name || user.username }}</span>
              </button>
              <div v-if="userMenuOpen" @click.self="userMenuOpen = false"
                class="absolute mt-1 w-48 bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700 rounded-lg shadow-lg py-1 z-40"
                :class="dir === 'rtl' ? 'start-0' : 'end-0'">
                <div class="px-3 py-2 border-b border-gray-100 dark:border-slate-700">
                  <p class="text-sm font-medium text-gray-900 dark:text-white truncate">{{ user.full_name || user.username }}</p>
                  <p class="text-xs text-gray-400">{{ user.role }}</p>
                </div>
                <router-link to="/profile" @click="userMenuOpen = false" class="block px-3 py-2 text-sm text-gray-700 dark:text-slate-200 hover:bg-gray-50 dark:hover:bg-slate-700">{{ t('nav.profile') }}</router-link>
                <button @click="logout" class="w-full text-start px-3 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-slate-700">{{ t('nav.logout') }}</button>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div class="p-6 lg:p-8 flex-1">
        <router-view />
      </div>
    </main>
  </div>
</template>
