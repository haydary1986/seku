import { createRouter, createWebHistory } from 'vue-router'
import Landing from '../views/Landing.vue'
import Login from '../views/Login.vue'
import Register from '../views/Register.vue'
import Dashboard from '../views/Dashboard.vue'
import Targets from '../views/Targets.vue'
import Scans from '../views/Scans.vue'
import ScanDetail from '../views/ScanDetail.vue'
import ResultDetail from '../views/ResultDetail.vue'
import Leaderboard from '../views/Leaderboard.vue'
import Upgrade from '../views/Upgrade.vue'
import Users from '../views/Users.vue'
import Settings from '../views/Settings.vue'
import Subscriptions from '../views/Subscriptions.vue'
import Schedules from '../views/Schedules.vue'
import Methodology from '../views/Methodology.vue'
import MethodologyAr from '../views/MethodologyAr.vue'
import Pricing from '../views/Pricing.vue'
import APIKeys from '../views/APIKeys.vue'
import Profile from '../views/Profile.vue'
import AIChat from '../views/AIChat.vue'
import Compare from '../views/Compare.vue'
import Webhooks from '../views/Webhooks.vue'
import Docs from '../views/Docs.vue'
import Discovery from '../views/Discovery.vue'
import Directives from '../views/Directives.vue'
import DataLeak from '../views/DataLeak.vue'

const routes = [
  // Public pages
  { path: '/', name: 'Landing', component: Landing, meta: { public: true, landing: true } },
  { path: '/login', name: 'Login', component: Login, meta: { public: true } },
  { path: '/register', name: 'Register', component: Register, meta: { public: true } },
  { path: '/methodology', name: 'Methodology', component: Methodology, meta: { public: true } },
  { path: '/methodology-ar', name: 'MethodologyAr', component: MethodologyAr, meta: { public: true } },
  { path: '/pricing', name: 'Pricing', component: Pricing, meta: { public: true } },

  // Protected pages (require login)
  { path: '/dashboard', name: 'Dashboard', component: Dashboard },
  { path: '/targets', name: 'Targets', component: Targets },
  { path: '/scans', name: 'Scans', component: Scans },
  { path: '/scans/:id', name: 'ScanDetail', component: ScanDetail },
  { path: '/results/:id', name: 'ResultDetail', component: ResultDetail },
  { path: '/leaderboard', name: 'Leaderboard', component: Leaderboard },
  { path: '/upgrade', name: 'Upgrade', component: Upgrade },
  { path: '/schedules', name: 'Schedules', component: Schedules },
  { path: '/api-keys', name: 'APIKeys', component: APIKeys },
  { path: '/profile', name: 'Profile', component: Profile },
  { path: '/ai-chat', name: 'AIChat', component: AIChat },
  { path: '/compare', name: 'Compare', component: Compare },
  { path: '/webhooks', name: 'Webhooks', component: Webhooks },
  { path: '/docs', name: 'Docs', component: Docs },
  { path: '/discovery', name: 'Discovery', component: Discovery },
  { path: '/directives', name: 'Directives', component: Directives },
  { path: '/data-leak', name: 'DataLeak', component: DataLeak },
  { path: '/users', name: 'Users', component: Users, meta: { admin: true } },
  { path: '/settings', name: 'Settings', component: Settings, meta: { admin: true } },
  { path: '/subscriptions', name: 'Subscriptions', component: Subscriptions, meta: { admin: true } },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior() {
    return { top: 0 }
  },
})

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')

  // If logged in and visiting landing, go to dashboard
  if (to.meta.landing && token) {
    next('/dashboard')
    return
  }

  // If not logged in and page requires auth, go to landing
  if (!to.meta.public && !token) {
    next('/')
    return
  }

  next()
})

export default router
