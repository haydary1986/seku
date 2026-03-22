import { createRouter, createWebHistory } from 'vue-router'
import Landing from '../views/Landing.vue'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'
import Targets from '../views/Targets.vue'
import Scans from '../views/Scans.vue'
import ScanDetail from '../views/ScanDetail.vue'
import ResultDetail from '../views/ResultDetail.vue'
import Leaderboard from '../views/Leaderboard.vue'
import Users from '../views/Users.vue'
import Settings from '../views/Settings.vue'
import Schedules from '../views/Schedules.vue'
import Methodology from '../views/Methodology.vue'
import MethodologyAr from '../views/MethodologyAr.vue'
import Pricing from '../views/Pricing.vue'

const routes = [
  // Public pages
  { path: '/', name: 'Landing', component: Landing, meta: { public: true, landing: true } },
  { path: '/login', name: 'Login', component: Login, meta: { public: true } },
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
  { path: '/schedules', name: 'Schedules', component: Schedules },
  { path: '/users', name: 'Users', component: Users, meta: { admin: true } },
  { path: '/settings', name: 'Settings', component: Settings, meta: { admin: true } },
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
