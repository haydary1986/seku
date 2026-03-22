import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'
import Targets from '../views/Targets.vue'
import Scans from '../views/Scans.vue'
import ScanDetail from '../views/ScanDetail.vue'
import ResultDetail from '../views/ResultDetail.vue'
import Leaderboard from '../views/Leaderboard.vue'
import Users from '../views/Users.vue'
import Settings from '../views/Settings.vue'
import Methodology from '../views/Methodology.vue'

const routes = [
  { path: '/login', name: 'Login', component: Login, meta: { public: true } },
  { path: '/methodology', name: 'Methodology', component: Methodology, meta: { public: true } },
  { path: '/', name: 'Dashboard', component: Dashboard },
  { path: '/targets', name: 'Targets', component: Targets },
  { path: '/scans', name: 'Scans', component: Scans },
  { path: '/scans/:id', name: 'ScanDetail', component: ScanDetail },
  { path: '/results/:id', name: 'ResultDetail', component: ResultDetail },
  { path: '/leaderboard', name: 'Leaderboard', component: Leaderboard },
  { path: '/users', name: 'Users', component: Users, meta: { admin: true } },
  { path: '/settings', name: 'Settings', component: Settings, meta: { admin: true } },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')
  if (!to.meta.public && !token) {
    next('/login')
  } else {
    next()
  }
})

export default router
