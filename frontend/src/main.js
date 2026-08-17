import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import './style.css'
import App from './App.vue'
import { initAnalytics } from './composables/useAnalytics'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')

// Initialize Google Analytics + verification tags from admin SEO settings
initAnalytics(router)

// Build stamp — also bumps the bundle hash so a fresh asset URL is emitted
// (bypasses any stale Cloudflare 404 cached for a prior asset during deploy swap).
window.__SEKU_BUILD__ = '2026-08-17-activity'
