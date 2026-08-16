<script setup>
import { ref, computed, onMounted } from 'vue'
import { getDownloadStats, agentDownloadUrl } from '../api'

const stats = ref({ total: 0, by_platform: {} })
const macArch = ref('macos-arm64') // 'macos-arm64' | 'macos-intel'

const macCount = computed(
  () => (stats.value.by_platform?.['macos-arm64'] || 0) + (stats.value.by_platform?.['macos-intel'] || 0)
)

function fmt(n) {
  return (n || 0).toLocaleString()
}
async function load() {
  try {
    const { data } = await getDownloadStats()
    stats.value = data || { total: 0, by_platform: {} }
  } catch {
    /* ignore */
  }
}
function onDownload() {
  setTimeout(load, 1500)
}
onMounted(load)
</script>

<template>
  <div class="public-shell min-h-full">
    <!-- Branded hero -->
    <div class="relative overflow-hidden text-white">
      <div class="absolute inset-0 ring-grid opacity-50 pointer-events-none"></div>
      <div class="relative max-w-5xl mx-auto px-4 md:px-6 py-12 text-center">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white/15 backdrop-blur mb-4">
          <svg class="w-9 h-9" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M9 12l2 2 4-4m5.6 0c0 5-3.4 9.7-8.6 11C7.4 19.7 4 15 4 10V6l8-3 8 3v4z" />
          </svg>
        </div>
        <div class="mt-6 inline-flex items-center gap-2 bg-white/15 backdrop-blur rounded-full px-5 py-2">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          <span class="text-2xl font-bold font-mono tabular-nums text-gradient">{{ fmt(stats.total) }}</span>
          <span class="text-slate-300 text-sm">إجمالي التحميلات</span>
        </div>
      </div>
    </div>

    <div class="max-w-5xl mx-auto px-4 md:px-6 py-10">
      <!-- Platform cards -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <!-- Windows -->
        <div class="card card-hover p-6 flex flex-col items-center text-center">
          <svg viewBox="0 0 24 24" class="w-11 h-11 mb-3" fill="#0078D4">
            <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-13.051-1.351" />
          </svg>
          <p class="font-semibold text-gray-900 dark:text-white">Windows</p>
          <p class="text-xs text-gray-500 dark:text-slate-400 mb-1">64-bit · .exe</p>
          <p class="text-[11px] text-gray-400 dark:text-slate-400 mb-4">{{ fmt(stats.by_platform?.windows) }} تحميل</p>
          <a :href="agentDownloadUrl('windows')" @click="onDownload" class="mt-auto w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-accent-grad glow-accent text-white rounded-lg hover:opacity-90 transition text-sm font-medium">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            تحميل
          </a>
        </div>

        <!-- macOS (single card, arch selector) -->
        <div class="card card-hover p-6 flex flex-col items-center text-center">
          <svg viewBox="0 0 24 24" class="w-11 h-11 mb-3 text-gray-900 dark:text-slate-100" fill="currentColor">
            <path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.53 4.09M12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25" />
          </svg>
          <p class="font-semibold text-gray-900 dark:text-white">macOS</p>
          <p class="text-[11px] text-gray-400 dark:text-slate-400 mb-2">{{ fmt(macCount) }} تحميل</p>
          <!-- two options -->
          <div class="flex w-full rounded-lg border border-gray-200 dark:border-white/15 overflow-hidden text-xs mb-3">
            <button @click="macArch = 'macos-arm64'" :class="macArch === 'macos-arm64' ? 'bg-accent-grad text-white' : 'bg-slate-900/60 text-slate-300 hover:bg-white/5'" class="px-2 py-1.5 flex-1 transition">Apple Silicon</button>
            <button @click="macArch = 'macos-intel'" :class="macArch === 'macos-intel' ? 'bg-accent-grad text-white' : 'bg-slate-900/60 text-slate-300 hover:bg-white/5'" class="px-2 py-1.5 flex-1 border-r border-gray-200 dark:border-white/10 transition">Intel</button>
          </div>
          <a :href="agentDownloadUrl(macArch)" @click="onDownload" class="mt-auto w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-accent-grad glow-accent text-white rounded-lg hover:opacity-90 transition text-sm font-medium">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            تحميل {{ macArch === 'macos-arm64' ? '(Apple Silicon)' : '(Intel)' }}
          </a>
          <p class="text-[10px] text-gray-400 dark:text-slate-400 mt-2">ظهرت رسالة «Apple could not verify»؟ الحل بالأسفل ↓</p>
        </div>

        <!-- Linux -->
        <div class="card card-hover p-6 flex flex-col items-center text-center">
          <svg viewBox="0 0 64 64" class="w-11 h-11 mb-3">
            <path fill="#1f2937" d="M32 6c-8 0-13 6-13 15 0 5-3 7-5 12-1.5 3.5-2 7 1 9 1.5 1 3 .5 4 1.5 1 1 1 3 2.5 4 2 1.5 5 2 10.5 2s8.5-.5 10.5-2c1.5-1 1.5-3 2.5-4 1-1 2.5-.5 4-1.5 3-2 2.5-5.5 1-9-2-5-5-7-5-12 0-9-5-15-13-15z" />
            <ellipse cx="32" cy="40" rx="10" ry="14" fill="#f3f4f6" />
            <ellipse cx="27" cy="18" rx="3.4" ry="4.4" fill="#fff" />
            <ellipse cx="37" cy="18" rx="3.4" ry="4.4" fill="#fff" />
            <circle cx="27.6" cy="19" r="1.6" fill="#111" />
            <circle cx="36.4" cy="19" r="1.6" fill="#111" />
            <path fill="#f59e0b" d="M28.5 21h7L32 26z" />
            <path fill="#f59e0b" d="M24 57c-2.5 1-5 1-5.5-.5-.4-1.2 1.5-2.8 4-3.5zM40 57c2.5 1 5 1 5.5-.5.4-1.2-1.5-2.8-4-3.5z" />
          </svg>
          <p class="font-semibold text-gray-900 dark:text-white">Linux</p>
          <p class="text-xs text-gray-500 dark:text-slate-400 mb-1">64-bit</p>
          <p class="text-[11px] text-gray-400 dark:text-slate-400 mb-4">{{ fmt(stats.by_platform?.linux) }} تحميل</p>
          <a :href="agentDownloadUrl('linux')" @click="onDownload" class="mt-auto w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-accent-grad glow-accent text-white rounded-lg hover:opacity-90 transition text-sm font-medium">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            تحميل
          </a>
        </div>
      </div>

      <!-- macOS Gatekeeper notice -->
      <div class="mt-6 card p-5 ring-1 ring-amber-500/25">
        <p class="font-semibold text-gray-900 dark:text-white">🍎 ظهرت رسالة «Apple could not verify…» على ماك؟</p>
        <p class="text-sm text-gray-500 dark:text-slate-400 mt-1">
          هذا طبيعي — الملف غير موقّع من Apple (ليس فايروساً). لتشغيله: افتح <strong>Terminal</strong>، ثم نفّذ الأوامر بالترتيب (لنسخة Apple Silicon):
        </p>
        <pre class="mt-2 text-xs bg-slate-900 text-slate-100 rounded-lg p-3 overflow-x-auto" dir="ltr"><code>cd ~/Downloads
xattr -c seku-agent-macos-arm64      # يشيل حجب Gatekeeper
chmod +x seku-agent-macos-arm64      # يخليه قابل للتشغيل
./seku-agent-macos-arm64 -server https://sec.erticaz.com -token &lt;TOKEN&gt;</code></pre>
        <p class="text-[11px] text-gray-400 dark:text-slate-400 mt-2">
          نزّلت نسخة Intel؟ بدّل الاسم إلى <code>seku-agent-macos-intel</code>. — أو بدون تيرمنال: <strong>الإعدادات → الخصوصية والأمان → «فتح على أي حال / Open Anyway»</strong>.
        </p>
      </div>

      <!-- Quick start -->
      <div class="mt-6 card p-6">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">التشغيل بثلاث خطوات</h2>
        <ol class="space-y-4">
          <li class="flex gap-3">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-emerald-500/15 text-emerald-400 text-sm font-bold font-mono flex items-center justify-center">1</span>
            <div>
              <p class="text-gray-800 dark:text-slate-200 font-medium">أنشئ وكيلاً واحصل على التوكن</p>
              <p class="text-sm text-gray-500 dark:text-slate-400">من لوحة التحكم → صفحة <strong>Agents</strong> → «إنشاء وكيل» → انسخ التوكن.</p>
            </div>
          </li>
          <li class="flex gap-3">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-emerald-500/15 text-emerald-400 text-sm font-bold font-mono flex items-center justify-center">2</span>
            <div>
              <p class="text-gray-800 dark:text-slate-200 font-medium">شغّل الوكيل على جهاز داخل الشبكة</p>
              <pre class="mt-1 text-xs bg-slate-900 text-slate-100 rounded-lg p-3 overflow-x-auto"><code>seku-agent -server https://sec.erticaz.com -token &lt;TOKEN&gt;</code></pre>
              <p class="text-[11px] text-gray-400 dark:text-slate-400 mt-1">على ويندوز: <code>seku-agent.exe -server ... -token ...</code></p>
            </div>
          </li>
          <li class="flex gap-3">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-emerald-500/15 text-emerald-400 text-sm font-bold font-mono flex items-center justify-center">3</span>
            <div>
              <p class="text-gray-800 dark:text-slate-200 font-medium">عيّن فحصاً لهدف داخلي</p>
              <p class="text-sm text-gray-500 dark:text-slate-400">من صفحة Agents، اختر الوكيل وأدخل الهدف (مثل <code>http://192.168.1.1</code>) — الوكيل ينفّذه محلياً وترجع النتائج للوحة.</p>
            </div>
          </li>
        </ol>
        <div class="mt-4 text-xs text-gray-500 dark:text-slate-400 bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3">
          🔒 الوكيل <strong>مُقيّد أمنياً</strong>: يشغّل محرّك الفحص فقط ولا ينفّذ أوامر عامة. افحص فقط الأنظمة التي تملكها أو لديك إذن بها.
        </div>
      </div>

      <!-- Brand footer -->
      <div class="mt-8 text-center text-sm text-gray-400 dark:text-slate-400">
        <span class="font-semibold text-gray-500 dark:text-slate-300">Seku</span> — منصّة الفحص الأمني ·
        <a href="https://erticaz.com" class="text-indigo-600 dark:text-emerald-400 hover:underline">erticaz.com</a>
      </div>
    </div>
  </div>
</template>
