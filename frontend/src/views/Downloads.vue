<script setup>
import { ref, onMounted } from 'vue'
import { getDownloadStats, agentDownloadUrl } from '../api'

const stats = ref({ total: 0, by_platform: {} })

const platforms = [
  { key: 'windows', name: 'Windows', sub: '64-bit · .exe', emoji: '🪟' },
  { key: 'macos-arm64', name: 'macOS', sub: 'Apple Silicon (M1/M2/M3)', emoji: '🍎' },
  { key: 'macos-intel', name: 'macOS', sub: 'Intel', emoji: '🍎' },
  { key: 'linux', name: 'Linux', sub: '64-bit', emoji: '🐧' },
]

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
  <div class="min-h-full bg-gray-50">
    <!-- Branded hero -->
    <div class="bg-gradient-to-br from-indigo-700 via-indigo-600 to-purple-700 text-white">
      <div class="max-w-5xl mx-auto px-4 md:px-6 py-12 text-center">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white/15 backdrop-blur mb-4">
          <svg class="w-9 h-9" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M9 12l2 2 4-4m5.6 0c0 5-3.4 9.7-8.6 11C7.4 19.7 4 15 4 10V6l8-3 8 3v4z" />
          </svg>
        </div>
        <h1 class="text-3xl md:text-4xl font-bold">Seku Agent</h1>
        <p class="mt-2 text-indigo-100 max-w-2xl mx-auto">
          شغّل الفحص الأمني <strong>داخل شبكتك المحلية</strong> — نزّل الوكيل على جهاز داخل الشبكة، وافحص الراوتر والسيرفرات والأجهزة الداخلية من لوحة التحكم.
        </p>
        <div class="mt-6 inline-flex items-center gap-2 bg-white/15 backdrop-blur rounded-full px-5 py-2">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          <span class="text-2xl font-bold tabular-nums">{{ fmt(stats.total) }}</span>
          <span class="text-indigo-100 text-sm">إجمالي التحميلات</span>
        </div>
      </div>
    </div>

    <div class="max-w-5xl mx-auto px-4 md:px-6 py-10">
      <!-- Platform cards -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div
          v-for="p in platforms"
          :key="p.key"
          class="bg-white rounded-2xl border border-gray-200 shadow-sm p-5 flex flex-col items-center text-center hover:shadow-md hover:border-indigo-200 transition"
        >
          <div class="text-4xl mb-3">{{ p.emoji }}</div>
          <p class="font-semibold text-gray-900">{{ p.name }}</p>
          <p class="text-xs text-gray-500 mb-1">{{ p.sub }}</p>
          <p class="text-[11px] text-gray-400 mb-4">{{ fmt(stats.by_platform?.[p.key]) }} تحميل</p>
          <a
            :href="agentDownloadUrl(p.key)"
            @click="onDownload"
            class="mt-auto w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition text-sm font-medium"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            تحميل
          </a>
        </div>
      </div>

      <!-- Quick start -->
      <div class="mt-10 bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
        <h2 class="text-lg font-semibold text-gray-900 mb-4">التشغيل بثلاث خطوات</h2>
        <ol class="space-y-4">
          <li class="flex gap-3">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-indigo-100 text-indigo-700 text-sm font-bold flex items-center justify-center">1</span>
            <div>
              <p class="text-gray-800 font-medium">أنشئ وكيلاً واحصل على التوكن</p>
              <p class="text-sm text-gray-500">من لوحة التحكم → صفحة <strong>Agents</strong> → «إنشاء وكيل» → انسخ التوكن.</p>
            </div>
          </li>
          <li class="flex gap-3">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-indigo-100 text-indigo-700 text-sm font-bold flex items-center justify-center">2</span>
            <div>
              <p class="text-gray-800 font-medium">شغّل الوكيل على جهاز داخل الشبكة</p>
              <pre class="mt-1 text-xs bg-slate-900 text-slate-100 rounded-lg p-3 overflow-x-auto"><code>seku-agent -server https://sec.erticaz.com -token &lt;TOKEN&gt;</code></pre>
              <p class="text-[11px] text-gray-400 mt-1">على ويندوز: <code>seku-agent.exe -server ... -token ...</code></p>
            </div>
          </li>
          <li class="flex gap-3">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-indigo-100 text-indigo-700 text-sm font-bold flex items-center justify-center">3</span>
            <div>
              <p class="text-gray-800 font-medium">عيّن فحصاً لهدف داخلي</p>
              <p class="text-sm text-gray-500">من صفحة Agents، اختر الوكيل وأدخل الهدف (مثل <code>http://192.168.1.1</code>) — الوكيل ينفّذه محلياً وترجع النتائج للوحة.</p>
            </div>
          </li>
        </ol>
        <div class="mt-4 text-xs text-gray-500 bg-amber-50 border border-amber-200 rounded-lg p-3">
          🔒 الوكيل <strong>مُقيّد أمنياً</strong>: يشغّل محرّك الفحص فقط ولا ينفّذ أوامر عامة. افحص فقط الأنظمة التي تملكها أو لديك إذن بها.
        </div>
      </div>

      <!-- Brand footer -->
      <div class="mt-8 text-center text-sm text-gray-400">
        <span class="font-semibold text-gray-500">Seku</span> — منصّة الفحص الأمني ·
        <a href="https://erticaz.com" class="text-indigo-600 hover:underline">erticaz.com</a>
      </div>
    </div>
  </div>
</template>
