<script setup>
import { ref, onMounted, computed } from 'vue'
import { getScanCriteria } from '../api'
import { useSEO } from '../composables/useSEO'

useSEO({
  title: 'منهجية التقييم الأمني — Security Methodology',
  description: 'منهجية سيكو لتقييم أمان المواقع الإلكترونية. 37 فئة فحص، نظام نقاط من 1000، OWASP Top 10، CVSS v3.1. شفافية كاملة في معايير التقييم.',
  keywords: 'منهجية أمان, OWASP, CVSS, نظام تقييم, security methodology, scoring system',
})

const methodology = ref(null)
const loading = ref(true)
const error = ref(null)
const expandedCategories = ref({})

const categoryNames = {
  ssl: 'تشفير SSL/TLS',
  headers: 'ترويسات الأمان',
  cookies: 'أمان الكوكيز',
  server_info: 'معلومات السيرفر',
  directory: 'الملفات والمجلدات',
  performance: 'أداء السيرفر',
  ddos: 'حماية DDoS',
  cors: 'إعدادات CORS',
  http_methods: 'طرق HTTP',
  dns: 'أمان DNS',
  mixed_content: 'المحتوى المختلط',
  info_disclosure: 'تسريب المعلومات',
  hosting: 'جودة الاستضافة',
  content: 'تحسين المحتوى',
  advanced_security: 'الأمان المتقدم',
  malware: 'الفايروسات والتهديدات',
  threat_intel: 'استخبارات التهديدات',
  seo: 'تحسين محركات البحث',
  third_party: 'مخاطر السكربتات الخارجية',
  js_libraries: 'مكتبات JavaScript',
}

const importanceLabels = {
  critical: 'حرج',
  high: 'عالي',
  medium: 'متوسط',
  low: 'منخفض',
}

const gradeLabels = {
  'A+': 'ممتاز',
  'A': 'جيد جداً',
  'B': 'جيد',
  'C': 'متوسط',
  'D': 'دون المتوسط',
  'F': 'راسب',
}

function getCategoryName(cat) {
  return categoryNames[cat.id] || cat.name
}

function getImportanceLabel(importance) {
  return importanceLabels[importance] || importance
}

function getGradeLabel(grade) {
  return gradeLabels[grade] || grade
}

function toggleCategory(id) {
  expandedCategories.value[id] = !expandedCategories.value[id]
}

function isCategoryExpanded(id) {
  return !!expandedCategories.value[id]
}

function expandAll() {
  if (!methodology.value) return
  methodology.value.categories.forEach(cat => {
    expandedCategories.value[cat.id] = true
  })
}

function collapseAll() {
  expandedCategories.value = {}
}

const totalWeight = computed(() => {
  if (!methodology.value) return 0
  return methodology.value.categories.reduce((sum, cat) => sum + cat.weight, 0)
})

function getImportanceColor(importance) {
  const colors = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
  }
  return colors[importance] || 'bg-gray-100 text-gray-800 border-gray-200'
}

function getGradeColor(grade) {
  const colors = {
    'A+': 'bg-emerald-500 text-white',
    'A': 'bg-green-500 text-white',
    'B': 'bg-blue-500 text-white',
    'C': 'bg-yellow-500 text-white',
    'D': 'bg-orange-500 text-white',
    'F': 'bg-red-600 text-white',
  }
  return colors[grade] || 'bg-gray-500 text-white'
}

function getGradeBorder(grade) {
  const colors = {
    'A+': 'border-emerald-200 bg-emerald-50',
    'A': 'border-green-200 bg-green-50',
    'B': 'border-blue-200 bg-blue-50',
    'C': 'border-yellow-200 bg-yellow-50',
    'D': 'border-orange-200 bg-orange-50',
    'F': 'border-red-200 bg-red-50',
  }
  return colors[grade] || 'border-gray-200 bg-gray-50'
}

function getCategoryIcon(id) {
  const icons = {
    ssl: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
    headers: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    cookies: 'M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
    server_info: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01',
    directory: 'M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z',
    performance: 'M13 10V3L4 14h7v7l9-11h-7z',
    ddos: 'M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    cors: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
    http_methods: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
    dns: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9',
    mixed_content: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
    info_disclosure: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
    hosting: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01',
    content: 'M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z',
    advanced_security: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
    malware: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
    seo: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01',
    third_party: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1',
    js_libraries: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',
    threat_intel: 'M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
  }
  return icons[id] || 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
}

function formatScore(score) {
  if (typeof score === 'number') return score.toString()
  return String(score)
}

onMounted(async () => {
  try {
    const res = await getScanCriteria()
    methodology.value = res.data.methodology
  } catch (e) {
    error.value = 'فشل في تحميل بيانات المنهجية. يرجى المحاولة مرة أخرى لاحقاً.'
    console.error('Failed to load criteria:', e)
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="public-shell" dir="rtl">

    <!-- Header Banner -->
    <header class="text-white ring-grid">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-12 sm:py-16">
        <div class="text-center">
          <div class="inline-flex items-center gap-2 bg-white/10 backdrop-blur-sm rounded-full px-4 py-1.5 text-sm font-medium mb-6">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            معيار التقييم الأمني العالمي للمواقع الإلكترونية
          </div>
          <h1 class="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight">
            Seku <span class="text-gradient">منهجية التقييم</span>
          </h1>
          <p class="mt-4 text-lg sm:text-xl text-slate-300 max-w-3xl mx-auto leading-relaxed" v-if="methodology">
            {{ methodology.description }}
          </p>
          <p class="mt-4 text-lg sm:text-xl text-slate-300 max-w-3xl mx-auto leading-relaxed" v-else-if="!loading">
            إطار شامل لتقييم أمان المواقع الإلكترونية
          </p>
          <div class="mt-8 flex flex-wrap items-center justify-center gap-6 text-sm" v-if="methodology">
            <div class="flex items-center gap-2 bg-white/10 rounded-lg px-4 py-2">
              <span class="font-medium">الإصدار</span>
              <span class="bg-white/20 rounded px-2 py-0.5 font-bold font-mono">{{ methodology.version }}</span>
            </div>
            <div class="flex items-center gap-2 bg-white/10 rounded-lg px-4 py-2">
              <span class="font-medium">الدرجة القصوى</span>
              <span class="bg-white/20 rounded px-2 py-0.5 font-bold font-mono">{{ methodology.max_score }}</span>
            </div>
            <div class="flex items-center gap-2 bg-white/10 rounded-lg px-4 py-2">
              <span class="font-medium">الفئات</span>
              <span class="bg-white/20 rounded px-2 py-0.5 font-bold font-mono">{{ methodology.categories?.length }}</span>
            </div>
          </div>
        </div>
      </div>
    </header>

    <!-- Main Content -->
    <main class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">

      <!-- Loading -->
      <div v-if="loading" class="flex flex-col items-center justify-center py-24">
        <div class="animate-spin rounded-full h-14 w-14 border-4 border-indigo-200 border-t-indigo-600"></div>
        <p class="mt-4 text-slate-500 dark:text-slate-400 text-sm">جاري تحميل المنهجية...</p>
      </div>

      <!-- Error -->
      <div v-else-if="error" class="bg-rose-500/10 border border-rose-500/30 rounded-xl p-8 text-center">
        <svg class="w-12 h-12 text-rose-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <p class="text-rose-300 font-medium">{{ error }}</p>
      </div>

      <!-- Content -->
      <div v-else-if="methodology">

        <!-- Scoring Formula Card -->
        <section class="card p-6 sm:p-8 mb-8">
          <div class="flex items-start gap-4">
            <div class="flex-shrink-0 w-12 h-12 bg-emerald-500/15 rounded-xl flex items-center justify-center">
              <svg class="w-6 h-6 text-emerald-600 dark:text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 7h6m0 10v-3m-3 3h.01M9 17h.01M9 14h.01M12 14h.01M15 11h.01M12 11h.01M9 11h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
              </svg>
            </div>
            <div class="flex-1">
              <h2 class="text-xl font-bold text-slate-900 dark:text-white mb-2">كيف يتم حساب الدرجة</h2>
              <p class="text-slate-700 dark:text-slate-300 mb-4">{{ methodology.scoring_formula }}</p>
              <div class="bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 rounded-xl p-4">
                <p class="text-sm font-medium text-slate-700 dark:text-slate-200 mb-3">توزيع أوزان الفئات (المجموع: {{ totalWeight }}%)</p>
                <div class="space-y-2">
                  <div v-for="cat in methodology.categories" :key="cat.id" class="flex items-center gap-3">
                    <span class="text-xs font-medium text-slate-700 dark:text-slate-300 w-44 truncate">{{ getCategoryName(cat) }}</span>
                    <div class="flex-1 bg-gray-200 dark:bg-white/10 rounded-full h-2.5 overflow-hidden">
                      <div
                        class="h-full rounded-full bg-accent-grad transition-all duration-500"
                        :style="{ width: (cat.weight / totalWeight * 100) + '%' }"
                      ></div>
                    </div>
                    <span class="text-xs font-bold text-slate-700 dark:text-slate-200 w-12 text-left">{{ cat.weight }}%</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <!-- Grading Scale -->
        <section class="card p-6 sm:p-8 mb-8">
          <h2 class="text-xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
            <div class="w-10 h-10 bg-amber-500/15 rounded-xl flex items-center justify-center">
              <svg class="w-5 h-5 text-amber-600 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
              </svg>
            </div>
            مقياس التقدير
          </h2>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div
              v-for="grade in methodology.grading_scale"
              :key="grade.grade"
              :class="['rounded-xl border-2 p-5 transition-all hover:shadow-md dark:bg-slate-800/50', getGradeBorder(grade.grade)]"
            >
              <div class="flex items-center gap-4 mb-3">
                <span :class="['inline-flex items-center justify-center w-14 h-14 rounded-xl text-xl font-black shadow-sm', getGradeColor(grade.grade)]">
                  {{ grade.grade }}
                </span>
                <div>
                  <p class="font-bold text-slate-900 dark:text-white text-lg">{{ getGradeLabel(grade.grade) }}</p>
                  <p class="text-sm text-slate-500 dark:text-slate-400">{{ grade.min_score }} - {{ grade.max_score }} نقطة</p>
                </div>
              </div>
              <p class="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">{{ grade.description }}</p>
            </div>
          </div>
        </section>

        <!-- Controls -->
        <div class="flex items-center justify-between mb-6">
          <h2 class="text-2xl font-bold text-slate-900 dark:text-white">فئات الأمان</h2>
          <div class="flex gap-2">
            <button
              @click="expandAll"
              class="px-4 py-2 text-sm font-medium text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg hover:bg-emerald-500/20 transition-colors"
            >
              توسيع الكل
            </button>
            <button
              @click="collapseAll"
              class="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-300 bg-gray-50 dark:bg-white/5 border border-gray-200 dark:border-white/10 rounded-lg hover:bg-gray-100 dark:hover:bg-white/10 transition-colors"
            >
              طي الكل
            </button>
          </div>
        </div>

        <!-- Category Sections -->
        <div class="space-y-4">
          <div
            v-for="(cat, catIndex) in methodology.categories"
            :key="cat.id"
            class="card card-hover overflow-hidden"
          >
            <!-- Category Header (clickable) -->
            <button
              @click="toggleCategory(cat.id)"
              class="w-full flex items-center gap-4 p-5 sm:p-6 text-right hover:bg-gray-50 dark:hover:bg-white/5 transition-colors"
            >
              <!-- Icon -->
              <div class="flex-shrink-0 w-12 h-12 bg-emerald-500/15 rounded-xl flex items-center justify-center">
                <svg class="w-6 h-6 text-emerald-600 dark:text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="getCategoryIcon(cat.id)" />
                </svg>
              </div>

              <!-- Title + Meta -->
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-3 flex-wrap">
                  <span class="text-xs font-mono text-slate-500 dark:text-slate-400">#{{ catIndex + 1 }}</span>
                  <h3 class="text-lg font-bold text-slate-900 dark:text-white">{{ getCategoryName(cat) }}</h3>
                  <span :class="['text-xs font-semibold px-2.5 py-0.5 rounded-full border', getImportanceColor(cat.importance)]">
                    {{ getImportanceLabel(cat.importance) }}
                  </span>
                </div>
                <p class="text-sm text-slate-500 dark:text-slate-400 mt-1 line-clamp-1">{{ cat.description }}</p>
              </div>

              <!-- Weight Badge -->
              <div class="flex-shrink-0 text-left hidden sm:block">
                <div class="text-2xl font-black text-emerald-600 dark:text-emerald-400 font-mono">{{ cat.weight }}%</div>
                <div class="text-xs text-slate-500 dark:text-slate-400">الوزن</div>
              </div>

              <!-- Checks count -->
              <div class="flex-shrink-0 hidden md:flex items-center gap-1 bg-slate-100 dark:bg-white/5 rounded-lg px-3 py-1.5">
                <span class="text-sm font-bold text-slate-700 dark:text-slate-200">{{ cat.checks?.length }}</span>
                <span class="text-xs text-slate-500 dark:text-slate-400">فحص</span>
              </div>

              <!-- Expand icon -->
              <svg
                :class="['w-5 h-5 text-slate-500 dark:text-slate-400 flex-shrink-0 transition-transform duration-200', isCategoryExpanded(cat.id) ? 'rotate-180' : '']"
                fill="none" stroke="currentColor" viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            <!-- Expanded Content -->
            <div v-if="isCategoryExpanded(cat.id)" class="border-t border-gray-100 dark:border-white/10">
              <!-- Description -->
              <div class="px-5 sm:px-6 pt-5 pb-2">
                <p class="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">{{ cat.description }}</p>
                <div class="sm:hidden mt-2">
                  <span class="text-sm font-bold text-emerald-600 dark:text-emerald-400">الوزن: {{ cat.weight }}%</span>
                </div>
              </div>

              <!-- Checks -->
              <div class="px-5 sm:px-6 pb-6 space-y-4 mt-2">
                <div
                  v-for="(check, checkIndex) in cat.checks"
                  :key="checkIndex"
                  class="border border-gray-200 dark:border-white/10 rounded-xl overflow-hidden"
                >
                  <!-- Check Header -->
                  <div class="bg-slate-50 dark:bg-white/5 px-5 py-4">
                    <div class="flex items-start justify-between gap-4">
                      <div class="flex-1">
                        <div class="flex items-center gap-2 flex-wrap">
                          <h4 class="font-semibold text-slate-900 dark:text-white">{{ check.name }}</h4>
                          <span class="text-xs bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 font-medium px-2 py-0.5 rounded-md">
                            الوزن: {{ check.weight }}
                          </span>
                        </div>
                        <p class="text-sm text-slate-500 dark:text-slate-400 mt-1">{{ check.description }}</p>
                      </div>
                      <div class="flex-shrink-0 text-left">
                        <div class="text-sm font-semibold text-slate-700 dark:text-slate-200">القصوى: {{ check.max_score }}</div>
                      </div>
                    </div>
                  </div>

                  <!-- Scoring Breakdown -->
                  <div class="px-5 py-4">
                    <p class="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3">تفاصيل نظام التقييم</p>
                    <div class="space-y-2">
                      <div
                        v-for="(rule, ruleIndex) in check.scoring"
                        :key="ruleIndex"
                        class="flex items-center gap-3 text-sm"
                      >
                        <!-- Score Indicator -->
                        <span
                          :class="[
                            'flex-shrink-0 inline-flex items-center justify-center min-w-[4.5rem] px-2 py-1 rounded-md text-xs font-bold font-mono',
                            typeof rule.score === 'number' && rule.score >= 900 ? 'bg-emerald-100 text-emerald-700' :
                            typeof rule.score === 'number' && rule.score >= 700 ? 'bg-green-100 text-green-700' :
                            typeof rule.score === 'number' && rule.score >= 400 ? 'bg-yellow-100 text-yellow-700' :
                            typeof rule.score === 'number' && rule.score >= 100 ? 'bg-orange-100 text-orange-700' :
                            typeof rule.score === 'number' && rule.score === 0 ? 'bg-red-100 text-red-700' :
                            'bg-blue-100 text-blue-700'
                          ]"
                        >
                          {{ formatScore(rule.score) }}
                        </span>
                        <!-- Condition -->
                        <span class="text-slate-700 dark:text-slate-200">{{ rule.condition }}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Footer Note -->
        <footer class="mt-12 card p-6 sm:p-8 text-center">
          <svg class="w-10 h-10 text-emerald-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 class="text-lg font-bold text-slate-900 dark:text-white mb-2">حول هذه المنهجية</h3>
          <p class="text-sm text-slate-700 dark:text-slate-300 max-w-2xl mx-auto leading-relaxed">
            يتم تطبيق هذه المنهجية بشكل موحد على جميع المواقع الإلكترونية التي يتم تقييمها بواسطة نظام Seku.
            تم تصميم هذا الإطار لتوفير تقييم شفاف وقابل للتكرار وشامل لوضع أمان المواقع الإلكترونية.
            يتم إجراء جميع الفحوصات تلقائياً باستخدام تقنيات غير تطفلية.
            يتم تحديث الدرجات مع كل عملية فحص لتعكس الحالة الراهنة لإعدادات أمان الموقع.
          </p>
          <p class="text-xs text-slate-500 dark:text-slate-400 mt-4">
            إطار التقييم الأمني Seku الإصدار {{ methodology.version }}
          </p>
        </footer>
      </div>
    </main>
  </div>
</template>
