<script setup>
import { ref, onMounted, computed } from 'vue'
import { getDirectives } from '../api'

const data = ref(null)
const loading = ref(true)
const filter = ref('all') // all, critical, high, medium

const filtered = computed(() => {
  if (!data.value?.directives) return []
  if (filter.value === 'all') return data.value.directives
  return data.value.directives.filter(d => d.priority === filter.value)
})

onMounted(async () => {
  try {
    const res = await getDirectives()
    data.value = res.data
  } catch (e) {
    console.error('Failed to load directives:', e)
  } finally {
    loading.value = false
  }
})

function printDirectives() {
  window.print()
}

function getPriorityStyle(p) {
  if (p === 'critical') return 'bg-red-100 text-red-800 border-red-300'
  if (p === 'high') return 'bg-orange-100 text-orange-800 border-orange-300'
  return 'bg-yellow-100 text-yellow-800 border-yellow-300'
}

function getPriorityLabel(p) {
  if (p === 'critical') return 'حرج'
  if (p === 'high') return 'عالي'
  return 'متوسط'
}
</script>

<template>
  <div>
    <!-- Header -->
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">الأوامر الوزارية المقترحة</h1>
        <p class="text-gray-500 mt-1">مقترحات أوامر إدارية بناءً على تحليل نتائج فحص جميع المواقع الجامعية</p>
      </div>
      <button v-if="data?.directives?.length" @click="printDirectives"
        class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm flex items-center gap-2 print:hidden">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"/>
        </svg>
        طباعة
      </button>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <!-- No Data -->
    <div v-else-if="!data?.directives?.length" class="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
      <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>
      <p class="text-lg text-gray-500">لا توجد نتائج فحص حالياً</p>
      <p class="text-sm text-gray-400 mt-1">قم بإجراء فحص شامل أولاً لتوليد المقترحات</p>
    </div>

    <div v-else>
      <!-- Official Header (printable) -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-8 mb-6 print:shadow-none print:border-0">
        <div class="text-center mb-6 print:mb-8">
          <p class="text-lg font-bold text-gray-800">جمهورية العراق</p>
          <p class="text-lg font-bold text-gray-800">وزارة التعليم العالي والبحث العلمي</p>
          <p class="text-base text-gray-600 mt-2">دائرة الأمن السيبراني</p>
          <div class="w-24 h-0.5 bg-gray-300 mx-auto mt-4"></div>
          <p class="text-xl font-bold text-gray-900 mt-4">مقترحات أوامر إدارية لتحسين الأمن السيبراني للجامعات</p>
          <p class="text-sm text-gray-500 mt-2">تم توليدها آلياً بناءً على فحص {{ data.total_sites }} موقع جامعي</p>
        </div>

        <!-- Summary Stats -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div class="bg-indigo-50 rounded-lg p-4 text-center">
            <p class="text-3xl font-bold text-indigo-700">{{ data.total_sites }}</p>
            <p class="text-sm text-indigo-600">موقع تم فحصه</p>
          </div>
          <div class="bg-red-50 rounded-lg p-4 text-center">
            <p class="text-3xl font-bold text-red-700">{{ data.critical_count }}</p>
            <p class="text-sm text-red-600">أوامر حرجة</p>
          </div>
          <div class="bg-orange-50 rounded-lg p-4 text-center">
            <p class="text-3xl font-bold text-orange-700">{{ data.high_count }}</p>
            <p class="text-sm text-orange-600">أوامر عالية الأهمية</p>
          </div>
          <div class="bg-blue-50 rounded-lg p-4 text-center">
            <p class="text-3xl font-bold text-blue-700">{{ data.directives.length }}</p>
            <p class="text-sm text-blue-600">إجمالي المقترحات</p>
          </div>
        </div>
      </div>

      <!-- Filter -->
      <div class="flex gap-2 mb-4 print:hidden">
        <button @click="filter = 'all'" :class="filter === 'all' ? 'bg-indigo-600 text-white' : 'bg-gray-100 text-gray-700'"
          class="px-4 py-2 rounded-lg text-sm transition-colors">الكل ({{ data.directives.length }})</button>
        <button @click="filter = 'critical'" :class="filter === 'critical' ? 'bg-red-600 text-white' : 'bg-gray-100 text-gray-700'"
          class="px-4 py-2 rounded-lg text-sm transition-colors">حرج ({{ data.critical_count }})</button>
        <button @click="filter = 'high'" :class="filter === 'high' ? 'bg-orange-600 text-white' : 'bg-gray-100 text-gray-700'"
          class="px-4 py-2 rounded-lg text-sm transition-colors">عالي ({{ data.high_count }})</button>
        <button @click="filter = 'medium'" :class="filter === 'medium' ? 'bg-yellow-600 text-white' : 'bg-gray-100 text-gray-700'"
          class="px-4 py-2 rounded-lg text-sm transition-colors">متوسط</button>
      </div>

      <!-- Directives List -->
      <div class="space-y-4">
        <div v-for="d in filtered" :key="d.id"
          class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden print:break-inside-avoid print:shadow-none">

          <!-- Directive Header -->
          <div class="p-6">
            <div class="flex items-start gap-4">
              <div class="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center text-white font-bold text-lg"
                :class="d.priority === 'critical' ? 'bg-red-500' : d.priority === 'high' ? 'bg-orange-500' : 'bg-yellow-500'">
                {{ d.id }}
              </div>
              <div class="flex-1">
                <div class="flex items-center gap-2 mb-2">
                  <span :class="getPriorityStyle(d.priority)" class="px-2.5 py-0.5 rounded-full text-xs font-bold border">
                    {{ getPriorityLabel(d.priority) }}
                  </span>
                  <span class="text-xs text-gray-400">{{ d.category }}</span>
                  <span class="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full">
                    {{ Math.round(d.affected_pct) }}% من الجامعات
                  </span>
                </div>

                <!-- Arabic Title & Body -->
                <h3 class="text-lg font-bold text-gray-900 mb-2">{{ d.title_ar }}</h3>
                <p class="text-gray-700 leading-relaxed mb-3">{{ d.body_ar }}</p>

                <!-- English Title & Body -->
                <div class="bg-gray-50 rounded-lg p-4 mb-3" dir="ltr">
                  <h4 class="text-sm font-semibold text-gray-800 mb-1">{{ d.title }}</h4>
                  <p class="text-sm text-gray-600">{{ d.body }}</p>
                </div>

                <!-- Stats -->
                <div class="flex flex-wrap gap-3 text-sm">
                  <span class="flex items-center gap-1 text-red-600">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                    </svg>
                    {{ d.affected }} / {{ d.total_sites }} جامعة متأثرة
                  </span>
                  <span class="flex items-center gap-1 text-green-600">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
                    </svg>
                    التأثير المتوقع: {{ d.impact }}
                  </span>
                </div>

                <!-- Examples -->
                <div v-if="d.examples?.length" class="mt-3">
                  <p class="text-xs text-gray-500 mb-1">أمثلة على الجامعات المتأثرة:</p>
                  <div class="flex flex-wrap gap-1.5">
                    <span v-for="ex in d.examples" :key="ex" class="px-2 py-0.5 bg-gray-100 text-gray-600 rounded text-xs">
                      {{ ex }}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Print Footer -->
      <div class="hidden print:block mt-8 text-center text-sm text-gray-500 border-t pt-4">
        <p>تم إنشاء هذا التقرير آلياً بواسطة نظام Seku للأمن السيبراني</p>
        <p>التاريخ: {{ new Date().toLocaleDateString('ar-IQ') }}</p>
      </div>
    </div>
  </div>
</template>
