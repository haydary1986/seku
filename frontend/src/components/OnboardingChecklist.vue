<script setup>
import { ref, computed } from 'vue'
import { useI18n } from '../i18n'
import vOnboarding from '../i18n/fragments/vOnboarding.json'

const props = defineProps({
  hasTargets: { type: Boolean, default: false },
  hasVerified: { type: Boolean, default: false },
  hasScans: { type: Boolean, default: false },
})

const emit = defineEmits(['dismiss'])

// Local translation helper: resolve the vOnboarding.* fragment, delegate
// everything else to the shared i18n instance (keeps existing t() behaviour).
const { t: _t, lang } = useI18n()
const t = (key) =>
  key.startsWith('vOnboarding.')
    ? (vOnboarding[lang.value]?.vOnboarding?.[key.slice(12)] ?? _t(key))
    : _t(key)

const DISMISS_KEY = 'seku_onboard_dismissed'
const dismissed = ref(localStorage.getItem(DISMISS_KEY) === '1')

const steps = computed(() => [
  { key: 'step1', done: props.hasTargets, to: '/targets' },
  { key: 'step2', done: props.hasVerified, to: '/targets' },
  { key: 'step3', done: props.hasScans, to: '/scans' },
  { key: 'step4', done: props.hasScans, to: '/scans' },
])

const completedCount = computed(() => steps.value.filter((s) => s.done).length)
const progressPercent = computed(() => Math.round((completedCount.value / steps.value.length) * 100))
const allComplete = computed(() => completedCount.value === steps.value.length)

// Hide automatically once everything is done OR the user dismissed it.
const visible = computed(() => !dismissed.value && !allComplete.value)

function dismiss() {
  localStorage.setItem(DISMISS_KEY, '1')
  dismissed.value = true
  emit('dismiss')
}
</script>

<template>
  <div v-if="visible" class="bg-white rounded-xl shadow-sm border border-indigo-100 p-6 mb-8">
    <!-- Header -->
    <div class="flex items-start justify-between gap-4 mb-5">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-indigo-500 to-emerald-500 flex items-center justify-center flex-shrink-0">
          <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 3l-1.5 4.5L7 9l4.5 1.5L13 15l1.5-4.5L19 9l-4.5-1.5L13 3zM6 16l-.75 2.25L3 19l2.25.75L6 22l.75-2.25L9 19l-2.25-.75L6 16z"/>
          </svg>
        </div>
        <div>
          <h3 class="text-lg font-semibold text-gray-900">{{ t('vOnboarding.title') }}</h3>
          <p class="text-sm text-gray-500">{{ t('vOnboarding.subtitle') }}</p>
        </div>
      </div>
      <button
        @click="dismiss"
        class="text-xs text-gray-400 hover:text-gray-600 transition-colors whitespace-nowrap flex-shrink-0"
      >
        {{ t('vOnboarding.dismiss') }}
      </button>
    </div>

    <!-- Progress -->
    <div class="mb-5">
      <div class="flex items-center justify-between mb-1.5">
        <span class="text-xs font-medium text-gray-500">{{ completedCount }}/{{ steps.length }} {{ t('vOnboarding.stepsCompleted') }}</span>
        <span class="text-xs font-bold text-emerald-600">{{ progressPercent }}%</span>
      </div>
      <div class="w-full bg-gray-100 rounded-full h-2 overflow-hidden">
        <div
          class="h-full rounded-full bg-gradient-to-r from-indigo-500 to-emerald-500 transition-all duration-500"
          :style="{ width: progressPercent + '%' }"
        ></div>
      </div>
    </div>

    <!-- Steps -->
    <ol class="space-y-3">
      <li v-for="(step, i) in steps" :key="step.key" class="flex items-center gap-3">
        <div
          :class="step.done ? 'bg-emerald-100 text-emerald-600' : 'bg-gray-100 text-gray-500'"
          class="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 font-semibold text-sm"
        >
          <svg v-if="step.done" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
          </svg>
          <span v-else>{{ i + 1 }}</span>
        </div>
        <div class="flex-1 min-w-0">
          <p :class="step.done ? 'text-gray-400 line-through' : 'text-gray-900'" class="text-sm font-medium">
            {{ t('vOnboarding.' + step.key + 'Title') }}
          </p>
          <p class="text-xs text-gray-400 truncate">{{ t('vOnboarding.' + step.key + 'Desc') }}</p>
        </div>
        <router-link
          v-if="!step.done"
          :to="step.to"
          class="flex-shrink-0 px-3 py-1.5 text-xs font-medium bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
        >
          {{ t('vOnboarding.' + step.key + 'Cta') }}
        </router-link>
      </li>
    </ol>
  </div>
</template>
