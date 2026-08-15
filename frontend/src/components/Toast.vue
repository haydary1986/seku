<script setup>
import { useToast } from '../composables/useToast'

const { toasts, dismiss } = useToast()
const cls = {
  success: 'bg-green-600',
  error: 'bg-red-600',
  info: 'bg-gray-800',
}
</script>

<template>
  <teleport to="body">
    <div class="fixed z-[9999] top-4 left-1/2 -translate-x-1/2 flex flex-col gap-2 items-center pointer-events-none" dir="rtl">
      <transition-group name="toast">
        <div
          v-for="t in toasts"
          :key="t.id"
          :class="cls[t.type] || cls.info"
          class="pointer-events-auto text-white px-4 py-2.5 rounded-lg shadow-lg text-sm max-w-md flex items-center gap-3"
        >
          <span>{{ t.message }}</span>
          <button @click="dismiss(t.id)" class="opacity-70 hover:opacity-100" aria-label="إغلاق">✕</button>
        </div>
      </transition-group>
    </div>
  </teleport>
</template>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: all 0.25s ease;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>
