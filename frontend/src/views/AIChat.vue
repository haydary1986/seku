<script setup>
import { ref, nextTick, onMounted, watch } from 'vue'
import { chatWithAI } from '../api.js'
import { useI18n } from '../i18n'

const { lang } = useI18n()

// Load saved messages from localStorage
const STORAGE_KEY = 'seku_ai_chat_history'
function loadMessages() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    return saved ? JSON.parse(saved) : []
  } catch { return [] }
}

const messages = ref(loadMessages())
const input = ref('')
const loading = ref(false)
const messagesContainer = ref(null)

// Auto-save messages on every change
watch(messages, (val) => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(val))
}, { deep: true })

function clearChat() {
  messages.value = []
  localStorage.removeItem(STORAGE_KEY)
}

onMounted(() => {
  scrollToBottom()
})

const suggestions = [
  'What are the most critical issues in my latest scan?',
  'How do I fix HSTS configuration?',
  'Explain CSP headers and how to implement them',
  'What is the difference between TLS 1.2 and 1.3?',
  'How to achieve a perfect 1000 score?',
]

const suggestionsAr = [
  'ما هي أخطر المشاكل في آخر فحص لي؟',
  'كيف أصلح إعدادات HSTS؟',
  'اشرح ترويسات CSP وكيفية تطبيقها',
  'ما الفرق بين TLS 1.2 و TLS 1.3؟',
  'كيف أحقق درجة 1000 كاملة؟',
]

function scrollToBottom() {
  nextTick(() => {
    if (messagesContainer.value) {
      messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
    }
  })
}

async function sendMessage(text) {
  if (!text.trim()) return
  messages.value.push({ role: 'user', content: text })
  input.value = ''
  loading.value = true
  scrollToBottom()

  try {
    const { data } = await chatWithAI({ message: text, history: messages.value.slice(-10) })
    messages.value.push({ role: 'assistant', content: data.response })
  } catch (e) {
    messages.value.push({
      role: 'assistant',
      content: lang.value === 'ar'
        ? 'عذراً، حدث خطأ. يرجى التحقق من إعدادات AI.'
        : 'Sorry, I encountered an error. Please check AI settings.'
    })
  } finally {
    loading.value = false
    scrollToBottom()
  }
}

function renderMarkdown(text) {
  return text
    .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre class="bg-gray-800 dark:bg-gray-900 text-green-400 p-3 rounded-lg my-2 overflow-x-auto text-sm"><code>$2</code></pre>')
    .replace(/### (.*)/g, '<h3 class="font-bold text-lg mt-3 mb-1">$1</h3>')
    .replace(/## (.*)/g, '<h2 class="font-bold text-xl mt-3 mb-1">$1</h2>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code class="bg-gray-200 dark:bg-gray-700 px-1 rounded text-sm">$1</code>')
    .replace(/^- (.*)/gm, '<li class="mr-4">$1</li>')
    .replace(/\n/g, '<br>')
}
</script>

<template>
  <div class="flex flex-col h-[calc(100vh-80px)]">
    <!-- Header -->
    <div class="border-b border-gray-200 dark:border-gray-700 p-4 flex items-center gap-3 bg-white dark:bg-slate-900 rounded-t-xl">
      <div class="w-10 h-10 bg-indigo-100 dark:bg-indigo-900 rounded-xl flex items-center justify-center">
        <svg class="w-6 h-6 text-indigo-600 dark:text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
        </svg>
      </div>
      <div class="flex-1">
        <h2 class="font-bold text-gray-900 dark:text-white">{{ lang === 'ar' ? 'مساعد الأمان الذكي' : 'AI Security Assistant' }}</h2>
        <p class="text-xs text-gray-500 dark:text-gray-400">
          {{ lang === 'ar' ? 'اسأل عن نتائج الفحص أو أفضل ممارسات الأمان' : 'Ask about your scan results or security best practices' }}
          <span v-if="messages.length" class="text-gray-400"> — {{ messages.length }} {{ lang === 'ar' ? 'رسالة' : 'messages' }}</span>
        </p>
      </div>
      <button v-if="messages.length" @click="clearChat"
        class="px-3 py-1.5 text-xs text-red-600 border border-red-200 rounded-lg hover:bg-red-50 transition-colors flex items-center gap-1">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
        </svg>
        {{ lang === 'ar' ? 'مسح' : 'Clear' }}
      </button>
    </div>

    <!-- Messages -->
    <div class="flex-1 overflow-y-auto p-4 space-y-4 bg-gray-50 dark:bg-slate-800" ref="messagesContainer">
      <!-- Welcome message -->
      <div v-if="messages.length === 0" class="text-center py-12">
        <div class="w-16 h-16 bg-indigo-100 dark:bg-indigo-900 rounded-2xl flex items-center justify-center mx-auto mb-4">
          <svg class="w-8 h-8 text-indigo-600 dark:text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
          </svg>
        </div>
        <h3 class="text-xl font-bold text-gray-900 dark:text-white mb-2">{{ lang === 'ar' ? 'كيف يمكنني مساعدتك؟' : 'How can I help you?' }}</h3>
        <p class="text-gray-500 dark:text-gray-400 mb-6">{{ lang === 'ar' ? 'اختر سؤالاً أو اكتب سؤالك الخاص' : 'Choose a question or type your own' }}</p>
        <div class="flex flex-wrap justify-center gap-2 mt-4 max-w-2xl mx-auto">
          <button
            v-for="(s, i) in (lang === 'ar' ? suggestionsAr : suggestions)"
            :key="i"
            @click="sendMessage(s)"
            class="px-3 py-1.5 bg-white dark:bg-slate-700 border border-gray-200 dark:border-gray-600 rounded-full text-sm text-gray-700 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-indigo-900 hover:border-indigo-300 dark:hover:border-indigo-600 transition-colors"
          >
            {{ s }}
          </button>
        </div>
      </div>

      <!-- Message bubbles -->
      <div v-for="(msg, i) in messages" :key="i" :class="msg.role === 'user' ? 'flex justify-end' : 'flex justify-start'">
        <div
          :class="msg.role === 'user'
            ? 'bg-indigo-600 text-white rounded-2xl rounded-br-sm'
            : 'bg-white dark:bg-slate-700 text-gray-900 dark:text-gray-100 rounded-2xl rounded-bl-sm shadow-sm'"
          class="max-w-[80%] px-4 py-3"
        >
          <div v-if="msg.role === 'assistant'" v-html="renderMarkdown(msg.content)" class="prose prose-sm dark:prose-invert max-w-none"></div>
          <p v-else>{{ msg.content }}</p>
        </div>
      </div>

      <!-- Loading indicator -->
      <div v-if="loading" class="flex justify-start">
        <div class="bg-white dark:bg-slate-700 rounded-2xl px-4 py-3 shadow-sm">
          <div class="flex gap-1">
            <div class="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
            <div class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay:0.1s"></div>
            <div class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay:0.2s"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Input -->
    <div class="border-t border-gray-200 dark:border-gray-700 p-4 bg-white dark:bg-slate-900 rounded-b-xl">
      <form @submit.prevent="sendMessage(input)" class="flex gap-2">
        <input
          v-model="input"
          :placeholder="lang === 'ar' ? 'اسأل عن الأمان...' : 'Ask about security...'"
          class="flex-1 px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-xl bg-gray-50 dark:bg-slate-800 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
        />
        <button
          type="submit"
          :disabled="!input.trim() || loading"
          class="px-6 py-3 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl font-medium transition-colors flex items-center gap-2"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/>
          </svg>
          <span class="hidden sm:inline">{{ lang === 'ar' ? 'إرسال' : 'Send' }}</span>
        </button>
      </form>
    </div>
  </div>
</template>
