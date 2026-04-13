<script setup>
import { ref, onMounted } from 'vue'
import { getProfile, getMyOrganization, changePassword, getMyAlerts, updateMyAlerts } from '../api'
import api from '../api'
import PasswordInput from '../components/PasswordInput.vue'

const user = ref(null)
const org = ref(null)
const loading = ref(true)
const saving = ref(false)
const message = ref('')
const error = ref('')

const profileForm = ref({ username: '', full_name: '', email: '' })
const passwordForm = ref({ old_password: '', new_password: '', confirm_password: '' })
const showPasswordForm = ref(false)

// Email alert state
const alertForm = ref({
  email: '',
  events: { scan_completed: true, score_drop: true, critical_found: false },
  digest_frequency: 'immediate',
  is_active: false,
})
const alertSaving = ref(false)
const alertMessage = ref('')

async function loadProfile() {
  loading.value = true
  try {
    const [userRes, orgRes, alertsRes] = await Promise.all([
      getProfile(),
      getMyOrganization(),
      getMyAlerts(),
    ])
    user.value = userRes.data
    org.value = orgRes.data
    profileForm.value = {
      username: userRes.data.username,
      full_name: userRes.data.full_name || '',
      email: userRes.data.email || '',
    }

    // Parse alert preferences
    const alert = alertsRes.data
    if (alert) {
      alertForm.value.email = alert.email || userRes.data.email || ''
      alertForm.value.is_active = alert.is_active || false
      alertForm.value.digest_frequency = alert.digest_frequency || 'immediate'
      // Parse events string into object
      const eventList = (alert.events || '').split(',').map(e => e.trim())
      alertForm.value.events = {
        scan_completed: eventList.includes('scan_completed'),
        score_drop: eventList.includes('score_drop'),
        critical_found: eventList.includes('critical_found'),
      }
    }
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
}

async function saveProfile() {
  saving.value = true
  message.value = ''
  error.value = ''
  try {
    const { data } = await api.put('/auth/profile', profileForm.value)
    user.value = data
    // Update localStorage
    const stored = JSON.parse(localStorage.getItem('user') || '{}')
    stored.username = data.username
    stored.full_name = data.full_name
    stored.email = data.email
    localStorage.setItem('user', JSON.stringify(stored))
    message.value = 'Profile updated successfully'
    setTimeout(() => message.value = '', 3000)
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to update profile'
  } finally {
    saving.value = false
  }
}

async function updatePassword() {
  message.value = ''
  error.value = ''
  if (passwordForm.value.new_password !== passwordForm.value.confirm_password) {
    error.value = 'Passwords do not match'
    return
  }
  if (passwordForm.value.new_password.length < 6) {
    error.value = 'Password must be at least 6 characters'
    return
  }
  saving.value = true
  try {
    await changePassword({
      old_password: passwordForm.value.old_password,
      new_password: passwordForm.value.new_password,
    })
    message.value = 'Password changed successfully'
    passwordForm.value = { old_password: '', new_password: '', confirm_password: '' }
    showPasswordForm.value = false
    setTimeout(() => message.value = '', 3000)
  } catch (e) {
    error.value = e.response?.data?.error || 'Failed to change password'
  } finally {
    saving.value = false
  }
}

async function saveAlerts() {
  alertSaving.value = true
  alertMessage.value = ''
  try {
    // Build events string from checkboxes
    const events = Object.entries(alertForm.value.events)
      .filter(([, v]) => v)
      .map(([k]) => k)
      .join(',')

    await updateMyAlerts({
      email: alertForm.value.email,
      events,
      min_severity: 'all',
      is_active: alertForm.value.is_active,
      digest_frequency: alertForm.value.digest_frequency,
    })
    alertMessage.value = 'Alert preferences saved!'
    setTimeout(() => alertMessage.value = '', 3000)
  } catch (e) {
    alertMessage.value = 'Failed: ' + (e.response?.data?.error || e.message)
  } finally {
    alertSaving.value = false
  }
}

const planLabels = { free: 'Free', basic: 'Basic', pro: 'Pro', enterprise: 'Enterprise' }

onMounted(loadProfile)
</script>

<template>
  <div>
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Profile Settings</h1>
      <p class="text-gray-500 mt-1">Manage your account and organization settings</p>
    </div>

    <div v-if="loading" class="flex justify-center py-20">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>

    <div v-else class="max-w-2xl space-y-6">
      <!-- Messages -->
      <div v-if="message" class="bg-green-50 border border-green-200 text-green-700 rounded-lg p-4">{{ message }}</div>
      <div v-if="error" class="bg-red-50 border border-red-200 text-red-700 rounded-lg p-4">{{ error }}</div>

      <!-- Organization Info -->
      <div v-if="org" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>
          </svg>
          Organization
        </h3>
        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span class="text-gray-500">Name:</span>
            <span class="font-medium text-gray-900 mr-2">{{ org.name }}</span>
          </div>
          <div>
            <span class="text-gray-500">Plan:</span>
            <span :class="['mr-2 px-2 py-0.5 rounded-full text-xs font-medium',
              org.plan === 'enterprise' ? 'bg-purple-100 text-purple-700' :
              org.plan === 'pro' ? 'bg-indigo-100 text-indigo-700' :
              org.plan === 'basic' ? 'bg-blue-100 text-blue-700' :
              'bg-gray-100 text-gray-700']">
              {{ planLabels[org.plan] || org.plan }}
            </span>
          </div>
          <div>
            <span class="text-gray-500">Max Targets:</span>
            <span class="font-medium text-gray-900 mr-2">{{ org.max_targets }}</span>
          </div>
          <div>
            <span class="text-gray-500">Max Scans/Month:</span>
            <span class="font-medium text-gray-900 mr-2">{{ org.max_scans }}</span>
          </div>
        </div>
      </div>

      <!-- Profile Form -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
          </svg>
          Account Information
        </h3>
        <form @submit.prevent="saveProfile" class="space-y-4">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Username</label>
            <input v-model="profileForm.username" type="text" required
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Full Name</label>
            <input v-model="profileForm.full_name" type="text"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Email</label>
            <input v-model="profileForm.email" type="email"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <button type="submit" :disabled="saving"
            class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50">
            {{ saving ? 'Saving...' : 'Save Changes' }}
          </button>
        </form>
      </div>

      <!-- Email Alert Preferences -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
          </svg>
          Email Alerts
        </h3>

        <form @submit.prevent="saveAlerts" class="space-y-4">
          <!-- Toggle active -->
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm font-medium text-gray-700">Enable Email Alerts</p>
              <p class="text-xs text-gray-400">Receive email notifications for scan events</p>
            </div>
            <button type="button" @click="alertForm.is_active = !alertForm.is_active"
              :class="[alertForm.is_active ? 'bg-indigo-600' : 'bg-gray-300', 'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full transition-colors duration-200 ease-in-out']">
              <span :class="[alertForm.is_active ? 'translate-x-5' : 'translate-x-0', 'pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out mt-0.5 ml-0.5']"></span>
            </button>
          </div>

          <div v-if="alertForm.is_active" class="space-y-4">
            <!-- Email -->
            <div>
              <label class="block text-sm text-gray-600 mb-1">Notification Email</label>
              <input v-model="alertForm.email" type="email" required
                placeholder="your@email.com"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
            </div>

            <!-- Event checkboxes -->
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">Notify me when</label>
              <div class="space-y-2">
                <label class="flex items-center gap-3 cursor-pointer">
                  <input type="checkbox" v-model="alertForm.events.scan_completed"
                    class="w-4 h-4 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500" />
                  <div>
                    <span class="text-sm text-gray-700">Scan Completed</span>
                    <p class="text-xs text-gray-400">When a scan job finishes and results are ready</p>
                  </div>
                </label>
                <label class="flex items-center gap-3 cursor-pointer">
                  <input type="checkbox" v-model="alertForm.events.score_drop"
                    class="w-4 h-4 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500" />
                  <div>
                    <span class="text-sm text-gray-700">Score Drop</span>
                    <p class="text-xs text-gray-400">When a website's security score decreases</p>
                  </div>
                </label>
                <label class="flex items-center gap-3 cursor-pointer">
                  <input type="checkbox" v-model="alertForm.events.critical_found"
                    class="w-4 h-4 text-indigo-600 border-gray-300 rounded focus:ring-indigo-500" />
                  <div>
                    <span class="text-sm text-gray-700">Critical Vulnerability Found</span>
                    <p class="text-xs text-gray-400">When a critical severity issue is detected</p>
                  </div>
                </label>
              </div>
            </div>

            <!-- Frequency -->
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-2">Delivery Frequency</label>
              <div class="grid grid-cols-3 gap-2">
                <button type="button" @click="alertForm.digest_frequency = 'immediate'"
                  :class="[alertForm.digest_frequency === 'immediate' ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50', 'px-3 py-2 text-sm rounded-lg border text-center transition-colors']">
                  Immediate
                </button>
                <button type="button" @click="alertForm.digest_frequency = 'daily'"
                  :class="[alertForm.digest_frequency === 'daily' ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50', 'px-3 py-2 text-sm rounded-lg border text-center transition-colors']">
                  Daily Digest
                </button>
                <button type="button" @click="alertForm.digest_frequency = 'weekly'"
                  :class="[alertForm.digest_frequency === 'weekly' ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50', 'px-3 py-2 text-sm rounded-lg border text-center transition-colors']">
                  Weekly Digest
                </button>
              </div>
            </div>
          </div>

          <div v-if="alertMessage" :class="['px-4 py-3 rounded-lg text-sm', alertMessage.includes('Failed') ? 'bg-red-50 text-red-700' : 'bg-green-50 text-green-700']">
            {{ alertMessage }}
          </div>

          <button type="submit" :disabled="alertSaving"
            class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50">
            {{ alertSaving ? 'Saving...' : 'Save Alert Preferences' }}
          </button>
        </form>
      </div>

      <!-- Password Change -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-lg font-semibold text-gray-900 flex items-center gap-2">
            <svg class="w-5 h-5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
            </svg>
            Password
          </h3>
          <button @click="showPasswordForm = !showPasswordForm"
            class="text-sm text-indigo-600 hover:text-indigo-800">
            {{ showPasswordForm ? 'Cancel' : 'Change Password' }}
          </button>
        </div>

        <form v-if="showPasswordForm" @submit.prevent="updatePassword" class="space-y-4">
          <div>
            <label class="block text-sm text-gray-600 mb-1">Current Password</label>
            <PasswordInput v-model="passwordForm.old_password" :required="true"
              input-class="w-full px-3 py-2 pl-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">New Password</label>
            <PasswordInput v-model="passwordForm.new_password" :required="true"
              input-class="w-full px-3 py-2 pl-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <div>
            <label class="block text-sm text-gray-600 mb-1">Confirm New Password</label>
            <PasswordInput v-model="passwordForm.confirm_password" :required="true"
              input-class="w-full px-3 py-2 pl-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" />
          </div>
          <button type="submit" :disabled="saving"
            class="px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50">
            {{ saving ? 'Changing...' : 'Change Password' }}
          </button>
        </form>
        <p v-else class="text-sm text-gray-500">Click "Change Password" to update your password</p>
      </div>
    </div>
  </div>
</template>
