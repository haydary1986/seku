<script setup>
import { ref, onMounted } from 'vue'
import { getUsers, createUser, updateUser, deleteUser } from '../api'
import PasswordInput from '../components/PasswordInput.vue'

const users = ref([])
const loading = ref(true)
const showForm = ref(false)
const editingUser = ref(null)

const form = ref({ username: '', password: '', full_name: '', email: '', role: 'user' })

async function loadUsers() {
  loading.value = true
  try {
    const { data } = await getUsers()
    users.value = data
  } catch (e) {
    console.error('Failed to load users:', e)
  } finally {
    loading.value = false
  }
}

function openAdd() {
  editingUser.value = null
  form.value = { username: '', password: '', full_name: '', email: '', role: 'user' }
  showForm.value = true
}

function openEdit(user) {
  editingUser.value = user
  form.value = { username: user.username, password: '', full_name: user.full_name, email: user.email, role: user.role }
  showForm.value = true
}

async function saveUser() {
  try {
    if (editingUser.value) {
      const update = { ...form.value }
      if (!update.password) delete update.password
      await updateUser(editingUser.value.ID, update)
    } else {
      await createUser(form.value)
    }
    showForm.value = false
    await loadUsers()
  } catch (e) {
    alert(e.response?.data?.error || 'Failed to save user')
  }
}

async function removeUser(id) {
  if (!confirm('Delete this user?')) return
  try {
    await deleteUser(id)
    await loadUsers()
  } catch (e) {
    alert(e.response?.data?.error || 'Failed to delete user')
  }
}

async function toggleActive(user) {
  try {
    await updateUser(user.ID, { is_active: !user.is_active })
    await loadUsers()
  } catch (e) {
    console.error(e)
  }
}

onMounted(loadUsers)
</script>

<template>
  <div>
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900">User Management</h1>
        <p class="text-gray-500 mt-1">Manage system users and permissions</p>
      </div>
      <button @click="openAdd" class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 text-sm">
        Add User
      </button>
    </div>

    <!-- User Form -->
    <div v-if="showForm" class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
      <h3 class="text-lg font-semibold text-gray-900 mb-4">
        {{ editingUser ? 'Edit User' : 'New User' }}
      </h3>
      <form @submit.prevent="saveUser" class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label class="block text-sm text-gray-600 mb-1">Username *</label>
          <input v-model="form.username" type="text" required :disabled="!!editingUser"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100" />
        </div>
        <div>
          <label class="block text-sm text-gray-600 mb-1">{{ editingUser ? 'New Password (leave empty to keep)' : 'Password *' }}</label>
          <PasswordInput v-model="form.password" :required="!editingUser"
            input-class="w-full px-3 py-2 pl-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
        </div>
        <div>
          <label class="block text-sm text-gray-600 mb-1">Full Name</label>
          <input v-model="form.full_name" type="text"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
        </div>
        <div>
          <label class="block text-sm text-gray-600 mb-1">Email</label>
          <input v-model="form.email" type="email"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500" />
        </div>
        <div>
          <label class="block text-sm text-gray-600 mb-1">Role</label>
          <select v-model="form.role" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500">
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div class="md:col-span-2 flex gap-3">
          <button type="submit" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">Save</button>
          <button type="button" @click="showForm = false" class="px-6 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300">Cancel</button>
        </div>
      </form>
    </div>

    <!-- Users Table -->
    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      <table v-if="users.length" class="w-full text-sm">
        <thead class="bg-gray-50">
          <tr>
            <th class="py-3 px-4 text-right text-gray-600 font-medium">Username</th>
            <th class="py-3 px-4 text-right text-gray-600 font-medium">Full Name</th>
            <th class="py-3 px-4 text-right text-gray-600 font-medium">Email</th>
            <th class="py-3 px-4 text-center text-gray-600 font-medium">Role</th>
            <th class="py-3 px-4 text-center text-gray-600 font-medium">Status</th>
            <th class="py-3 px-4 text-center text-gray-600 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.ID" class="border-t border-gray-100 hover:bg-gray-50">
            <td class="py-3 px-4 font-medium text-gray-900">{{ u.username }}</td>
            <td class="py-3 px-4 text-gray-700">{{ u.full_name || '-' }}</td>
            <td class="py-3 px-4 text-gray-500">{{ u.email || '-' }}</td>
            <td class="py-3 px-4 text-center">
              <span :class="['px-2 py-1 rounded-full text-xs font-medium', u.role === 'admin' ? 'bg-purple-100 text-purple-700' : 'bg-gray-100 text-gray-700']">
                {{ u.role }}
              </span>
            </td>
            <td class="py-3 px-4 text-center">
              <button @click="toggleActive(u)" :class="['px-2 py-1 rounded-full text-xs font-medium cursor-pointer', u.is_active ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700']">
                {{ u.is_active ? 'Active' : 'Disabled' }}
              </button>
            </td>
            <td class="py-3 px-4 text-center">
              <div class="flex items-center justify-center gap-2">
                <button @click="openEdit(u)" class="text-indigo-600 hover:text-indigo-800 text-sm">Edit</button>
                <button @click="removeUser(u.ID)" class="text-red-500 hover:text-red-700 text-sm">Delete</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
