import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

// Add auth token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Redirect to login on 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && window.location.pathname !== '/login') {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Auth
export const login = (data) => api.post('/auth/login', data)
export const getProfile = () => api.get('/auth/profile')
export const changePassword = (data) => api.put('/auth/password', data)

// Targets
export const getTargets = () => api.get('/targets')
export const createTarget = (data) => api.post('/targets', data)
export const createBulkTargets = (targets) => api.post('/targets/bulk', { targets })
export const updateTarget = (id, data) => api.put(`/targets/${id}`, data)
export const deleteTarget = (id) => api.delete(`/targets/${id}`)

// Scans
export const getScanJobs = () => api.get('/scans')
export const getScanJob = (id) => api.get(`/scans/${id}`)
export const startScan = (data) => api.post('/scans/start', data)
export const deleteScanJob = (id) => api.delete(`/scans/${id}`)

// Results
export const getScanResult = (id) => api.get(`/results/${id}`)

// Dashboard & Leaderboard
export const getDashboardStats = () => api.get('/dashboard')
export const getLeaderboard = () => api.get('/leaderboard')

// Public: Scan Criteria / Methodology
export const getScanCriteria = () => api.get('/criteria')

// AI Analysis
export const analyzeResult = (id) => api.post(`/ai/analyze/${id}`)
export const getAIAnalysis = (id) => api.get(`/ai/analysis/${id}`)

// Admin: Users
export const getUsers = () => api.get('/users')
export const createUser = (data) => api.post('/users', data)
export const updateUser = (id, data) => api.put(`/users/${id}`, data)
export const deleteUser = (id) => api.delete(`/users/${id}`)

// Admin: Settings
export const getSettings = () => api.get('/settings')
export const updateSettings = (data) => api.put('/settings', data)

export default api
