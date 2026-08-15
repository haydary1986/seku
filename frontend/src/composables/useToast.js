import { reactive } from 'vue'

// Module-level singleton store so every component shares one toast queue.
const state = reactive({ toasts: [] })
let seq = 0

export function useToast() {
  function push(message, type = 'info', timeout = 4000) {
    const id = ++seq
    state.toasts.push({ id, message, type })
    if (timeout) setTimeout(() => dismiss(id), timeout)
    return id
  }
  function dismiss(id) {
    const i = state.toasts.findIndex((t) => t.id === id)
    if (i !== -1) state.toasts.splice(i, 1)
  }
  return {
    toasts: state.toasts,
    push,
    dismiss,
    success: (m, t) => push(m, 'success', t),
    error: (m, t) => push(m, 'error', t),
    info: (m, t) => push(m, 'info', t),
  }
}
