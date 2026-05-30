import axios from 'axios'

export const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('nac_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('nac_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  },
)

// API 타입 정의
export interface Endpoint {
  id: string
  mac_address: string
  ip_address: string | null
  hostname: string | null
  os_family: string | null
  status: 'allowed' | 'blocked' | 'quarantine' | 'pending'
  last_seen: string | null
  created_at: string
}

export interface Policy {
  id: string
  name: string
  description: string | null
  priority: number
  action: 'allow' | 'deny' | 'quarantine'
  enabled: boolean
  created_at: string
}

export interface AuditLog {
  id: string | number
  event_type: string
  endpoint_id: string | null
  detail: Record<string, unknown> | null
  created_at: string
}

export interface DashboardStats {
  total_endpoints: number
  allowed: number
  blocked: number
  quarantine: number
  recent_events: number
}

interface PagedResponse<T> {
  total: number
  limit: number
  offset: number
  items: T[]
}

// API 함수
export const endpointsApi = {
  list: () =>
    api.get<PagedResponse<Endpoint>>('/endpoints').then((r) => ({ ...r, data: r.data.items })),
  get: (id: string) => api.get<Endpoint>(`/endpoints/${id}`),
  block: (id: string) => api.post(`/endpoints/${id}/block`),
  allow: (id: string) => api.post(`/endpoints/${id}/allow`),
  quarantine: (id: string) => api.post(`/endpoints/${id}/quarantine`),
}

export const policiesApi = {
  list: () => api.get<Policy[]>('/policies'),
  create: (data: Omit<Policy, 'id' | 'created_at'>) => api.post<Policy>('/policies', data),
  update: (id: string, data: Partial<Policy>) => api.put<Policy>(`/policies/${id}`, data),
  delete: (id: string) => api.delete(`/policies/${id}`),
}

export const auditApi = {
  list: (limit = 50) =>
    api
      .get<PagedResponse<AuditLog>>(`/audit?limit=${limit}`)
      .then((r) => ({ ...r, data: r.data.items })),
}

export const statsApi = {
  get: () => api.get<DashboardStats>('/stats'),
}
