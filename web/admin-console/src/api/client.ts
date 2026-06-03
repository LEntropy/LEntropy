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
  os_version: string | null
  device_type: string | null
  status: 'allowed' | 'denied' | 'quarantined' | 'pending'
  last_seen: string | null
  created_at: string
  assigned_policy_id: string | null
  policy_exempt: boolean
  is_compliant: boolean | null
}

export interface Policy {
  id: string
  name: string
  description: string | null
  priority: number
  action: 'allow' | 'deny' | 'quarantine'
  enabled: boolean
  conditions: unknown[]
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
  assignPolicy: (id: string, policyId: string | null) =>
    api.post(`/endpoints/${id}/policy`, { policy_id: policyId }),
  setExempt: (id: string, exempt: boolean) =>
    api.post(`/endpoints/${id}/exempt`, { exempt }),
  getLogs: (id: string, limit = 30) =>
    api
      .get<PagedResponse<AuditLog>>(`/audit?endpoint_id=${id}&limit=${limit}`)
      .then((r) => ({ ...r, data: r.data.items })),
}

export const policiesApi = {
  list: () => api.get<Policy[]>('/policies'),
  create: (data: Omit<Policy, 'id' | 'created_at'>) => api.post<Policy>('/policies', data),
  update: (id: string, data: Partial<Policy>) => api.put<Policy>(`/policies/${id}`, data),
  delete: (id: string) => api.delete(`/policies/${id}`),
  evaluate: (defaultAction: string | null = null) =>
    api.post<{ evaluated: number; changed: number; skipped: number }>('/policies/evaluate', {
      default_action: defaultAction,
    }),
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

// ── 네트워크 관리 ────────────────────────────────────────────────────────────

export interface HostEntry {
  ip: string
  octet: number
  mac: string | null
  hostname: string | null
  os_family: string | null
  os_version: string | null
  device_type: string | null
  vendor: string | null
  nac_status: 'allowed' | 'denied' | 'quarantined' | 'pending' | 'unregistered'
  endpoint_id: string | null
  last_auth_user: string | null
  arp_active: boolean
  last_seen: string | null
}

export interface IpRule {
  id: string
  ip_cidr: string
  action: 'block' | 'quarantine'
  note: string | null
  enabled: boolean
  created_at: string
}

export const networkApi = {
  hosts: (subnet?: string) =>
    api.get<HostEntry[]>(`/network/hosts${subnet ? `?subnet=${encodeURIComponent(subnet)}` : ''}`),
  listIpRules: () => api.get<IpRule[]>('/network/ip-rules'),
  createIpRule: (data: { ip_cidr: string; action: 'block' | 'quarantine'; note?: string }) =>
    api.post<IpRule>('/network/ip-rules', data),
  deleteIpRule: (id: string) => api.delete(`/network/ip-rules/${id}`),
  enableIpRule: (id: string) => api.post(`/network/ip-rules/${id}/enable`),
  disableIpRule: (id: string) => api.post(`/network/ip-rules/${id}/disable`),
}

// ── 사용자 관리 ───────────────────────────────────────────────────────────────

export interface NacUser {
  id: string
  username: string
  role: 'admin' | 'user'
  enabled: boolean
}

export interface CreateUserRequest {
  username: string
  password: string
  role: 'admin' | 'user'
}

export const usersApi = {
  list: () => api.get<NacUser[]>('/users'),
  create: (data: CreateUserRequest) => api.post<NacUser>('/users', data),
  delete: (id: string) => api.delete(`/users/${id}`),
  changePassword: (id: string, password: string) =>
    api.put(`/users/${id}/password`, { password }),
  enable: (id: string) => api.post(`/users/${id}/enable`),
  disable: (id: string) => api.post(`/users/${id}/disable`),
}
