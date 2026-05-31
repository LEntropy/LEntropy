import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useApi } from '../hooks/useApi'
import { endpointsApi, policiesApi, type Endpoint, type Policy, type AuditLog } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import { Search, FileText, ShieldOff, X, Ban } from 'lucide-react'

// ── 이벤트 로그 모달 ─────────────────────────────────────────────────────────
function LogModal({ endpoint, onClose }: { endpoint: Endpoint; onClose: () => void }) {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    endpointsApi
      .getLogs(endpoint.id)
      .then((r) => setLogs(r.data))
      .catch(() => setLogs([]))
      .finally(() => setLoading(false))
  }, [endpoint.id])

  const eventLabel: Record<string, string> = {
    endpoint_allowed: '허용',
    endpoint_blocked: '차단',
    endpoint_quarantined: '격리',
    endpoint_policy_assigned: '정책 할당',
    endpoint_policy_exempted: '예외 설정',
    endpoint_policy_unexempted: '예외 해제',
    agent_registered: '에이전트 등록',
    agent_status_reported: '상태 보고',
    radius_auth_success: 'RADIUS 인증 성공',
    radius_auth_failure: 'RADIUS 인증 실패',
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/30">
      <div className="h-full w-full max-w-lg bg-white shadow-xl flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div>
            <h2 className="font-semibold text-gray-900 text-base">이벤트 로그</h2>
            <p className="text-xs text-gray-500 mt-0.5 font-mono">
              {endpoint.mac_address} · {endpoint.hostname ?? endpoint.ip_address ?? '—'}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center h-32 text-gray-400 text-sm">
              로딩 중...
            </div>
          ) : logs.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-gray-400 text-sm">
              이벤트 기록이 없습니다.
            </div>
          ) : (
            <ul className="divide-y divide-gray-100">
              {logs.map((log) => (
                <li key={log.id} className="px-5 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className="text-xs font-medium text-gray-800 bg-gray-100 px-1.5 py-0.5 rounded">
                        {eventLabel[log.event_type] ?? log.event_type}
                      </span>
                      {log.detail && Object.keys(log.detail).length > 0 && (
                        <p className="text-xs text-gray-500 mt-1 font-mono">
                          {JSON.stringify(log.detail)}
                        </p>
                      )}
                    </div>
                    <span className="text-xs text-gray-400 whitespace-nowrap flex-shrink-0">
                      {new Date(log.created_at).toLocaleString('ko-KR')}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}

// ── 정책 할당 드롭다운 ─────────────────────────────────────────────────────────
function PolicySelect({
  endpoint,
  policies,
  onChange,
}: {
  endpoint: Endpoint
  policies: Policy[]
  onChange: (ep: Endpoint, policyId: string | null) => Promise<void>
}) {
  const [busy, setBusy] = useState(false)
  const current = endpoint.assigned_policy_id

  const handleChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value === '' ? null : e.target.value
    setBusy(true)
    try {
      await onChange(endpoint, val)
    } finally {
      setBusy(false)
    }
  }

  return (
    <select
      value={current ?? ''}
      onChange={handleChange}
      disabled={busy || endpoint.policy_exempt}
      className="text-xs border border-gray-200 rounded px-1.5 py-0.5 bg-white text-gray-700
                 focus:outline-none focus:ring-1 focus:ring-blue-400
                 disabled:opacity-50 disabled:cursor-not-allowed max-w-[140px]"
    >
      <option value="">자동 (우선순위)</option>
      {policies.map((p) => (
        <option key={p.id} value={p.id}>
          {p.name}
        </option>
      ))}
    </select>
  )
}

// ── 메인 컴포넌트 ─────────────────────────────────────────────────────────────
export function Endpoints() {
  const navigate = useNavigate()
  const { data: endpoints, loading, reload } = useApi<Endpoint[]>(endpointsApi.list)
  const { data: policies } = useApi<Policy[]>(policiesApi.list)
  const [search, setSearch] = useState('')
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [logEndpoint, setLogEndpoint] = useState<Endpoint | null>(null)

  const filtered = (endpoints ?? []).filter((e) => {
    const q = search.toLowerCase()
    return (
      e.mac_address.toLowerCase().includes(q) ||
      (e.hostname ?? '').toLowerCase().includes(q) ||
      (e.ip_address ?? '').includes(q) ||
      (e.os_family ?? '').toLowerCase().includes(q)
    )
  })

  const doAction = async (id: string, action: 'allow' | 'block' | 'quarantine') => {
    setActionLoading(id + action)
    try {
      if (action === 'allow') await endpointsApi.allow(id)
      else if (action === 'block') await endpointsApi.block(id)
      else await endpointsApi.quarantine(id)
      await reload()
    } finally {
      setActionLoading(null)
    }
  }

  const handleAssignPolicy = useCallback(
    async (ep: Endpoint, policyId: string | null) => {
      await endpointsApi.assignPolicy(ep.id, policyId)
      await reload()
    },
    [reload],
  )

  const handleAddToBlacklist = useCallback(
    async (ep: Endpoint) => {
      const allPolicies = policies ?? []
      const blacklistPolicy = allPolicies.find((p) =>
        (p.conditions as unknown[]).some(
          (c) => (c as { type: string }).type === 'mac_blacklist',
        ),
      )

      if (!blacklistPolicy) {
        if (confirm(`블랙리스트 정책이 없습니다. "${ep.mac_address}"를 블랙리스트 페이지에서 추가하시겠습니까?`)) {
          navigate('/blacklist')
        }
        return
      }

      const existing = (blacklistPolicy.conditions as unknown[]).find(
        (c) => (c as { type: string }).type === 'mac_blacklist',
      ) as { type: string; macs: string[] } | undefined

      if (existing?.macs.some((m: string) => m.toLowerCase() === ep.mac_address.toLowerCase())) {
        alert('이미 블랙리스트에 등록된 단말입니다.')
        return
      }

      const newConditions = (blacklistPolicy.conditions as unknown[]).map((c) => {
        const cond = c as { type: string; macs: string[] }
        if (cond.type === 'mac_blacklist') {
          return { ...cond, macs: [...cond.macs, ep.mac_address] }
        }
        return cond
      })

      await policiesApi.update(blacklistPolicy.id, { conditions: newConditions })
      alert(`${ep.mac_address}이 블랙리스트에 추가되었습니다. 정책 평가를 실행하세요.`)
    },
    [policies, navigate],
  )

  const handleToggleExempt = async (ep: Endpoint) => {
    setActionLoading(ep.id + 'exempt')
    try {
      await endpointsApi.setExempt(ep.id, !ep.policy_exempt)
      await reload()
    } finally {
      setActionLoading(null)
    }
  }

  const policyMap = new Map((policies ?? []).map((p) => [p.id, p]))

  return (
    <div className="p-6">
      {/* 헤더 */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">단말 관리</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            총 {(endpoints ?? []).length}개 단말 · 정책 할당 및 예외 설정 가능
          </p>
        </div>
      </div>

      {/* 안내 박스 */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg px-4 py-3 mb-4 text-sm text-blue-800 flex gap-3">
        <div className="flex-shrink-0 mt-0.5 text-blue-400">ℹ</div>
        <div>
          <strong>정책 할당</strong>: 드롭다운으로 특정 정책을 단말에 직접 지정합니다.{' '}
          <strong>자동(우선순위)</strong>로 두면 정책 평가 시 조건이 가장 먼저 일치하는 정책이
          적용됩니다.{' '}
          <strong>예외 설정</strong>된 단말은 정책 평가에서 완전히 제외되어 현재 상태를
          유지합니다.
        </div>
      </div>

      {/* 검색 */}
      <div className="relative mb-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="MAC, IP, 호스트명, OS 검색..."
          className="w-full pl-9 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      {loading ? (
        <div className="text-gray-500 py-8 text-center text-sm">로딩 중...</div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-x-auto">
          <table className="w-full text-sm min-w-[900px]">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600 whitespace-nowrap">MAC 주소</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">IP / 호스트명</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">OS</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">상태</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">할당 정책</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600 whitespace-nowrap">예외</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600 whitespace-nowrap">최근 활동</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">제어</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.map((ep) => {
                const isExempt = ep.policy_exempt
                const assignedPolicy = ep.assigned_policy_id ? policyMap.get(ep.assigned_policy_id) : null

                return (
                  <tr
                    key={ep.id}
                    className={`hover:bg-gray-50 transition-colors ${isExempt ? 'bg-amber-50/40' : ''}`}
                  >
                    {/* MAC */}
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-gray-800">{ep.mac_address}</span>
                    </td>

                    {/* IP / 호스트명 */}
                    <td className="px-4 py-3">
                      <div className="text-gray-800 text-xs">{ep.ip_address ?? '—'}</div>
                      {ep.hostname && (
                        <div className="text-gray-400 text-xs mt-0.5 truncate max-w-[120px]">
                          {ep.hostname}
                        </div>
                      )}
                    </td>

                    {/* OS */}
                    <td className="px-4 py-3">
                      <div className="text-gray-700 text-xs">{ep.os_family ?? '—'}</div>
                      {ep.os_version && (
                        <div className="text-gray-400 text-xs">{ep.os_version}</div>
                      )}
                    </td>

                    {/* 상태 */}
                    <td className="px-4 py-3">
                      <StatusBadge status={ep.status} />
                      {ep.is_compliant !== null && (
                        <span
                          className={`block mt-1 text-[10px] font-medium ${
                            ep.is_compliant ? 'text-green-600' : 'text-red-500'
                          }`}
                        >
                          {ep.is_compliant ? '✓ 컴플라이언스' : '✗ 컴플라이언스'}
                        </span>
                      )}
                    </td>

                    {/* 할당 정책 */}
                    <td className="px-4 py-3">
                      <PolicySelect
                        endpoint={ep}
                        policies={policies ?? []}
                        onChange={handleAssignPolicy}
                      />
                      {assignedPolicy && (
                        <div className="text-[10px] text-blue-600 mt-0.5">
                          ↳ {assignedPolicy.action === 'allow' ? '허용' : assignedPolicy.action === 'deny' ? '차단' : '격리'}
                        </div>
                      )}
                    </td>

                    {/* 예외 설정 */}
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleToggleExempt(ep)}
                        disabled={actionLoading === ep.id + 'exempt'}
                        title={isExempt ? '예외 해제' : '정책 예외로 설정'}
                        className={`flex items-center gap-1 px-2 py-1 rounded text-xs font-medium transition-colors disabled:opacity-40 ${
                          isExempt
                            ? 'bg-amber-100 text-amber-700 hover:bg-amber-200'
                            : 'bg-gray-100 text-gray-500 hover:bg-gray-200'
                        }`}
                      >
                        <ShieldOff className="h-3 w-3" />
                        {isExempt ? '예외중' : '예외'}
                      </button>
                    </td>

                    {/* 최근 활동 */}
                    <td className="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">
                      {ep.last_seen
                        ? new Date(ep.last_seen).toLocaleString('ko-KR', {
                            month: '2-digit',
                            day: '2-digit',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        : '—'}
                    </td>

                    {/* 제어 버튼 */}
                    <td className="px-4 py-3">
                      <div className="flex gap-1 justify-end flex-wrap">
                        <ActionBtn
                          label="허용"
                          onClick={() => doAction(ep.id, 'allow')}
                          disabled={!!actionLoading || ep.status === 'allowed'}
                          variant="success"
                        />
                        <ActionBtn
                          label="격리"
                          onClick={() => doAction(ep.id, 'quarantine')}
                          disabled={!!actionLoading || ep.status === 'quarantined'}
                          variant="warning"
                        />
                        <ActionBtn
                          label="차단"
                          onClick={() => doAction(ep.id, 'block')}
                          disabled={!!actionLoading || ep.status === 'denied'}
                          variant="danger"
                        />
                        <button
                          onClick={() => handleAddToBlacklist(ep)}
                          title="블랙리스트에 추가"
                          className="p-1 rounded text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors"
                        >
                          <Ban className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => setLogEndpoint(ep)}
                          title="이벤트 로그 보기"
                          className="p-1 rounded text-gray-400 hover:text-blue-600 hover:bg-blue-50 transition-colors"
                        >
                          <FileText className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="text-center py-12 text-gray-400 text-sm">
              {search ? '검색 결과가 없습니다.' : '등록된 단말이 없습니다.'}
            </div>
          )}
        </div>
      )}

      {/* 이벤트 로그 모달 */}
      {logEndpoint && (
        <LogModal endpoint={logEndpoint} onClose={() => setLogEndpoint(null)} />
      )}
    </div>
  )
}

function ActionBtn({
  label,
  onClick,
  disabled,
  variant,
}: {
  label: string
  onClick: () => void
  disabled: boolean
  variant: 'success' | 'warning' | 'danger'
}) {
  const styles = {
    success: 'bg-green-100 text-green-700 hover:bg-green-200',
    warning: 'bg-yellow-100 text-yellow-700 hover:bg-yellow-200',
    danger: 'bg-red-100 text-red-700 hover:bg-red-200',
  }[variant]

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`px-2 py-1 text-xs rounded font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${styles}`}
    >
      {label}
    </button>
  )
}
