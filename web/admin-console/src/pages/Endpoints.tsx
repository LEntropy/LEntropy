import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { endpointsApi, type Endpoint } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import { Search } from 'lucide-react'

export function Endpoints() {
  const { data: endpoints, loading, reload } = useApi<Endpoint[]>(endpointsApi.list)
  const [search, setSearch] = useState('')
  const [actionLoading, setActionLoading] = useState<string | null>(null)

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
    setActionLoading(id)
    try {
      if (action === 'allow') await endpointsApi.allow(id)
      else if (action === 'block') await endpointsApi.block(id)
      else await endpointsApi.quarantine(id)
      await reload()
    } finally {
      setActionLoading(null)
    }
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">단말 관리</h1>
        <span className="text-sm text-gray-500">총 {(endpoints ?? []).length}개</span>
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
        <div className="text-gray-500">로딩 중...</div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600">MAC 주소</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">IP 주소</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">호스트명</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">OS</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">상태</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">최근 활동</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">작업</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.map((ep) => (
                <tr key={ep.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 font-mono text-xs">{ep.mac_address}</td>
                  <td className="px-4 py-3 text-gray-600">{ep.ip_address ?? '—'}</td>
                  <td className="px-4 py-3 text-gray-600">{ep.hostname ?? '—'}</td>
                  <td className="px-4 py-3 text-gray-600">{ep.os_family ?? '—'}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={ep.status} />
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">
                    {ep.last_seen
                      ? new Date(ep.last_seen).toLocaleString('ko-KR')
                      : '—'}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex gap-1 justify-end">
                      <ActionBtn
                        label="허용"
                        onClick={() => doAction(ep.id, 'allow')}
                        disabled={actionLoading === ep.id || ep.status === 'allowed'}
                        variant="success"
                      />
                      <ActionBtn
                        label="격리"
                        onClick={() => doAction(ep.id, 'quarantine')}
                        disabled={actionLoading === ep.id || ep.status === 'quarantine'}
                        variant="warning"
                      />
                      <ActionBtn
                        label="차단"
                        onClick={() => doAction(ep.id, 'block')}
                        disabled={actionLoading === ep.id || ep.status === 'blocked'}
                        variant="danger"
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="text-center py-12 text-gray-400">검색 결과가 없습니다.</div>
          )}
        </div>
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
