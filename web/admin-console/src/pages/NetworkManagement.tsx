import { useState, useCallback } from 'react'
import { useApi } from '../hooks/useApi'
import { networkApi, endpointsApi, type HostEntry } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import { Search, RefreshCw, Wifi, WifiOff, AlertCircle } from 'lucide-react'

const SUBNET_OPTIONS = [
  '192.168.0.0/24',
  '192.168.1.0/24',
  '10.0.0.0/24',
  '10.0.1.0/24',
  '172.16.0.0/24',
]

const NAC_STATUS_LABEL: Record<string, string> = {
  allowed: '허용',
  denied: '차단',
  quarantined: '격리',
  pending: '대기',
  unregistered: '미등록',
}

const NAC_STATUS_COLOR: Record<string, string> = {
  allowed: 'bg-green-100 text-green-700',
  denied: 'bg-red-100 text-red-700',
  quarantined: 'bg-yellow-100 text-yellow-700',
  pending: 'bg-blue-100 text-blue-700',
  unregistered: 'bg-gray-100 text-gray-500',
}

export function NetworkManagement() {
  const [subnet, setSubnet] = useState('192.168.0.0/24')
  const [subnetInput, setSubnetInput] = useState('192.168.0.0/24')
  const [search, setSearch] = useState('')
  const [showUnused, setShowUnused] = useState(true)
  const [actionLoading, setActionLoading] = useState<string | null>(null)

  const fetchHosts = useCallback(() => networkApi.hosts(subnet), [subnet])
  const { data: hosts, loading, reload } = useApi<HostEntry[]>(fetchHosts)

  const applySubnet = () => {
    setSubnet(subnetInput.trim())
  }

  const filtered = (hosts ?? []).filter((h) => {
    if (!showUnused && !h.arp_active && h.nac_status === 'unregistered') return false
    const q = search.toLowerCase()
    if (!q) return true
    return (
      h.ip.includes(q) ||
      (h.mac ?? '').toLowerCase().includes(q) ||
      (h.hostname ?? '').toLowerCase().includes(q) ||
      (h.os_family ?? '').toLowerCase().includes(q) ||
      (h.last_auth_user ?? '').toLowerCase().includes(q)
    )
  })

  const doAction = async (
    host: HostEntry,
    action: 'allow' | 'block' | 'quarantine',
  ) => {
    if (!host.endpoint_id) return
    setActionLoading(host.ip + action)
    try {
      if (action === 'allow') await endpointsApi.allow(host.endpoint_id)
      else if (action === 'block') await endpointsApi.block(host.endpoint_id)
      else await endpointsApi.quarantine(host.endpoint_id)
      await reload()
    } finally {
      setActionLoading(null)
    }
  }

  // 요약 통계
  const total = hosts?.length ?? 0
  const active = hosts?.filter((h) => h.arp_active).length ?? 0
  const registered = hosts?.filter((h) => h.endpoint_id).length ?? 0
  const blocked = hosts?.filter((h) => h.nac_status === 'denied').length ?? 0

  return (
    <div className="p-6">
      {/* 헤더 */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">네트워크 관리</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            서브넷 전체 IP 범위 현황 · ARP 테이블 및 NAC 등록 상태 통합 보기
          </p>
        </div>
        <button
          onClick={reload}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 text-sm bg-white border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 transition-colors"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          새로고침
        </button>
      </div>

      {/* 서브넷 선택 */}
      <div className="bg-white rounded-xl border border-gray-200 p-4 mb-4">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-sm font-medium text-gray-700 whitespace-nowrap">스캔 서브넷:</span>
          <div className="flex gap-2 flex-wrap">
            {SUBNET_OPTIONS.map((s) => (
              <button
                key={s}
                onClick={() => {
                  setSubnetInput(s)
                  setSubnet(s)
                }}
                className={`px-3 py-1 text-xs rounded-full border transition-colors ${
                  subnet === s
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-300 hover:bg-gray-50'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2 ml-auto">
            <input
              type="text"
              value={subnetInput}
              onChange={(e) => setSubnetInput(e.target.value)}
              placeholder="192.168.x.x/24"
              className="border border-gray-300 rounded px-3 py-1 text-sm w-40 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={applySubnet}
              className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
            >
              적용
            </button>
          </div>
        </div>
      </div>

      {/* 요약 카드 */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        {[
          { label: '전체 IP', value: total, color: 'text-gray-700', bg: 'bg-gray-50' },
          { label: '활성 (ARP)', value: active, color: 'text-blue-700', bg: 'bg-blue-50' },
          { label: 'NAC 등록', value: registered, color: 'text-green-700', bg: 'bg-green-50' },
          { label: '차단됨', value: blocked, color: 'text-red-700', bg: 'bg-red-50' },
        ].map((card) => (
          <div
            key={card.label}
            className={`${card.bg} rounded-xl p-3 border border-gray-200`}
          >
            <p className="text-xs text-gray-500">{card.label}</p>
            <p className={`text-2xl font-bold mt-0.5 ${card.color}`}>{card.value}</p>
          </div>
        ))}
      </div>

      {/* 필터/검색 */}
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="IP, MAC, 호스트명, OS, 사용자 검색..."
            className="w-full pl-9 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <label className="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
          <input
            type="checkbox"
            checked={showUnused}
            onChange={(e) => setShowUnused(e.target.checked)}
            className="rounded"
          />
          미사용 IP 표시
        </label>
      </div>

      {loading ? (
        <div className="text-gray-400 text-center py-16 text-sm">스캔 중...</div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-x-auto">
          <table className="w-full text-sm min-w-[900px]">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600 w-8">#</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600 whitespace-nowrap">IP 주소</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">연결 상태</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">MAC 주소</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">호스트명</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">OS / 장치</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">NAC 상태</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">인증 계정</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600 whitespace-nowrap">최근 활동</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">제어</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.map((host) => {
                const isUnused = !host.arp_active && host.nac_status === 'unregistered'
                return (
                  <tr
                    key={host.ip}
                    className={`transition-colors ${
                      isUnused
                        ? 'bg-gray-50/50 text-gray-400'
                        : host.nac_status === 'denied'
                        ? 'bg-red-50/30 hover:bg-red-50/50'
                        : 'hover:bg-gray-50'
                    }`}
                  >
                    {/* 순번 */}
                    <td className="px-4 py-2.5 text-xs text-gray-400 font-mono">
                      {host.octet}
                    </td>

                    {/* IP */}
                    <td className="px-4 py-2.5">
                      <span className="font-mono text-xs font-medium text-gray-800">
                        {host.ip}
                      </span>
                    </td>

                    {/* 연결 상태 */}
                    <td className="px-4 py-2.5">
                      {host.arp_active ? (
                        <span className="inline-flex items-center gap-1 text-xs text-green-700">
                          <Wifi className="h-3.5 w-3.5" />
                          활성
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-gray-400">
                          <WifiOff className="h-3.5 w-3.5" />
                          비활성
                        </span>
                      )}
                    </td>

                    {/* MAC */}
                    <td className="px-4 py-2.5">
                      <span className="font-mono text-xs">
                        {host.mac ?? (isUnused ? '—' : <span className="text-gray-300">—</span>)}
                      </span>
                    </td>

                    {/* 호스트명 */}
                    <td className="px-4 py-2.5">
                      <span className="text-xs">{host.hostname ?? '—'}</span>
                    </td>

                    {/* OS / 장치 */}
                    <td className="px-4 py-2.5">
                      {host.os_family ? (
                        <div>
                          <div className="text-xs text-gray-700">{host.os_family}</div>
                          {host.device_type && (
                            <div className="text-[10px] text-gray-400">{host.device_type}</div>
                          )}
                        </div>
                      ) : host.vendor ? (
                        <span className="text-xs text-gray-500">{host.vendor}</span>
                      ) : (
                        <span className="text-xs text-gray-300">—</span>
                      )}
                    </td>

                    {/* NAC 상태 */}
                    <td className="px-4 py-2.5">
                      {host.endpoint_id ? (
                        <StatusBadge
                          status={
                            host.nac_status as
                              | 'allowed'
                              | 'denied'
                              | 'quarantined'
                              | 'pending'
                          }
                        />
                      ) : (
                        <span
                          className={`inline-block text-[11px] font-medium px-2 py-0.5 rounded-full ${
                            NAC_STATUS_COLOR[host.nac_status]
                          }`}
                        >
                          {NAC_STATUS_LABEL[host.nac_status]}
                        </span>
                      )}
                    </td>

                    {/* 인증 계정 */}
                    <td className="px-4 py-2.5">
                      {host.last_auth_user ? (
                        <span className="text-xs font-medium text-blue-700 bg-blue-50 px-1.5 py-0.5 rounded">
                          {host.last_auth_user}
                        </span>
                      ) : (
                        <span className="text-xs text-gray-300">—</span>
                      )}
                    </td>

                    {/* 최근 활동 */}
                    <td className="px-4 py-2.5 text-xs text-gray-400 whitespace-nowrap">
                      {host.last_seen
                        ? new Date(host.last_seen).toLocaleString('ko-KR', {
                            month: '2-digit',
                            day: '2-digit',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        : '—'}
                    </td>

                    {/* 제어 */}
                    <td className="px-4 py-2.5">
                      {host.endpoint_id ? (
                        <div className="flex gap-1 justify-end">
                          <HostActionBtn
                            label="허용"
                            onClick={() => doAction(host, 'allow')}
                            disabled={!!actionLoading || host.nac_status === 'allowed'}
                            variant="success"
                          />
                          <HostActionBtn
                            label="격리"
                            onClick={() => doAction(host, 'quarantine')}
                            disabled={!!actionLoading || host.nac_status === 'quarantined'}
                            variant="warning"
                          />
                          <HostActionBtn
                            label="차단"
                            onClick={() => doAction(host, 'block')}
                            disabled={!!actionLoading || host.nac_status === 'denied'}
                            variant="danger"
                          />
                        </div>
                      ) : host.arp_active ? (
                        <div className="flex items-center justify-end gap-1 text-xs text-amber-600">
                          <AlertCircle className="h-3.5 w-3.5" />
                          <span>미등록</span>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {filtered.length === 0 && !loading && (
            <div className="text-center py-12 text-gray-400 text-sm">
              {search ? '검색 결과가 없습니다.' : '호스트가 없습니다.'}
            </div>
          )}
        </div>
      )}

      {/* 범례 */}
      <div className="mt-3 flex gap-4 text-xs text-gray-500 flex-wrap">
        <span className="flex items-center gap-1">
          <Wifi className="h-3.5 w-3.5 text-green-500" />
          ARP 테이블에 현재 활성
        </span>
        <span className="flex items-center gap-1">
          <WifiOff className="h-3.5 w-3.5 text-gray-400" />
          현재 비활성 (기록만 존재)
        </span>
        <span className="flex items-center gap-1">
          <AlertCircle className="h-3.5 w-3.5 text-amber-500" />
          NAC에 미등록 (ARP에는 보임)
        </span>
      </div>
    </div>
  )
}

function HostActionBtn({
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
