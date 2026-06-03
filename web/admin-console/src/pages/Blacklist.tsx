import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { policiesApi, networkApi, type Policy, type IpRule } from '../api/client'
import { Plus, Trash2, AlertTriangle, Ban, Info, Globe } from 'lucide-react'

interface MacBlacklistCondition {
  type: 'mac_blacklist'
  macs: string[]
}

function getBlacklistMacs(policy: Policy): string[] {
  for (const c of policy.conditions as unknown[]) {
    const cond = c as { type: string; macs?: string[] }
    if (cond.type === 'mac_blacklist' && Array.isArray(cond.macs)) {
      return cond.macs
    }
  }
  return []
}

export function Blacklist() {
  const { data: policies, loading, reload } = useApi<Policy[]>(policiesApi.list)
  const { data: ipRules, reload: reloadIpRules } = useApi<IpRule[]>(networkApi.listIpRules)
  const [newMac, setNewMac] = useState('')
  const [addingTo, setAddingTo] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [newPolicyName, setNewPolicyName] = useState('mac-blacklist')
  const [bulkMacs, setBulkMacs] = useState('')
  const [addingIp, setAddingIp] = useState(false)
  const [newIpCidr, setNewIpCidr] = useState('')
  const [newIpAction, setNewIpAction] = useState<'block' | 'quarantine'>('block')
  const [newIpNote, setNewIpNote] = useState('')

  const blacklistPolicies = (policies ?? []).filter((p) =>
    (p.conditions as unknown[]).some(
      (c) => (c as { type: string }).type === 'mac_blacklist',
    ),
  )

  const handleAddMac = async (policy: Policy) => {
    const mac = newMac.trim()
    if (!mac) return

    const existing = getBlacklistMacs(policy)
    if (existing.some((m) => m.toLowerCase() === mac.toLowerCase())) {
      alert('이미 블랙리스트에 있는 MAC 주소입니다.')
      return
    }

    const newConditions = (policy.conditions as unknown[]).map((c) => {
      const cond = c as MacBlacklistCondition
      if (cond.type === 'mac_blacklist') {
        return { ...cond, macs: [...cond.macs, mac] }
      }
      return cond
    })

    await policiesApi.update(policy.id, { conditions: newConditions })
    setNewMac('')
    setAddingTo(null)
    reload()
  }

  const handleRemoveMac = async (policy: Policy, mac: string) => {
    if (!confirm(`${mac}을 블랙리스트에서 제거하시겠습니까?`)) return

    const newConditions = (policy.conditions as unknown[]).map((c) => {
      const cond = c as MacBlacklistCondition
      if (cond.type === 'mac_blacklist') {
        return { ...cond, macs: cond.macs.filter((m) => m !== mac) }
      }
      return cond
    })

    await policiesApi.update(policy.id, { conditions: newConditions })
    reload()
  }

  const handleCreateBlacklistPolicy = async () => {
    const macs = bulkMacs
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean)

    await policiesApi.create({
      name: newPolicyName,
      description: 'MAC 주소 블랙리스트 — 등록된 단말 자동 차단',
      priority: 1,
      action: 'deny',
      enabled: true,
      conditions: [{ type: 'mac_blacklist', macs }],
    })
    setCreating(false)
    setNewPolicyName('mac-blacklist')
    setBulkMacs('')
    reload()
  }

  const handleDeletePolicy = async (id: string) => {
    if (!confirm('블랙리스트 정책을 삭제하시겠습니까?')) return
    await policiesApi.delete(id)
    reload()
  }

  const handleAddIpRule = async () => {
    const cidr = newIpCidr.trim()
    if (!cidr) return
    try {
      await networkApi.createIpRule({
        ip_cidr: cidr,
        action: newIpAction,
        note: newIpNote.trim() || undefined,
      })
      setNewIpCidr('')
      setNewIpNote('')
      setAddingIp(false)
      reloadIpRules()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
      alert(msg ?? 'IP 차단 규칙 추가 실패')
    }
  }

  const handleDeleteIpRule = async (id: string, cidr: string) => {
    if (!confirm(`${cidr} IP 차단 규칙을 삭제하시겠습니까?`)) return
    await networkApi.deleteIpRule(id)
    reloadIpRules()
  }

  const handleToggleIpRule = async (rule: IpRule) => {
    if (rule.enabled) {
      await networkApi.disableIpRule(rule.id)
    } else {
      await networkApi.enableIpRule(rule.id)
    }
    reloadIpRules()
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <Ban className="h-7 w-7 text-red-500" />
          <h1 className="text-2xl font-bold text-gray-900">블랙리스트 관리</h1>
        </div>
        <button
          onClick={() => setCreating(!creating)}
          className="flex items-center gap-2 bg-red-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-red-700 transition-colors"
        >
          <Plus className="h-4 w-4" />
          새 블랙리스트 그룹
        </button>
      </div>

      <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-4 flex gap-3">
        <AlertTriangle className="h-5 w-5 text-amber-500 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-amber-800">
          <p className="font-medium mb-1">블랙리스트 동작 방식</p>
          <p>
            블랙리스트에 등록된 MAC 주소의 단말은{' '}
            <strong>우선순위 1번으로 즉시 차단</strong>됩니다.{' '}
            "단말 관리" 탭에서도 단말 우클릭 또는 액션 버튼으로 빠르게 추가할 수 있습니다.
            등록 후 <strong>정책 평가 실행</strong>이 필요합니다.
          </p>
        </div>
      </div>

      {/* 신규 블랙리스트 그룹 생성 폼 */}
      {creating && (
        <div className="bg-white rounded-xl border border-red-200 p-5 mb-4">
          <h2 className="text-base font-semibold text-gray-800 mb-4">새 블랙리스트 그룹 생성</h2>
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">그룹명</label>
              <input
                type="text"
                value={newPolicyName}
                onChange={(e) => setNewPolicyName(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500"
                placeholder="예: mac-blacklist, blocked-devices"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                MAC 주소 목록 <span className="text-gray-400">(줄바꿈으로 구분, 비워도 됨)</span>
              </label>
              <textarea
                value={bulkMacs}
                onChange={(e) => setBulkMacs(e.target.value)}
                rows={4}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-red-500"
                placeholder={'aa:bb:cc:dd:ee:ff\n11:22:33:44:55:66'}
              />
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button
              onClick={handleCreateBlacklistPolicy}
              disabled={!newPolicyName}
              className="bg-red-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-red-700 disabled:opacity-50"
            >
              생성
            </button>
            <button
              onClick={() => setCreating(false)}
              className="bg-gray-100 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-200"
            >
              취소
            </button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="text-gray-500">로딩 중...</div>
      ) : blacklistPolicies.length === 0 ? (
        <div className="bg-white rounded-xl border border-gray-200 p-12 text-center">
          <Ban className="h-12 w-12 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-500 mb-2">등록된 블랙리스트가 없습니다.</p>
          <button
            onClick={() => setCreating(true)}
            className="text-red-500 text-sm underline hover:text-red-700"
          >
            새 블랙리스트 그룹 만들기
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {blacklistPolicies.map((policy) => {
            const macs = getBlacklistMacs(policy)
            return (
              <div key={policy.id} className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                <div className="flex items-center justify-between px-5 py-3 bg-gray-50 border-b border-gray-200">
                  <div className="flex items-center gap-3">
                    <Ban className="h-4 w-4 text-red-400" />
                    <div>
                      <span className="font-semibold text-gray-800">{policy.name}</span>
                      {policy.description && (
                        <span className="ml-2 text-xs text-gray-500">{policy.description}</span>
                      )}
                    </div>
                    <span className="text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded-full">
                      {macs.length}개 등록
                    </span>
                    {!policy.enabled && (
                      <span className="text-xs bg-gray-200 text-gray-500 px-2 py-0.5 rounded-full">
                        비활성
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setAddingTo(addingTo === policy.id ? null : policy.id)}
                      className="text-xs bg-red-50 text-red-600 px-3 py-1.5 rounded-lg border border-red-200 hover:bg-red-100 transition-colors flex items-center gap-1"
                    >
                      <Plus className="h-3 w-3" />
                      MAC 추가
                    </button>
                    <button
                      onClick={() => handleDeletePolicy(policy.id)}
                      className="p-1.5 rounded text-gray-400 hover:text-red-500 hover:bg-red-50 transition-colors"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                {/* MAC 추가 입력 */}
                {addingTo === policy.id && (
                  <div className="px-5 py-3 bg-red-50 border-b border-red-100 flex gap-2">
                    <input
                      type="text"
                      value={newMac}
                      onChange={(e) => setNewMac(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleAddMac(policy)}
                      className="flex-1 border border-gray-300 rounded-lg px-3 py-1.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-red-500"
                      placeholder="aa:bb:cc:dd:ee:ff"
                      autoFocus
                    />
                    <button
                      onClick={() => handleAddMac(policy)}
                      className="bg-red-600 text-white px-3 py-1.5 rounded-lg text-sm hover:bg-red-700"
                    >
                      추가
                    </button>
                    <button
                      onClick={() => { setAddingTo(null); setNewMac('') }}
                      className="bg-gray-100 text-gray-600 px-3 py-1.5 rounded-lg text-sm hover:bg-gray-200"
                    >
                      취소
                    </button>
                  </div>
                )}

                {/* MAC 목록 */}
                {macs.length === 0 ? (
                  <div className="px-5 py-6 text-center text-sm text-gray-400">
                    등록된 MAC 주소가 없습니다. 위의 "MAC 추가" 버튼을 클릭하세요.
                  </div>
                ) : (
                  <div className="divide-y divide-gray-100">
                    {macs.map((mac) => (
                      <div key={mac} className="flex items-center justify-between px-5 py-2.5">
                        <span className="font-mono text-sm text-gray-800">{mac}</span>
                        <button
                          onClick={() => handleRemoveMac(policy, mac)}
                          className="p-1 rounded text-gray-300 hover:text-red-500 hover:bg-red-50 transition-colors"
                          title="블랙리스트에서 제거"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      <div className="mt-4 bg-blue-50 border border-blue-100 rounded-lg p-3 flex gap-2">
        <Info className="h-4 w-4 text-blue-400 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-blue-700">
          블랙리스트 정책의 우선순위는 기본값 1입니다. 더 낮은 우선순위의 정책이 있다면{' '}
          <strong>정책 관리</strong> 탭에서 순서를 조정하세요. 등록/변경 후에는 반드시{' '}
          <strong>정책 평가 실행</strong>을 해야 단말 상태가 업데이트됩니다.
        </p>
      </div>

      {/* ── IP 직접 차단 섹션 ─────────────────────────────── */}
      <div className="mt-8">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <Globe className="h-6 w-6 text-orange-500" />
            <h2 className="text-xl font-bold text-gray-900">IP 직접 차단</h2>
            <span className="text-xs bg-orange-100 text-orange-700 px-2 py-0.5 rounded-full">
              {(ipRules ?? []).filter((r) => r.enabled).length}개 활성
            </span>
          </div>
          <button
            onClick={() => setAddingIp(!addingIp)}
            className="flex items-center gap-2 bg-orange-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-orange-700 transition-colors"
          >
            <Plus className="h-4 w-4" />
            IP 차단 추가
          </button>
        </div>

        <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 mb-3 flex gap-2">
          <AlertTriangle className="h-4 w-4 text-amber-500 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-amber-800">
            IP 기반 차단은 MAC 주소에 관계없이 특정 IP를 즉시 차단합니다. CIDR 표기법 지원
            (예: <code className="bg-amber-100 px-1 rounded">192.168.0.50</code>,{' '}
            <code className="bg-amber-100 px-1 rounded">192.168.0.0/24</code>).
          </p>
        </div>

        {/* IP 차단 추가 폼 */}
        {addingIp && (
          <div className="bg-white rounded-xl border border-orange-200 p-4 mb-3">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">IP / CIDR</label>
                <input
                  type="text"
                  value={newIpCidr}
                  onChange={(e) => setNewIpCidr(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAddIpRule()}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-orange-500"
                  placeholder="192.168.0.50"
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">동작</label>
                <select
                  value={newIpAction}
                  onChange={(e) => setNewIpAction(e.target.value as 'block' | 'quarantine')}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500"
                >
                  <option value="block">완전 차단 (block)</option>
                  <option value="quarantine">격리 (quarantine)</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">메모 (선택)</label>
                <input
                  type="text"
                  value={newIpNote}
                  onChange={(e) => setNewIpNote(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-500"
                  placeholder="차단 사유..."
                />
              </div>
            </div>
            <div className="flex gap-2 mt-3">
              <button
                onClick={handleAddIpRule}
                disabled={!newIpCidr.trim()}
                className="bg-orange-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-orange-700 disabled:opacity-50"
              >
                차단 적용
              </button>
              <button
                onClick={() => { setAddingIp(false); setNewIpCidr(''); setNewIpNote('') }}
                className="bg-gray-100 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-200"
              >
                취소
              </button>
            </div>
          </div>
        )}

        {/* IP 규칙 목록 */}
        {(ipRules ?? []).length === 0 ? (
          <div className="bg-white rounded-xl border border-gray-200 p-8 text-center">
            <Globe className="h-10 w-10 text-gray-300 mx-auto mb-2" />
            <p className="text-gray-500 text-sm">등록된 IP 차단 규칙이 없습니다.</p>
          </div>
        ) : (
          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 uppercase">IP / CIDR</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 uppercase">동작</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 uppercase">메모</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 uppercase">상태</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 uppercase">등록일</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {(ipRules ?? []).map((rule) => (
                  <tr key={rule.id} className={rule.enabled ? '' : 'opacity-50'}>
                    <td className="px-4 py-2.5 font-mono text-gray-800">{rule.ip_cidr}</td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                          rule.action === 'block'
                            ? 'bg-red-100 text-red-700'
                            : 'bg-yellow-100 text-yellow-700'
                        }`}
                      >
                        {rule.action === 'block' ? '완전 차단' : '격리'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-gray-500">{rule.note ?? '—'}</td>
                    <td className="px-4 py-2.5">
                      <button
                        onClick={() => handleToggleIpRule(rule)}
                        className={`text-xs px-2 py-0.5 rounded-full font-medium transition-colors ${
                          rule.enabled
                            ? 'bg-green-100 text-green-700 hover:bg-green-200'
                            : 'bg-gray-100 text-gray-500 hover:bg-gray-200'
                        }`}
                      >
                        {rule.enabled ? '활성' : '비활성'}
                      </button>
                    </td>
                    <td className="px-4 py-2.5 text-gray-400 text-xs">
                      {rule.created_at.slice(0, 10)}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        onClick={() => handleDeleteIpRule(rule.id, rule.ip_cidr)}
                        className="p-1 rounded text-gray-300 hover:text-red-500 hover:bg-red-50 transition-colors"
                        title="차단 규칙 삭제"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
