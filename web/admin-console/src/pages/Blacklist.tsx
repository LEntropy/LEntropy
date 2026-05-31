import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { policiesApi, type Policy } from '../api/client'
import { Plus, Trash2, AlertTriangle, Ban, Info } from 'lucide-react'

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
  const [newMac, setNewMac] = useState('')
  const [addingTo, setAddingTo] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [newPolicyName, setNewPolicyName] = useState('mac-blacklist')
  const [bulkMacs, setBulkMacs] = useState('')

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
    </div>
  )
}
