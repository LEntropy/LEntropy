import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { policiesApi, type Policy } from '../api/client'
import { Plus, Trash2, Play, Info } from 'lucide-react'

type ConditionType = 'any' | 'os_family' | 'device_type' | 'mac_list' | 'compliant'

interface Condition {
  type: string
  value?: string
  macs?: string[]
  required?: boolean
}

function conditionSummary(conditions: unknown[]): string {
  if (!conditions || conditions.length === 0) return '전체 단말'
  const c = conditions[0] as Condition
  if (c.type === 'os_family') return `OS: ${c.value}`
  if (c.type === 'device_type') return `기기유형: ${c.value}`
  if (c.type === 'mac_list') return `MAC 목록: ${(c.macs ?? []).length}개`
  if (c.type === 'compliant') return c.required ? '컴플라이언스 준수' : '컴플라이언스 미준수'
  return '복합 조건'
}

function buildConditions(condType: ConditionType, condValue: string): unknown[] {
  if (condType === 'any') return []
  if (condType === 'os_family') return [{ type: 'os_family', value: condValue }]
  if (condType === 'device_type') return [{ type: 'device_type', value: condValue }]
  if (condType === 'mac_list') {
    const macs = condValue.split('\n').map((s) => s.trim()).filter(Boolean)
    return [{ type: 'mac_list', macs }]
  }
  if (condType === 'compliant') return [{ type: 'compliant', required: condValue === 'true' }]
  return []
}

export function Policies() {
  const { data: policies, loading, reload } = useApi<Policy[]>(policiesApi.list)
  const [creating, setCreating] = useState(false)
  const [evaluating, setEvaluating] = useState(false)
  const [evalResult, setEvalResult] = useState<{
    evaluated: number
    changed: number
    skipped: number
  } | null>(null)
  const [defaultAction, setDefaultAction] = useState<string>('')

  const [form, setForm] = useState({
    name: '',
    description: '',
    priority: 100,
    action: 'allow' as Policy['action'],
    condType: 'any' as ConditionType,
    condValue: '',
  })

  const handleCreate = async () => {
    if (!form.name) return
    await policiesApi.create({
      name: form.name,
      description: form.description || null,
      priority: form.priority,
      action: form.action,
      enabled: true,
      conditions: buildConditions(form.condType, form.condValue),
    })
    setCreating(false)
    setForm({ name: '', description: '', priority: 100, action: 'allow', condType: 'any', condValue: '' })
    reload()
  }

  const handleEvaluate = async () => {
    setEvaluating(true)
    setEvalResult(null)
    try {
      const res = await policiesApi.evaluate(defaultAction || null)
      setEvalResult(res.data)
      reload()
    } finally {
      setEvaluating(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('정책을 삭제하시겠습니까?')) return
    await policiesApi.delete(id)
    reload()
  }

  const handleToggle = async (p: Policy) => {
    await policiesApi.update(p.id, { enabled: !p.enabled })
    reload()
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold text-gray-900">정책 관리</h1>
        <div className="flex gap-2 items-center">
          <div className="flex items-center gap-1.5">
            <label className="text-xs text-gray-500 whitespace-nowrap">미매칭 단말:</label>
            <select
              value={defaultAction}
              onChange={(e) => setDefaultAction(e.target.value)}
              className="text-xs border border-gray-300 rounded px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            >
              <option value="">변경 없음</option>
              <option value="allowed">허용</option>
              <option value="denied">차단</option>
              <option value="quarantined">격리</option>
            </select>
          </div>
          <button
            onClick={handleEvaluate}
            disabled={evaluating}
            className="flex items-center gap-2 bg-emerald-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-emerald-700 disabled:opacity-50 transition-colors"
          >
            <Play className="h-4 w-4" />
            {evaluating ? '평가 중...' : '정책 평가 실행'}
          </button>
          <button
            onClick={() => setCreating(!creating)}
            className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
          >
            <Plus className="h-4 w-4" />
            새 정책
          </button>
        </div>
      </div>

      {/* 동작 방식 안내 */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4 flex gap-3">
        <Info className="h-5 w-5 text-blue-500 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-blue-800">
          <p className="font-medium mb-1">정책 동작 방식</p>
          <p>
            정책은 <strong>우선순위(낮을수록 먼저)</strong> 순으로 평가됩니다. 단말이 조건에
            맞는 첫 번째 정책의 동작(허용·차단·격리)을 받습니다.{' '}
            <strong>"정책 평가 실행"</strong>을 누르면 등록된 모든 단말에 정책이 일괄
            적용됩니다.
          </p>
        </div>
      </div>

      {/* 평가 결과 */}
      {evalResult && (
        <div className="bg-emerald-50 border border-emerald-200 rounded-lg px-4 py-3 mb-4 text-sm text-emerald-800">
          평가 완료 — 전체 <strong>{evalResult.evaluated}개</strong> 단말 중{' '}
          <strong>{evalResult.changed}개</strong> 상태 변경됨
          {evalResult.skipped > 0 && (
            <span className="text-amber-600 ml-1">
              (예외 단말 <strong>{evalResult.skipped}개</strong> 제외)
            </span>
          )}
        </div>
      )}

      {/* 신규 정책 폼 */}
      {creating && (
        <div className="bg-white rounded-xl border border-blue-200 p-5 mb-4">
          <h2 className="text-base font-semibold text-gray-800 mb-4">새 정책 생성</h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">정책명</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="예: block-unknown-devices"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                우선순위 <span className="text-gray-400">(낮을수록 먼저 적용)</span>
              </label>
              <input
                type="number"
                value={form.priority}
                onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">동작</label>
              <select
                value={form.action}
                onChange={(e) => setForm({ ...form, action: e.target.value as Policy['action'] })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="allow">✅ 허용 — 네트워크 접근 허용</option>
                <option value="deny">🚫 차단 — 네트워크 접근 차단</option>
                <option value="quarantine">⚠️ 격리 — 격리 VLAN으로 이동</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">적용 조건</label>
              <select
                value={form.condType}
                onChange={(e) =>
                  setForm({ ...form, condType: e.target.value as ConditionType, condValue: '' })
                }
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="any">전체 단말 (조건 없음)</option>
                <option value="os_family">OS 종류</option>
                <option value="device_type">기기 유형</option>
                <option value="mac_list">특정 MAC 주소</option>
                <option value="compliant">컴플라이언스 상태</option>
              </select>
            </div>

            {form.condType === 'os_family' && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">OS 종류</label>
                <select
                  value={form.condValue}
                  onChange={(e) => setForm({ ...form, condValue: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">선택...</option>
                  <option value="Windows">Windows</option>
                  <option value="Linux">Linux</option>
                  <option value="macOS">macOS</option>
                  <option value="iOS">iOS</option>
                  <option value="Android">Android</option>
                </select>
              </div>
            )}
            {form.condType === 'device_type' && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">기기 유형</label>
                <select
                  value={form.condValue}
                  onChange={(e) => setForm({ ...form, condValue: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">선택...</option>
                  <option value="Workstation">Workstation</option>
                  <option value="Mobile">Mobile</option>
                  <option value="IoT">IoT</option>
                  <option value="Printer">Printer</option>
                </select>
              </div>
            )}
            {form.condType === 'mac_list' && (
              <div className="col-span-2">
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  MAC 주소 목록 <span className="text-gray-400">(줄바꿈으로 구분)</span>
                </label>
                <textarea
                  value={form.condValue}
                  onChange={(e) => setForm({ ...form, condValue: e.target.value })}
                  rows={3}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder={'aa:bb:cc:dd:ee:ff\n11:22:33:44:55:66'}
                />
              </div>
            )}
            {form.condType === 'compliant' && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  컴플라이언스 상태
                </label>
                <select
                  value={form.condValue}
                  onChange={(e) => setForm({ ...form, condValue: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="false">미준수 단말 (보안 검사 실패)</option>
                  <option value="true">준수 단말 (보안 검사 통과)</option>
                </select>
              </div>
            )}

            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-600 mb-1">설명 (선택)</label>
              <input
                type="text"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button
              onClick={handleCreate}
              disabled={!form.name}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
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
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600">정책명</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">적용 조건</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">동작</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">우선순위</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">활성</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">생성일</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">작업</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {(policies ?? []).map((p) => (
                <tr key={p.id} className={`hover:bg-gray-50 ${!p.enabled ? 'opacity-40' : ''}`}>
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-900">{p.name}</div>
                    {p.description && (
                      <div className="text-gray-500 text-xs mt-0.5">{p.description}</div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded-full">
                      {conditionSummary(p.conditions)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                        p.action === 'allow'
                          ? 'bg-green-100 text-green-800'
                          : p.action === 'deny'
                            ? 'bg-red-100 text-red-800'
                            : 'bg-yellow-100 text-yellow-800'
                      }`}
                    >
                      {p.action === 'allow' ? '허용' : p.action === 'deny' ? '차단' : '격리'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-600 font-mono text-xs">{p.priority}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleToggle(p)}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                        p.enabled ? 'bg-blue-600' : 'bg-gray-300'
                      }`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                          p.enabled ? 'translate-x-4' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">
                    {p.created_at ? new Date(p.created_at).toLocaleDateString('ko-KR') : '—'}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDelete(p.id)}
                      className="p-1.5 rounded text-gray-400 hover:text-red-500 hover:bg-red-50 transition-colors"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {(policies ?? []).length === 0 && (
            <div className="text-center py-12 text-gray-400">등록된 정책이 없습니다.</div>
          )}
        </div>
      )}
    </div>
  )
}
