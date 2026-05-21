import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { policiesApi, type Policy } from '../api/client'
import { Plus, Trash2 } from 'lucide-react'

export function Policies() {
  const { data: policies, loading, reload } = useApi<Policy[]>(policiesApi.list)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState<Omit<Policy, 'id' | 'created_at'>>({
    name: '',
    description: '',
    priority: 100,
    action: 'allow',
    enabled: true,
  })

  const handleCreate = async () => {
    await policiesApi.create(form)
    setCreating(false)
    setForm({ name: '', description: '', priority: 100, action: 'allow', enabled: true })
    reload()
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
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">정책 관리</h1>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
        >
          <Plus className="h-4 w-4" />
          새 정책
        </button>
      </div>

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
                placeholder="예: Block-Unknown-Devices"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">우선순위</label>
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
                <option value="allow">허용</option>
                <option value="deny">차단</option>
                <option value="quarantine">격리</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">설명</label>
              <input
                type="text"
                value={form.description ?? ''}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button
              onClick={handleCreate}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700"
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
                <th className="text-left px-4 py-3 font-medium text-gray-600">동작</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">우선순위</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">상태</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">생성일</th>
                <th className="text-right px-4 py-3 font-medium text-gray-600">작업</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {(policies ?? []).map((p) => (
                <tr key={p.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-900">{p.name}</div>
                    {p.description && (
                      <div className="text-gray-500 text-xs">{p.description}</div>
                    )}
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
                  <td className="px-4 py-3 text-gray-600">{p.priority}</td>
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
                    {new Date(p.created_at).toLocaleDateString('ko-KR')}
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
