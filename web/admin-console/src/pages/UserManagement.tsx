import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { usersApi, type NacUser, type CreateUserRequest } from '../api/client'
import { UserPlus, Trash2, KeyRound, ToggleLeft, ToggleRight, X, Shield, User } from 'lucide-react'

// ── 사용자 생성 모달 ──────────────────────────────────────────────────────────
function CreateUserModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: () => void
}) {
  const [form, setForm] = useState<CreateUserRequest>({
    username: '',
    password: '',
    role: 'user',
  })
  const [confirm, setConfirm] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (form.username.trim().length === 0) {
      setError('사용자명을 입력하세요.')
      return
    }
    if (form.password.length < 8) {
      setError('비밀번호는 최소 8자 이상이어야 합니다.')
      return
    }
    if (form.password !== confirm) {
      setError('비밀번호가 일치하지 않습니다.')
      return
    }
    setLoading(true)
    try {
      await usersApi.create(form)
      onCreated()
      onClose()
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { error?: string } } })?.response?.data?.error ??
        '사용자 생성에 실패했습니다.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-md mx-4">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <h2 className="font-semibold text-gray-900">신규 사용자 추가</h2>
          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-gray-100 text-gray-400"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg px-3 py-2">
              {error}
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">사용자명</label>
            <input
              type="text"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              placeholder="예: john.doe"
              autoFocus
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              권한
            </label>
            <div className="flex gap-3">
              {(['user', 'admin'] as const).map((r) => (
                <label
                  key={r}
                  className={`flex items-center gap-2 cursor-pointer px-3 py-2 rounded-lg border text-sm transition-colors flex-1 justify-center ${
                    form.role === r
                      ? 'border-blue-500 bg-blue-50 text-blue-700'
                      : 'border-gray-200 text-gray-600 hover:bg-gray-50'
                  }`}
                >
                  <input
                    type="radio"
                    name="role"
                    value={r}
                    checked={form.role === r}
                    onChange={() => setForm({ ...form, role: r })}
                    className="sr-only"
                  />
                  {r === 'admin' ? (
                    <Shield className="h-4 w-4" />
                  ) : (
                    <User className="h-4 w-4" />
                  )}
                  {r === 'admin' ? '관리자' : '일반 사용자'}
                </label>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              비밀번호 <span className="text-gray-400 font-normal">(최소 8자)</span>
            </label>
            <input
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              비밀번호 확인
            </label>
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 text-sm border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors"
            >
              취소
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {loading ? '생성 중...' : '사용자 추가'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── 비밀번호 변경 모달 ────────────────────────────────────────────────────────
function ChangePasswordModal({
  user,
  onClose,
  onChanged,
}: {
  user: NacUser
  onClose: () => void
  onChanged: () => void
}) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (password.length < 8) {
      setError('비밀번호는 최소 8자 이상이어야 합니다.')
      return
    }
    if (password !== confirm) {
      setError('비밀번호가 일치하지 않습니다.')
      return
    }
    setLoading(true)
    try {
      await usersApi.changePassword(user.id, password)
      onChanged()
      onClose()
    } catch {
      setError('비밀번호 변경에 실패했습니다.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-sm mx-4">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div>
            <h2 className="font-semibold text-gray-900">비밀번호 변경</h2>
            <p className="text-xs text-gray-500 mt-0.5">{user.username}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-gray-100 text-gray-400">
            <X className="h-5 w-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg px-3 py-2">
              {error}
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">새 비밀번호</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">확인</label>
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 text-sm border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
            >
              취소
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? '변경 중...' : '변경'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── 메인 컴포넌트 ─────────────────────────────────────────────────────────────
export function UserManagement() {
  const { data: users, loading, reload } = useApi<NacUser[]>(usersApi.list)
  const [showCreate, setShowCreate] = useState(false)
  const [pwUser, setPwUser] = useState<NacUser | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)

  const handleToggleEnabled = async (user: NacUser) => {
    setActionLoading(user.id + 'toggle')
    try {
      if (user.enabled) await usersApi.disable(user.id)
      else await usersApi.enable(user.id)
      await reload()
    } finally {
      setActionLoading(null)
    }
  }

  const handleDelete = async (user: NacUser) => {
    if (!confirm(`"${user.username}" 사용자를 삭제하시겠습니까?\n이 작업은 되돌릴 수 없습니다.`)) {
      return
    }
    setActionLoading(user.id + 'delete')
    try {
      await usersApi.delete(user.id)
      await reload()
    } finally {
      setActionLoading(null)
    }
  }

  const adminCount = (users ?? []).filter((u) => u.role === 'admin').length
  const activeCount = (users ?? []).filter((u) => u.enabled).length

  return (
    <div className="p-6">
      {/* 헤더 */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">사용자 관리</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Captive Portal 로그인 계정 관리 · argon2 암호화 저장
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors"
        >
          <UserPlus className="h-4 w-4" />
          사용자 추가
        </button>
      </div>

      {/* 요약 */}
      <div className="grid grid-cols-3 gap-3 mb-5">
        {[
          { label: '전체 계정', value: (users ?? []).length, color: 'text-gray-700', bg: 'bg-gray-50' },
          { label: '활성화됨', value: activeCount, color: 'text-green-700', bg: 'bg-green-50' },
          { label: '관리자', value: adminCount, color: 'text-blue-700', bg: 'bg-blue-50' },
        ].map((card) => (
          <div key={card.label} className={`${card.bg} rounded-xl p-3 border border-gray-200`}>
            <p className="text-xs text-gray-500">{card.label}</p>
            <p className={`text-2xl font-bold mt-0.5 ${card.color}`}>{card.value}</p>
          </div>
        ))}
      </div>

      {/* 안내 */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg px-4 py-3 mb-4 text-sm text-blue-800 flex gap-3">
        <div className="flex-shrink-0 mt-0.5">ℹ</div>
        <div>
          <strong>Captive Portal 인증 계정</strong>입니다. 단말이 차단/격리되면 이 계정으로 로그인하여
          네트워크 접근을 요청합니다.{' '}
          <strong>관리자</strong> 계정은 NAC Console 및 포털 모두 접근 가능합니다.
        </div>
      </div>

      {loading ? (
        <div className="text-gray-400 text-center py-16 text-sm">로딩 중...</div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-5 py-3 font-medium text-gray-600">사용자명</th>
                <th className="text-left px-5 py-3 font-medium text-gray-600">권한</th>
                <th className="text-left px-5 py-3 font-medium text-gray-600">상태</th>
                <th className="text-left px-5 py-3 font-medium text-gray-600 text-xs">계정 ID</th>
                <th className="text-right px-5 py-3 font-medium text-gray-600">작업</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {(users ?? []).map((user) => (
                <tr
                  key={user.id}
                  className={`transition-colors hover:bg-gray-50 ${!user.enabled ? 'opacity-60' : ''}`}
                >
                  {/* 사용자명 */}
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-2">
                      <div
                        className={`w-7 h-7 rounded-full flex items-center justify-center text-white text-xs font-bold ${
                          user.role === 'admin' ? 'bg-blue-500' : 'bg-gray-400'
                        }`}
                      >
                        {user.username[0]?.toUpperCase()}
                      </div>
                      <span className="font-medium text-gray-900">{user.username}</span>
                    </div>
                  </td>

                  {/* 권한 */}
                  <td className="px-5 py-3.5">
                    <span
                      className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full ${
                        user.role === 'admin'
                          ? 'bg-blue-100 text-blue-700'
                          : 'bg-gray-100 text-gray-600'
                      }`}
                    >
                      {user.role === 'admin' ? (
                        <Shield className="h-3 w-3" />
                      ) : (
                        <User className="h-3 w-3" />
                      )}
                      {user.role === 'admin' ? '관리자' : '일반'}
                    </span>
                  </td>

                  {/* 상태 */}
                  <td className="px-5 py-3.5">
                    <span
                      className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                        user.enabled
                          ? 'bg-green-100 text-green-700'
                          : 'bg-gray-100 text-gray-500'
                      }`}
                    >
                      {user.enabled ? '활성화' : '비활성화'}
                    </span>
                  </td>

                  {/* ID */}
                  <td className="px-5 py-3.5">
                    <span className="font-mono text-[11px] text-gray-400">
                      {user.id.split('-')[0]}...
                    </span>
                  </td>

                  {/* 작업 버튼 */}
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-1 justify-end">
                      {/* 활성화/비활성화 토글 */}
                      <button
                        onClick={() => handleToggleEnabled(user)}
                        disabled={actionLoading === user.id + 'toggle'}
                        title={user.enabled ? '비활성화' : '활성화'}
                        className={`p-1.5 rounded transition-colors disabled:opacity-40 ${
                          user.enabled
                            ? 'text-green-600 hover:bg-green-50'
                            : 'text-gray-400 hover:bg-gray-100'
                        }`}
                      >
                        {user.enabled ? (
                          <ToggleRight className="h-5 w-5" />
                        ) : (
                          <ToggleLeft className="h-5 w-5" />
                        )}
                      </button>

                      {/* 비밀번호 변경 */}
                      <button
                        onClick={() => setPwUser(user)}
                        title="비밀번호 변경"
                        className="p-1.5 rounded text-gray-400 hover:text-blue-600 hover:bg-blue-50 transition-colors"
                      >
                        <KeyRound className="h-4 w-4" />
                      </button>

                      {/* 삭제 */}
                      <button
                        onClick={() => handleDelete(user)}
                        disabled={actionLoading === user.id + 'delete'}
                        title="사용자 삭제"
                        className="p-1.5 rounded text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors disabled:opacity-40"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {(users ?? []).length === 0 && (
            <div className="text-center py-16 text-gray-400 text-sm">
              <UserPlus className="h-8 w-8 mx-auto mb-2 text-gray-300" />
              <p>등록된 사용자가 없습니다.</p>
              <p className="text-xs mt-1">
                위의 "사용자 추가" 버튼으로 첫 번째 계정을 만드세요.
              </p>
            </div>
          )}
        </div>
      )}

      {/* 모달 */}
      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={reload}
        />
      )}
      {pwUser && (
        <ChangePasswordModal
          user={pwUser}
          onClose={() => setPwUser(null)}
          onChanged={reload}
        />
      )}
    </div>
  )
}
