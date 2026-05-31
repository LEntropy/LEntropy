import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import { policiesApi, type Policy } from '../api/client'
import { Plus, Trash2, Play, Info, Shield, ChevronUp } from 'lucide-react'

type ConditionType =
  | 'any'
  | 'os_family'
  | 'device_type'
  | 'mac_list'
  | 'mac_blacklist'
  | 'compliant'
  | 'os_version_below'
  | 'os_version_at_least'
  | 'software_installed'
  | 'software_not_installed'
  | 'has_missing_patches'
  | 'usb_enabled'
  | 'bluetooth_enabled'
  | 'folder_sharing_enabled'

interface ConditionObj {
  type: string
  value?: string
  macs?: string[]
  required?: boolean
  version?: string
  name?: string
}

function conditionSummary(conditions: unknown[]): string {
  if (!conditions || conditions.length === 0) return '전체 단말'
  const c = conditions[0] as ConditionObj
  if (c.type === 'os_family') return `OS: ${c.value}`
  if (c.type === 'device_type') return `기기유형: ${c.value}`
  if (c.type === 'mac_list') return `MAC 허용목록: ${(c.macs ?? []).length}개`
  if (c.type === 'mac_blacklist') return `MAC 블랙리스트: ${(c.macs ?? []).length}개`
  if (c.type === 'compliant') return c.required ? '컴플라이언스 준수' : '컴플라이언스 미준수'
  if (c.type === 'os_version_below') return `OS 버전 < ${c.version}`
  if (c.type === 'os_version_at_least') return `OS 버전 ≥ ${c.version}`
  if (c.type === 'software_installed') return `SW 설치됨: ${c.name}`
  if (c.type === 'software_not_installed') return `SW 미설치: ${c.name}`
  if (c.type === 'has_missing_patches') return '미적용 패치 있음'
  if (c.type === 'usb_enabled') return 'USB 활성화'
  if (c.type === 'bluetooth_enabled') return '블루투스 활성화'
  if (c.type === 'folder_sharing_enabled') return '폴더 공유 활성화'
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
  if (condType === 'mac_blacklist') {
    const macs = condValue.split('\n').map((s) => s.trim()).filter(Boolean)
    return [{ type: 'mac_blacklist', macs }]
  }
  if (condType === 'compliant') return [{ type: 'compliant', required: condValue === 'true' }]
  if (condType === 'os_version_below') return [{ type: 'os_version_below', version: condValue }]
  if (condType === 'os_version_at_least') return [{ type: 'os_version_at_least', version: condValue }]
  if (condType === 'software_installed') return [{ type: 'software_installed', name: condValue }]
  if (condType === 'software_not_installed') return [{ type: 'software_not_installed', name: condValue }]
  if (condType === 'has_missing_patches') return [{ type: 'has_missing_patches' }]
  if (condType === 'usb_enabled') return [{ type: 'usb_enabled' }]
  if (condType === 'bluetooth_enabled') return [{ type: 'bluetooth_enabled' }]
  if (condType === 'folder_sharing_enabled') return [{ type: 'folder_sharing_enabled' }]
  return []
}

// 정책 템플릿 목록
const POLICY_TEMPLATES = [
  {
    name: 'block-old-windows',
    description: 'Windows 10 빌드 19041(버전 2004) 미만 차단',
    priority: 10,
    action: 'deny' as const,
    conditions: [{ type: 'os_version_below', version: '10.0.19041' }],
    label: '구형 Windows 차단',
    icon: '🪟',
  },
  {
    name: 'block-no-antivirus',
    description: '백신(Antivirus/Defender) 미설치 단말 격리',
    priority: 20,
    action: 'quarantine' as const,
    conditions: [{ type: 'software_not_installed', name: 'antivirus' }],
    label: '백신 미설치 격리',
    icon: '🛡️',
  },
  {
    name: 'block-missing-patches',
    description: '보안 패치가 누락된 단말 격리',
    priority: 30,
    action: 'quarantine' as const,
    conditions: [{ type: 'has_missing_patches' }],
    label: '미패치 단말 격리',
    icon: '🔧',
  },
  {
    name: 'block-usb-enabled',
    description: 'USB 저장소가 활성화된 단말 차단',
    priority: 40,
    action: 'deny' as const,
    conditions: [{ type: 'usb_enabled' }],
    label: 'USB 활성 차단',
    icon: '🔌',
  },
  {
    name: 'block-folder-sharing',
    description: '폴더 공유 활성 단말 격리',
    priority: 50,
    action: 'quarantine' as const,
    conditions: [{ type: 'folder_sharing_enabled' }],
    label: '폴더공유 격리',
    icon: '📂',
  },
  {
    name: 'block-non-compliant',
    description: '컴플라이언스 검사 실패 단말 격리',
    priority: 60,
    action: 'quarantine' as const,
    conditions: [{ type: 'compliant', required: false }],
    label: '비준수 단말 격리',
    icon: '⚠️',
  },
  {
    name: 'allow-compliant',
    description: '컴플라이언스 통과 단말 허용',
    priority: 100,
    action: 'allow' as const,
    conditions: [{ type: 'compliant', required: true }],
    label: '준수 단말 허용',
    icon: '✅',
  },
  {
    name: 'deny-all',
    description: '모든 단말 차단 (기본 deny-all 정책)',
    priority: 999,
    action: 'deny' as const,
    conditions: [],
    label: '전체 차단(기본)',
    icon: '🚫',
  },
]

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
  const [showTemplates, setShowTemplates] = useState(false)
  const [applyingTemplate, setApplyingTemplate] = useState<string | null>(null)

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

  const handleApplyTemplate = async (tpl: (typeof POLICY_TEMPLATES)[number]) => {
    setApplyingTemplate(tpl.name)
    try {
      await policiesApi.create({
        name: tpl.name,
        description: tpl.description,
        priority: tpl.priority,
        action: tpl.action,
        enabled: true,
        conditions: tpl.conditions,
      })
      reload()
    } finally {
      setApplyingTemplate(null)
    }
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

  const needsValue = !['any', 'has_missing_patches', 'usb_enabled', 'bluetooth_enabled', 'folder_sharing_enabled'].includes(form.condType)
  const isTextInput = ['os_version_below', 'os_version_at_least', 'software_installed', 'software_not_installed'].includes(form.condType)
  const isMacInput = ['mac_list', 'mac_blacklist'].includes(form.condType)

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
            onClick={() => setShowTemplates(!showTemplates)}
            className="flex items-center gap-2 bg-purple-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-purple-700 transition-colors"
          >
            <Shield className="h-4 w-4" />
            템플릿
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

      {/* 정책 템플릿 */}
      {showTemplates && (
        <div className="bg-purple-50 border border-purple-200 rounded-xl p-5 mb-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-base font-semibold text-purple-900">정책 템플릿</h2>
            <button onClick={() => setShowTemplates(false)}>
              <ChevronUp className="h-4 w-4 text-purple-400" />
            </button>
          </div>
          <p className="text-xs text-purple-700 mb-3">
            자주 쓰이는 NAC 정책 템플릿입니다. 클릭하면 즉시 정책이 생성됩니다.
          </p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {POLICY_TEMPLATES.map((tpl) => {
              const exists = (policies ?? []).some((p) => p.name === tpl.name)
              return (
                <button
                  key={tpl.name}
                  onClick={() => !exists && handleApplyTemplate(tpl)}
                  disabled={exists || applyingTemplate === tpl.name}
                  title={tpl.description}
                  className={`flex items-start gap-2 p-3 rounded-lg border text-left text-xs transition-colors ${
                    exists
                      ? 'bg-gray-100 border-gray-200 text-gray-400 cursor-not-allowed'
                      : 'bg-white border-purple-200 hover:border-purple-400 hover:bg-purple-50 text-gray-700'
                  }`}
                >
                  <span className="text-lg leading-none">{tpl.icon}</span>
                  <div>
                    <div className="font-medium">{tpl.label}</div>
                    <div className="text-gray-400 mt-0.5">{tpl.description}</div>
                    {exists && <div className="text-green-500 mt-0.5 font-medium">적용됨</div>}
                  </div>
                </button>
              )
            })}
          </div>
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
                placeholder="예: block-old-windows"
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
                <option value="allow">허용 — 네트워크 접근 허용</option>
                <option value="deny">차단 — 네트워크 접근 차단</option>
                <option value="quarantine">격리 — 격리 VLAN으로 이동</option>
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
                <optgroup label="기본">
                  <option value="any">전체 단말 (조건 없음)</option>
                  <option value="os_family">OS 종류</option>
                  <option value="device_type">기기 유형</option>
                  <option value="compliant">컴플라이언스 상태</option>
                </optgroup>
                <optgroup label="MAC 주소">
                  <option value="mac_list">MAC 허용목록 (Whitelist)</option>
                  <option value="mac_blacklist">MAC 블랙리스트</option>
                </optgroup>
                <optgroup label="OS 버전">
                  <option value="os_version_below">OS 버전 미만</option>
                  <option value="os_version_at_least">OS 버전 이상</option>
                </optgroup>
                <optgroup label="소프트웨어 (에이전트 필요)">
                  <option value="software_installed">소프트웨어 설치됨</option>
                  <option value="software_not_installed">소프트웨어 미설치</option>
                  <option value="has_missing_patches">보안 패치 누락</option>
                </optgroup>
                <optgroup label="장치 보안 (에이전트 필요)">
                  <option value="usb_enabled">USB 저장소 활성화</option>
                  <option value="bluetooth_enabled">블루투스 활성화</option>
                  <option value="folder_sharing_enabled">폴더 공유 활성화</option>
                </optgroup>
              </select>
            </div>

            {/* OS 종류 선택 */}
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

            {/* 기기 유형 선택 */}
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

            {/* 컴플라이언스 상태 */}
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

            {/* MAC 목록 입력 (whitelist / blacklist 공통) */}
            {isMacInput && (
              <div className="col-span-2">
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  MAC 주소 목록{' '}
                  <span className="text-gray-400">(줄바꿈으로 구분)</span>
                  {form.condType === 'mac_blacklist' && (
                    <span className="ml-2 text-red-500">블랙리스트 — 매칭 시 차단</span>
                  )}
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

            {/* OS 버전 입력 */}
            {(form.condType === 'os_version_below' || form.condType === 'os_version_at_least') && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  OS 버전{' '}
                  <span className="text-gray-400">
                    (Windows: 10.0.19041 / Linux: 5.15.0)
                  </span>
                </label>
                <input
                  type="text"
                  value={form.condValue}
                  onChange={(e) => setForm({ ...form, condValue: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="10.0.19041"
                />
                <p className="text-xs text-gray-400 mt-1">
                  Windows: winver 확인, 예) 10.0.19041 = Win10 2004
                </p>
              </div>
            )}

            {/* 소프트웨어 이름 입력 */}
            {isTextInput && (form.condType === 'software_installed' || form.condType === 'software_not_installed') && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  소프트웨어 이름{' '}
                  <span className="text-gray-400">(부분 일치)</span>
                </label>
                <input
                  type="text"
                  value={form.condValue}
                  onChange={(e) => setForm({ ...form, condValue: e.target.value })}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="예: antivirus, windows defender"
                />
              </div>
            )}

            {/* 조건 없는 타입 안내 */}
            {['has_missing_patches', 'usb_enabled', 'bluetooth_enabled', 'folder_sharing_enabled'].includes(form.condType) && (
              <div className="flex items-center gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 text-xs text-amber-700">
                <Info className="h-4 w-4 flex-shrink-0" />
                이 조건은 에이전트가 설치된 단말에서만 동작합니다.
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
              disabled={!form.name || (needsValue && !form.condValue && !isMacInput && !isTextInput)}
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
            <div className="text-center py-12 text-gray-400">
              등록된 정책이 없습니다.{' '}
              <button
                onClick={() => setShowTemplates(true)}
                className="text-purple-500 underline hover:text-purple-700"
              >
                템플릿으로 시작하기
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
