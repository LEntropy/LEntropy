import { useApi } from '../hooks/useApi'
import { auditApi, type AuditLog as AuditLogEntry } from '../api/client'

export function AuditLog() {
  const { data: logs, loading, reload } = useApi<AuditLogEntry[]>(() => auditApi.list(100))

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">감사 로그</h1>
        <button
          onClick={() => reload()}
          className="text-sm text-blue-600 hover:underline"
        >
          새로고침
        </button>
      </div>

      {loading ? (
        <div className="text-gray-500">로딩 중...</div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600">시각</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">이벤트 유형</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">MAC 주소</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">상세</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {(logs ?? []).map((log) => (
                <tr key={log.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-gray-500 whitespace-nowrap text-xs">
                    {new Date(log.created_at).toLocaleString('ko-KR')}
                  </td>
                  <td className="px-4 py-3 font-medium text-gray-800">{log.event_type}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-600">
                    {log.mac_address ?? '—'}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">
                    <code className="bg-gray-100 px-1.5 py-0.5 rounded">
                      {JSON.stringify(log.details)}
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {(logs ?? []).length === 0 && (
            <div className="text-center py-12 text-gray-400">감사 로그가 없습니다.</div>
          )}
        </div>
      )}
    </div>
  )
}
