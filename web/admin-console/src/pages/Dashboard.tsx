import { useApi } from '../hooks/useApi'
import { statsApi, auditApi, type DashboardStats, type AuditLog } from '../api/client'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const COLORS = ['#22c55e', '#ef4444', '#f59e0b', '#6b7280']

export function Dashboard() {
  const { data: stats, loading: statsLoading } = useApi<DashboardStats>(statsApi.get)
  const { data: logs, loading: logsLoading } = useApi<AuditLog[]>(() => auditApi.list(10))

  const chartData = stats
    ? [
        { name: '허용', value: stats.allowed },
        { name: '차단', value: stats.blocked },
        { name: '격리', value: stats.quarantine },
        { name: '대기', value: stats.total_endpoints - stats.allowed - stats.blocked - stats.quarantine },
      ]
    : []

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">대시보드</h1>

      {/* 요약 카드 */}
      {statsLoading ? (
        <div className="text-gray-500">로딩 중...</div>
      ) : stats ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <StatCard label="전체 단말" value={stats.total_endpoints} color="blue" />
          <StatCard label="허용" value={stats.allowed} color="green" />
          <StatCard label="차단" value={stats.blocked} color="red" />
          <StatCard label="격리" value={stats.quarantine} color="yellow" />
        </div>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 차트 */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-base font-semibold text-gray-800 mb-4">단말 상태 분포</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chartData}>
              <XAxis dataKey="name" tick={{ fontSize: 12 }} />
              <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {chartData.map((_, idx) => (
                  <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* 최근 이벤트 */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-base font-semibold text-gray-800 mb-4">최근 이벤트</h2>
          {logsLoading ? (
            <div className="text-gray-500 text-sm">로딩 중...</div>
          ) : (
            <ul className="space-y-2">
              {(logs ?? []).slice(0, 8).map((log) => (
                <li key={log.id} className="flex items-start gap-3 text-sm">
                  <span className="text-gray-400 whitespace-nowrap">
                    {new Date(log.created_at).toLocaleTimeString('ko-KR')}
                  </span>
                  <span className="text-gray-700">
                    <span className="font-medium">{log.event_type}</span>
                    {log.endpoint_id && (
                      <span className="text-gray-400 ml-1 font-mono text-xs">— {log.endpoint_id.slice(0, 8)}</span>
                    )}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}

function StatCard({
  label,
  value,
  color,
}: {
  label: string
  value: number
  color: 'blue' | 'green' | 'red' | 'yellow'
}) {
  const bg = {
    blue: 'bg-blue-50 text-blue-700',
    green: 'bg-green-50 text-green-700',
    red: 'bg-red-50 text-red-700',
    yellow: 'bg-yellow-50 text-yellow-700',
  }[color]

  return (
    <div className={`rounded-xl p-4 ${bg}`}>
      <p className="text-sm font-medium opacity-70">{label}</p>
      <p className="text-3xl font-bold mt-1">{value.toLocaleString()}</p>
    </div>
  )
}
