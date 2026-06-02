import { NavLink, Outlet } from 'react-router-dom'
import { Shield, Monitor, FileText, Activity, LogOut, Ban, Network, Users } from 'lucide-react'
import { clsx } from 'clsx'

const nav = [
  { to: '/', label: '대시보드', icon: Activity, end: true },
  { to: '/endpoints', label: '단말 관리', icon: Monitor },
  { to: '/network', label: '네트워크 관리', icon: Network },
  { to: '/policies', label: '정책 관리', icon: Shield },
  { to: '/blacklist', label: '블랙리스트', icon: Ban },
  { to: '/users', label: '사용자 관리', icon: Users },
  { to: '/audit', label: '감사 로그', icon: FileText },
]

export function Layout() {
  const handleLogout = () => {
    localStorage.removeItem('nac_token')
    window.location.href = '/login'
  }

  return (
    <div className="flex h-screen">
      {/* 사이드바 */}
      <aside className="w-60 bg-gray-900 text-white flex flex-col">
        <div className="p-4 border-b border-gray-700">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-blue-400" />
            <span className="font-bold text-lg">NAC Console</span>
          </div>
          <p className="text-gray-400 text-xs mt-1">Network Access Control</p>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {nav.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors',
                  isActive
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white',
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="p-3 border-t border-gray-700">
          <button
            onClick={handleLogout}
            className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm text-gray-300 hover:bg-gray-800 hover:text-white transition-colors"
          >
            <LogOut className="h-4 w-4" />
            로그아웃
          </button>
        </div>
      </aside>

      {/* 메인 콘텐츠 */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}
