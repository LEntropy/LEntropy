import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Endpoints } from './pages/Endpoints'
import { NetworkManagement } from './pages/NetworkManagement'
import { Policies } from './pages/Policies'
import { Blacklist } from './pages/Blacklist'
import { UserManagement } from './pages/UserManagement'
import { AuditLog } from './pages/AuditLog'
import { Login } from './pages/Login'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('nac_token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route path="/" element={<Dashboard />} />
          <Route path="/endpoints" element={<Endpoints />} />
          <Route path="/network" element={<NetworkManagement />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/blacklist" element={<Blacklist />} />
          <Route path="/users" element={<UserManagement />} />
          <Route path="/audit" element={<AuditLog />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
