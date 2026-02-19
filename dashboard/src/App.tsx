import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Layout from './components/Layout'
import Login from './views/Login'
import Overview from './views/Overview'
import KillSwitch from './views/KillSwitch'
import Integrity from './views/Integrity'

function ProtectedRoutes() {
  const { isAuthenticated } = useAuth()
  if (!isAuthenticated) return <Login />
  return (
    <Routes>
      <Route path="/dashboard" element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="killswitch" element={<KillSwitch />} />
        <Route path="integrity" element={<Integrity />} />
        <Route path="*" element={<Navigate to="/dashboard/" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard/" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <ProtectedRoutes />
      </BrowserRouter>
    </AuthProvider>
  )
}
