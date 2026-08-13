/**
 * 路由：PRD 7.2 的一级导航 + 名称详情页。
 */

import { BrowserRouter, Route, Routes } from 'react-router-dom'

import { AccountProvider } from './ui/account'
import { Shell } from './ui/shell'
import { AccountPage } from './pages/AccountPage'
import { AcquiredPage } from './pages/AcquiredPage'
import { AdvancedPage } from './pages/AdvancedPage'
import { EventsPage } from './pages/EventsPage'
import { HomePage } from './pages/HomePage'
import { NameDetailPage } from './pages/NameDetailPage'
import { RegisterPage } from './pages/RegisterPage'
import { SearchPage } from './pages/SearchPage'
import { SecurityPage } from './pages/SecurityPage'
import { SettingsPage } from './pages/SettingsPage'
import { TxCenterPage } from './pages/TxCenterPage'

export function App({ demoMode }: { demoMode: boolean }) {
  return (
    <BrowserRouter>
      <AccountProvider>
        <Shell demoMode={demoMode}>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/search" element={<SearchPage />} />
            <Route path="/name/:name" element={<NameDetailPage />} />
            <Route path="/account" element={<AccountPage />} />
            <Route path="/acquired" element={<AcquiredPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/tx" element={<TxCenterPage />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/advanced" element={<AdvancedPage demoMode={demoMode} />} />
            <Route path="/settings" element={<SettingsPage demoMode={demoMode} />} />
            <Route path="*" element={<HomePage />} />
          </Routes>
        </Shell>
      </AccountProvider>
    </BrowserRouter>
  )
}
