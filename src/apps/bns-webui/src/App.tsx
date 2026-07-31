import { Navigate, Route, Routes } from 'react-router-dom'

import { AppShell } from './shell'
import { AppStateProvider } from './state'
import { HomePage } from './pages/Home'
import { NameDetailPage } from './pages/NameDetail'
import {
  NamesPage,
  RegisterPage,
  SearchPage,
} from './pages/RegistryPages'
import {
  AdvancedPage,
  EventsPage,
  SettingsPage,
  TransactionsPage,
} from './pages/OperationsPages'

export default function App() {
  return (
    <AppStateProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<HomePage />} />
          <Route path="search" element={<SearchPage />} />
          <Route path="names" element={<NamesPage />} />
          <Route path="register" element={<RegisterPage />} />
          <Route path="name/:name" element={<NameDetailPage />} />
          <Route path="transactions" element={<TransactionsPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="advanced" element={<AdvancedPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate replace to="/" />} />
        </Route>
      </Routes>
    </AppStateProvider>
  )
}
