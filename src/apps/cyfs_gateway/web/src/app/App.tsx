import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from '@/app/components/Layout';
import Overview from '@/app/pages/Overview';
import Devices from '@/app/pages/Devices';
import Tunnels from '@/app/pages/Tunnels';
import Rules from '@/app/pages/Rules';
import Databases from '@/app/pages/Databases';
import Testing from '@/app/pages/Testing';
import Configuration from '@/app/pages/Configuration';
import TLSInterception from '@/app/pages/TLSInterception';
import Settings from '@/app/pages/Settings';
import Logs from '@/app/pages/developer/Logs';
import Connections from '@/app/pages/developer/Connections';
import ObjectTree from '@/app/pages/developer/ObjectTree';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview" element={<Overview />} />
          <Route path="devices" element={<Devices />} />
          <Route path="tunnels" element={<Tunnels />} />
          <Route path="rules" element={<Rules />} />
          <Route path="databases" element={<Databases />} />
          <Route path="testing" element={<Testing />} />
          <Route path="configuration" element={<Configuration />} />
          <Route path="tls-interception" element={<TLSInterception />} />
          <Route path="settings" element={<Settings />} />
          <Route path="developer/logs" element={<Logs />} />
          <Route path="developer/connections" element={<Connections />} />
          <Route path="developer/object-tree" element={<ObjectTree />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
