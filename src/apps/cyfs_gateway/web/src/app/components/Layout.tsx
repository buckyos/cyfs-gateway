import { Outlet, NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Smartphone, 
  Link as LinkIcon, 
  FileCode, 
  Database, 
  TestTube, 
  Settings as SettingsIcon,
  Shield,
  FolderOpen,
  ScrollText,
  Network,
  GitBranch
} from 'lucide-react';

const navItems = [
  { path: '/overview', label: '概览', icon: LayoutDashboard },
  { path: '/devices', label: '设备', icon: Smartphone },
  { path: '/tunnels', label: '链路', icon: LinkIcon },
  { path: '/rules', label: '规则', icon: FileCode },
  { path: '/databases', label: '数据库', icon: Database },
  { path: '/testing', label: '测试', icon: TestTube },
  { path: '/configuration', label: '配置', icon: FolderOpen },
  { path: '/tls-interception', label: 'TLS 拦截', icon: Shield },
  { path: '/settings', label: '系统设置', icon: SettingsIcon },
];

const developerItems = [
  { path: '/developer/logs', label: '日志', icon: ScrollText },
  { path: '/developer/connections', label: '连接', icon: Network },
  { path: '/developer/object-tree', label: '对象树', icon: GitBranch },
];

export default function Layout() {
  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-gray-200 overflow-y-auto">
        <div className="p-6">
          <h1 className="text-xl font-semibold text-gray-900">CYFS Gateway</h1>
          <p className="text-sm text-gray-500 mt-1">Dashboard</p>
        </div>
        
        <nav className="px-4 pb-4">
          <div className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm transition-colors ${
                      isActive
                        ? 'bg-blue-50 text-blue-700 font-medium'
                        : 'text-gray-700 hover:bg-gray-100'
                    }`
                  }
                >
                  <Icon className="w-5 h-5" />
                  {item.label}
                </NavLink>
              );
            })}
          </div>
          
          <div className="mt-8">
            <p className="px-4 mb-2 text-xs font-semibold text-gray-500 uppercase tracking-wide">
              开发者面板
            </p>
            <div className="space-y-1">
              {developerItems.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm transition-colors ${
                        isActive
                          ? 'bg-blue-50 text-blue-700 font-medium'
                          : 'text-gray-700 hover:bg-gray-100'
                      }`
                    }
                  >
                    <Icon className="w-5 h-5" />
                    {item.label}
                  </NavLink>
                );
              })}
            </div>
          </div>
        </nav>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
