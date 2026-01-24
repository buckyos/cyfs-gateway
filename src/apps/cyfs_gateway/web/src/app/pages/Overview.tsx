import { Activity, Users, Link as LinkIcon, Shield, AlertCircle, CheckCircle } from 'lucide-react';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { mockTrafficData, mockDeviceTraffic, mockTunnelTraffic, mockActionStats, formatBytes } from '@/app/lib/mockData';

const StatCard = ({ title, value, subtitle, icon: Icon, trend }: any) => (
  <div className="bg-white rounded-lg border border-gray-200 p-6">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm text-gray-600">{title}</p>
        <p className="text-2xl font-semibold text-gray-900 mt-1">{value}</p>
        {subtitle && <p className="text-sm text-gray-500 mt-1">{subtitle}</p>}
      </div>
      <div className="p-3 bg-blue-50 rounded-lg">
        <Icon className="w-6 h-6 text-blue-600" />
      </div>
    </div>
    {trend && (
      <div className="mt-4 flex items-center text-sm">
        <span className={`font-medium ${trend > 0 ? 'text-green-600' : 'text-red-600'}`}>
          {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
        </span>
        <span className="text-gray-600 ml-2">vs 上一小时</span>
      </div>
    )}
  </div>
);

const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444'];

export default function Overview() {
  const totalTraffic = mockTrafficData.reduce((sum, d) => sum + d.upload + d.download, 0);
  const activeConnections = 45;
  const activeTunnels = 2;
  const tlsInterceptionEnabled = true;

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">概览</h1>
        <p className="text-gray-600 mt-2">网关工作状态总览</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard
          title="总流量"
          value={formatBytes(totalTraffic * 1024 * 1024)}
          subtitle="过去 200 秒"
          icon={Activity}
        />
        <StatCard
          title="活跃连接"
          value={activeConnections}
          subtitle="当前连接数"
          icon={Users}
          trend={12}
        />
        <StatCard
          title="启用链路"
          value={activeTunnels}
          subtitle={`${activeTunnels}/3 个链路`}
          icon={LinkIcon}
        />
        <StatCard
          title="TLS 拦截"
          value={tlsInterceptionEnabled ? '已启用' : '已关闭'}
          subtitle="2 个设备"
          icon={Shield}
        />
      </div>

      {/* System Health */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-8">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">系统健康</h2>
        <div className="space-y-4">
          <div className="flex items-center justify-between py-3 border-b border-gray-100">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-5 h-5 text-green-600" />
              <div>
                <p className="font-medium text-gray-900">网关运行状态</p>
                <p className="text-sm text-gray-600">正常运行</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">运行时间 3 天 5 小时</span>
          </div>

          <div className="flex items-center justify-between py-3 border-b border-gray-100">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-5 h-5 text-green-600" />
              <div>
                <p className="font-medium text-gray-900">配置状态</p>
                <p className="text-sm text-gray-600">最近一次生效</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">5 分钟前</span>
          </div>

          <div className="flex items-center justify-between py-3 border-b border-gray-100">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-5 h-5 text-green-600" />
              <div>
                <p className="font-medium text-gray-900">远程配置同步</p>
                <p className="text-sm text-gray-600">自动更新已启用</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">最近检查: 10 分钟前</span>
          </div>

          <div className="flex items-center justify-between py-3">
            <div className="flex items-center gap-3">
              <AlertCircle className="w-5 h-5 text-blue-600" />
              <div>
                <p className="font-medium text-gray-900">TLS 拦截</p>
                <p className="text-sm text-gray-600">{tlsInterceptionEnabled ? '已启用' : '已关闭'}</p>
              </div>
            </div>
            <span className="text-sm text-gray-500">覆盖 2 个设备</span>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Traffic Chart */}
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">流量趋势</h2>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={mockTrafficData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
              <XAxis dataKey="time" stroke="#6B7280" />
              <YAxis stroke="#6B7280" />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="download" stroke="#3B82F6" strokeWidth={2} name="下载 (KB/s)" />
              <Line type="monotone" dataKey="upload" stroke="#10B981" strokeWidth={2} name="上传 (KB/s)" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Device Traffic */}
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">设备流量分布</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={mockDeviceTraffic}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {mockDeviceTraffic.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Tunnel Traffic */}
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">链路流量分布</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={mockTunnelTraffic}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {mockTunnelTraffic.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Action Stats */}
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">动作统计</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={mockActionStats}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {mockActionStats.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
