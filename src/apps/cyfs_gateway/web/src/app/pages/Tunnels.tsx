import { useState } from 'react';
import { Plus, Power, Activity, Gauge, HardDrive, Globe, TestTube } from 'lucide-react';
import { mockTunnels, formatBytes, type Tunnel } from '@/app/lib/mockData';

export default function Tunnels() {
  const [tunnels, setTunnels] = useState(mockTunnels);
  const [showAddDialog, setShowAddDialog] = useState(false);

  const toggleTunnel = (id: string) => {
    setTunnels((prev) =>
      prev.map((t) => (t.id === id ? { ...t, enabled: !t.enabled } : t))
    );
  };

  const runTest = (id: string) => {
    alert(`运行链路测试: ${id}\n\n正在测试连通性...\n\n此功能将跳转到日志页面并显示 trace-id`);
  };

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">链路（Tunnel）</h1>
          <p className="text-gray-600 mt-2">管理所有可用的 Tunnel 资源</p>
        </div>
        <button
          onClick={() => setShowAddDialog(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-5 h-5" />
          新增链路
        </button>
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">总链路数</p>
          <p className="text-2xl font-semibold text-gray-900 mt-1">{tunnels.length}</p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">启用链路</p>
          <p className="text-2xl font-semibold text-green-600 mt-1">
            {tunnels.filter((t) => t.enabled).length}
          </p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">活跃连接</p>
          <p className="text-2xl font-semibold text-blue-600 mt-1">
            {tunnels.filter((t) => t.status === 'active').length}
          </p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">总数据用量</p>
          <p className="text-2xl font-semibold text-gray-900 mt-1">
            {formatBytes(tunnels.reduce((sum, t) => sum + t.dataUsage, 0))}
          </p>
        </div>
      </div>

      {/* Tunnels grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {tunnels.map((tunnel) => (
          <div key={tunnel.id} className="bg-white rounded-lg border border-gray-200 p-6">
            {/* Header */}
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">{tunnel.name}</h3>
                <p className="text-sm text-gray-600 mt-1">
                  {tunnel.schema} - {tunnel.endpoint}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => toggleTunnel(tunnel.id)}
                  className={`p-2 rounded-lg transition-colors ${
                    tunnel.enabled
                      ? 'bg-green-100 text-green-700 hover:bg-green-200'
                      : 'bg-gray-100 text-gray-400 hover:bg-gray-200'
                  }`}
                  title={tunnel.enabled ? '点击禁用' : '点击启用'}
                >
                  <Power className="w-5 h-5" />
                </button>
                <div
                  className={`px-3 py-1 rounded-full text-xs font-medium ${
                    tunnel.status === 'active'
                      ? 'bg-green-100 text-green-700'
                      : tunnel.status === 'idle'
                      ? 'bg-gray-100 text-gray-600'
                      : 'bg-red-100 text-red-700'
                  }`}
                >
                  {tunnel.status === 'active'
                    ? '活跃'
                    : tunnel.status === 'idle'
                    ? '空闲'
                    : '错误'}
                </div>
              </div>
            </div>

            {/* Metrics grid */}
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                <Activity className="w-5 h-5 text-gray-600" />
                <div>
                  <p className="text-xs text-gray-600">延迟</p>
                  <p className="text-sm font-semibold text-gray-900">{tunnel.latency} ms</p>
                </div>
              </div>

              <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                <Gauge className="w-5 h-5 text-gray-600" />
                <div>
                  <p className="text-xs text-gray-600">带宽</p>
                  <p className="text-sm font-semibold text-gray-900">{tunnel.bandwidth} Mbps</p>
                </div>
              </div>

              <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                <Activity className="w-5 h-5 text-gray-600" />
                <div>
                  <p className="text-xs text-gray-600">当前吞吐</p>
                  <p className="text-sm font-semibold text-gray-900">{tunnel.throughput} MB/s</p>
                </div>
              </div>

              <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                <HardDrive className="w-5 h-5 text-gray-600" />
                <div>
                  <p className="text-xs text-gray-600">数据用量</p>
                  <p className="text-sm font-semibold text-gray-900">
                    {formatBytes(tunnel.dataUsage)}
                  </p>
                </div>
              </div>
            </div>

            {/* Exit IP */}
            <div className="flex items-center gap-2 mb-4 p-3 bg-blue-50 rounded-lg">
              <Globe className="w-5 h-5 text-blue-600" />
              <div>
                <p className="text-xs text-blue-600">出口 IP</p>
                <p className="text-sm font-semibold text-blue-900">{tunnel.exitIP}</p>
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-2">
              <button
                onClick={() => runTest(tunnel.id)}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                <TestTube className="w-4 h-4" />
                一键测试
              </button>
              <button className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
                查看详情
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Add tunnel dialog */}
      {showAddDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-2xl">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">新增链路</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  粘贴编码后的 JSON 配置
                </label>
                <textarea
                  className="w-full h-48 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                  placeholder='粘贴链路配置...'
                />
              </div>
              <p className="text-sm text-gray-600">
                在移动端可以扫描二维码导入配置。粘贴后系统会自动解析并展示预览。
              </p>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setShowAddDialog(false)}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                取消
              </button>
              <button className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                解析并保存
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
