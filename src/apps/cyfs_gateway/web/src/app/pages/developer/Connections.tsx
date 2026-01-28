import { useState } from 'react';
import { Search, Filter, Activity, Clock } from 'lucide-react';
import { mockConnections, formatBytes, formatDuration, type Connection } from '@/app/lib/mockData';

export default function Connections() {
  const [filter, setFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const filteredConnections = mockConnections.filter((conn) => {
    const matchesSearch =
      conn.deviceIP.includes(filter) ||
      conn.host.toLowerCase().includes(filter.toLowerCase()) ||
      conn.tunnelId.includes(filter);
    const matchesStatus = statusFilter === 'all' || conn.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const activeConnections = mockConnections.filter((c) => c.status === 'active').length;
  const totalBytesIn = mockConnections.reduce((sum, c) => sum + c.bytesIn, 0);
  const totalBytesOut = mockConnections.reduce((sum, c) => sum + c.bytesOut, 0);

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">连接</h1>
        <p className="text-gray-600 mt-2">查看 Tunnel 和 Stream 连接状态</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">活跃连接</p>
          <p className="text-2xl font-semibold text-green-600 mt-1">{activeConnections}</p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">总下载流量</p>
          <p className="text-2xl font-semibold text-blue-600 mt-1">{formatBytes(totalBytesIn)}</p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">总上传流量</p>
          <p className="text-2xl font-semibold text-blue-600 mt-1">{formatBytes(totalBytesOut)}</p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
        <div className="flex items-center gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="搜索 IP、域名或 Tunnel ID..."
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">全部状态</option>
            <option value="active">活跃</option>
            <option value="closed">已关闭</option>
          </select>
        </div>
      </div>

      {/* Connections table */}
      <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tunnel ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">设备 IP</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">协议</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">目标主机</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">状态</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">下载</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">上传</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">持续时间</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredConnections.map((conn) => (
                <tr key={conn.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-sm font-mono text-gray-900">{conn.tunnelId}</td>
                  <td className="px-6 py-4 text-sm font-mono text-gray-900">{conn.deviceIP}</td>
                  <td className="px-6 py-4">
                    <span className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded font-mono">
                      {conn.protocol.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900">{conn.host}</td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      {conn.status === 'active' ? (
                        <>
                          <Activity className="w-4 h-4 text-green-600" />
                          <span className="text-sm text-green-600">活跃</span>
                        </>
                      ) : (
                        <>
                          <Clock className="w-4 h-4 text-gray-400" />
                          <span className="text-sm text-gray-400">已关闭</span>
                        </>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900">{formatBytes(conn.bytesIn)}</td>
                  <td className="px-6 py-4 text-sm text-gray-900">{formatBytes(conn.bytesOut)}</td>
                  <td className="px-6 py-4 text-sm text-gray-600">{formatDuration(conn.duration)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {filteredConnections.length === 0 && (
        <div className="text-center py-12 text-gray-500">没有匹配的连接</div>
      )}
    </div>
  );
}
