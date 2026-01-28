import { useState } from 'react';
import { Search, Filter, Download, AlertCircle, Info, AlertTriangle, Bug } from 'lucide-react';
import { mockLogs, type LogEntry } from '@/app/lib/mockData';

const levelColors = {
  info: 'bg-blue-100 text-blue-700',
  warn: 'bg-yellow-100 text-yellow-700',
  error: 'bg-red-100 text-red-700',
  debug: 'bg-gray-100 text-gray-700',
};

const levelIcons = {
  info: Info,
  warn: AlertTriangle,
  error: AlertCircle,
  debug: Bug,
};

export default function Logs() {
  const [filter, setFilter] = useState('');
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [logs, setLogs] = useState<LogEntry[]>(mockLogs);

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      log.message.toLowerCase().includes(filter.toLowerCase()) ||
      log.source.toLowerCase().includes(filter.toLowerCase()) ||
      (log.traceId && log.traceId.includes(filter));
    const matchesLevel = levelFilter === 'all' || log.level === levelFilter;
    return matchesSearch && matchesLevel;
  });

  const exportLogs = () => {
    alert('导出日志...\n\n日志已保存到本地文件。');
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">日志</h1>
        <p className="text-gray-600 mt-2">查看系统运行日志和 Trace</p>
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
              placeholder="搜索日志内容、来源或 Trace ID..."
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">全部级别</option>
            <option value="info">Info</option>
            <option value="warn">Warn</option>
            <option value="error">Error</option>
            <option value="debug">Debug</option>
          </select>
          <button
            onClick={exportLogs}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            导出
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Info className="w-5 h-5 text-blue-600" />
            <span className="text-sm font-medium text-blue-900">Info</span>
          </div>
          <p className="text-2xl font-semibold text-blue-900">
            {logs.filter((l) => l.level === 'info').length}
          </p>
        </div>
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-5 h-5 text-yellow-600" />
            <span className="text-sm font-medium text-yellow-900">Warn</span>
          </div>
          <p className="text-2xl font-semibold text-yellow-900">
            {logs.filter((l) => l.level === 'warn').length}
          </p>
        </div>
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle className="w-5 h-5 text-red-600" />
            <span className="text-sm font-medium text-red-900">Error</span>
          </div>
          <p className="text-2xl font-semibold text-red-900">
            {logs.filter((l) => l.level === 'error').length}
          </p>
        </div>
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Bug className="w-5 h-5 text-gray-600" />
            <span className="text-sm font-medium text-gray-900">Debug</span>
          </div>
          <p className="text-2xl font-semibold text-gray-900">
            {logs.filter((l) => l.level === 'debug').length}
          </p>
        </div>
      </div>

      {/* Logs list */}
      <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">时间</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">级别</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">来源</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">消息</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Trace ID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredLogs.map((log) => {
                const Icon = levelIcons[log.level];
                return (
                  <tr key={log.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm text-gray-600 font-mono whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`flex items-center gap-2 px-2 py-1 rounded text-xs font-medium ${levelColors[log.level]}`}>
                        <Icon className="w-3 h-3" />
                        {log.level.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-700 font-mono">{log.source}</td>
                    <td className="px-6 py-4 text-sm text-gray-900">{log.message}</td>
                    <td className="px-6 py-4">
                      {log.traceId ? (
                        <button className="text-blue-600 hover:text-blue-700 text-sm font-mono">
                          {log.traceId}
                        </button>
                      ) : (
                        <span className="text-sm text-gray-400">-</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {filteredLogs.length === 0 && (
        <div className="text-center py-12 text-gray-500">没有匹配的日志</div>
      )}
    </div>
  );
}
