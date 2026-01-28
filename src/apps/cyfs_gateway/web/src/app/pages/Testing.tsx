import { useState } from 'react';
import { Play, CheckCircle, XCircle, Clock } from 'lucide-react';

const testWebsites = [
  { name: 'Google', url: 'https://www.google.com', category: '搜索引擎' },
  { name: 'YouTube', url: 'https://www.youtube.com', category: '视频' },
  { name: 'Netflix', url: 'https://www.netflix.com', category: '流媒体' },
  { name: 'Baidu', url: 'https://www.baidu.com', category: '搜索引擎' },
  { name: 'GitHub', url: 'https://github.com', category: '开发' },
  { name: 'Twitter', url: 'https://twitter.com', category: '社交' },
];

export default function Testing() {
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<any[]>([]);

  const runTests = async () => {
    setRunning(true);
    setResults([]);

    // 模拟测试过程
    for (const site of testWebsites) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      setResults((prev) => [
        ...prev,
        {
          name: site.name,
          url: site.url,
          status: Math.random() > 0.2 ? 'success' : 'failed',
          exitIP: '203.0.113.1',
          latency: Math.floor(Math.random() * 200) + 50,
          traceId: `trace-${Date.now()}`,
        },
      ]);
    }

    setRunning(false);
    alert('测试完成！结果以日志/trace 为主，可在开发者面板中查看详细信息。');
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">测试</h1>
        <p className="text-gray-600 mt-2">一键测试大网站连通性与出口 IP</p>
      </div>

      {/* Test button */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">预置网站测试</h2>
            <p className="text-sm text-gray-600 mt-1">
              测试 {testWebsites.length} 个常用网站的连通性
            </p>
          </div>
          <button
            onClick={runTests}
            disabled={running}
            className="flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:bg-gray-400"
          >
            <Play className="w-5 h-5" />
            {running ? '测试中...' : '开始测试'}
          </button>
        </div>
      </div>

      {/* Test websites */}
      <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">网站</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">分类</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">URL</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">状态</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">出口 IP</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">延迟</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Trace ID</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {testWebsites.map((site, index) => {
              const result = results.find((r) => r.name === site.name);
              return (
                <tr key={index} className="hover:bg-gray-50">
                  <td className="px-6 py-4 font-medium text-gray-900">{site.name}</td>
                  <td className="px-6 py-4 text-sm text-gray-600">{site.category}</td>
                  <td className="px-6 py-4 text-sm text-gray-600">{site.url}</td>
                  <td className="px-6 py-4">
                    {result ? (
                      <div className="flex items-center gap-2">
                        {result.status === 'success' ? (
                          <>
                            <CheckCircle className="w-5 h-5 text-green-600" />
                            <span className="text-sm text-green-600">成功</span>
                          </>
                        ) : (
                          <>
                            <XCircle className="w-5 h-5 text-red-600" />
                            <span className="text-sm text-red-600">失败</span>
                          </>
                        )}
                      </div>
                    ) : running && index <= results.length ? (
                      <div className="flex items-center gap-2">
                        <Clock className="w-5 h-5 text-blue-600 animate-spin" />
                        <span className="text-sm text-blue-600">测试中</span>
                      </div>
                    ) : (
                      <span className="text-sm text-gray-400">等待测试</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 font-mono">
                    {result ? result.exitIP : '-'}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">
                    {result ? `${result.latency} ms` : '-'}
                  </td>
                  <td className="px-6 py-4">
                    {result ? (
                      <button className="text-blue-600 hover:text-blue-700 text-sm font-mono">
                        {result.traceId}
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

      {results.length > 0 && (
        <div className="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-sm text-blue-900">
            💡 测试结果以日志/trace 为主。点击 Trace ID 可在开发者面板查看详细日志。
          </p>
        </div>
      )}
    </div>
  );
}
