import { useState } from 'react';
import { Eye, Edit3, Check, RotateCcw, Download, Upload, RefreshCw } from 'lucide-react';

export default function Configuration() {
  const [mode, setMode] = useState<'view' | 'edit'>('view');
  const [configText, setConfigText] = useState(
    JSON.stringify(
      {
        version: '1.0',
        includes: ['config/base.json', 'config/tunnels.json', 'config/post_gateway.json'],
        stack: {
          bind: '0.0.0.0:1080',
          protocol: 'socks5',
        },
        tunnels: ['tunnel1', 'tunnel2'],
        process_chain: {
          hooks: ['pre_route', 'post_route'],
        },
      },
      null,
      2
    )
  );

  const viewMergedConfig = () => {
    alert('查看合成后的完整配置（所有 include 展开 + params 替换）');
  };

  const applyConfig = () => {
    if (confirm('确认应用此配置？系统将进行校验后生效。')) {
      alert('配置校验通过！正在应用...\n\n配置已生效。');
      setMode('view');
    }
  };

  const rollback = () => {
    if (confirm('确认回滚到上一版本？')) {
      alert('已回滚到上一版本配置');
    }
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">配置管理</h1>
        <p className="text-gray-600 mt-2">查看、编辑和管理 Gateway 配置</p>
      </div>

      {/* Actions */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMode('view')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                mode === 'view'
                  ? 'bg-blue-100 text-blue-700'
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              <Eye className="w-4 h-4" />
              查看模式
            </button>
            <button
              onClick={() => setMode('edit')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                mode === 'edit'
                  ? 'bg-blue-100 text-blue-700'
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              <Edit3 className="w-4 h-4" />
              编辑模式
            </button>
            <button
              onClick={viewMergedConfig}
              className="flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-600 rounded-lg hover:bg-gray-200 transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              查看合成配置
            </button>
          </div>
          <div className="flex items-center gap-3">
            <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
              <Download className="w-4 h-4" />
              导出
            </button>
            <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
              <Upload className="w-4 h-4" />
              导入
            </button>
            <button
              onClick={rollback}
              className="flex items-center gap-2 px-4 py-2 border border-red-300 text-red-600 rounded-lg hover:bg-red-50 transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              回滚
            </button>
          </div>
        </div>
      </div>

      {/* Config editor */}
      <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <div className="bg-gray-50 border-b border-gray-200 px-6 py-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-900">配置内容</h2>
          {mode === 'edit' && (
            <button
              onClick={applyConfig}
              className="flex items-center gap-2 px-4 py-1.5 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors"
            >
              <Check className="w-4 h-4" />
              应用配置
            </button>
          )}
        </div>
        <div className="p-6">
          <textarea
            value={configText}
            onChange={(e) => setConfigText(e.target.value)}
            disabled={mode === 'view'}
            className="w-full h-[600px] px-4 py-3 border border-gray-300 rounded-lg font-mono text-sm bg-gray-900 text-green-400 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-800 disabled:cursor-not-allowed"
          />
        </div>
      </div>

      {/* Remote include status */}
      <div className="mt-6 bg-white rounded-lg border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">远程配置同步状态</h2>
        <div className="space-y-3">
          <div className="flex items-center justify-between py-3 border-b border-gray-100">
            <div>
              <p className="font-medium text-gray-900">config/base.json</p>
              <p className="text-sm text-gray-600">https://example.com/config/base.json</p>
            </div>
            <div className="text-right">
              <p className="text-sm text-green-600">自动更新已启用</p>
              <p className="text-xs text-gray-500">最近检查: 10 分钟前</p>
            </div>
          </div>
          <div className="flex items-center justify-between py-3 border-b border-gray-100">
            <div>
              <p className="font-medium text-gray-900">config/tunnels.json</p>
              <p className="text-sm text-gray-600">https://example.com/config/tunnels.json</p>
            </div>
            <div className="text-right">
              <p className="text-sm text-green-600">自动更新已启用</p>
              <p className="text-xs text-gray-500">最近检查: 10 分钟前</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
