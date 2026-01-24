import { useState } from 'react';
import { Info, Globe, Palette, Shield, Key, Plus, Trash2 } from 'lucide-react';

export default function Settings() {
  const [tokens, setTokens] = useState([
    { id: '1', name: '运维 Token', token: 'cyfs_***************abc', created: '2024-01-15' },
    { id: '2', name: '测试 Token', token: 'cyfs_***************xyz', created: '2024-01-20' },
  ]);

  const addToken = () => {
    const name = prompt('输入 Token 名称：');
    if (name) {
      const newToken = {
        id: Date.now().toString(),
        name,
        token: `cyfs_${Math.random().toString(36).substr(2, 20)}`,
        created: new Date().toISOString().split('T')[0],
      };
      setTokens([...tokens, newToken]);
      alert(`Token 已创建：\n\n${newToken.token}\n\n请妥善保管，此 Token 仅显示一次。`);
    }
  };

  const deleteToken = (id: string) => {
    if (confirm('确认撤销此 Token？此操作不可恢复。')) {
      setTokens(tokens.filter((t) => t.id !== id));
    }
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">系统设置</h1>
        <p className="text-gray-600 mt-2">配置系统基本参数和安全选项</p>
      </div>

      {/* System Info */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Info className="w-5 h-5" />
          系统信息
        </h2>
        <div className="grid grid-cols-2 gap-4">
          <div className="p-4 bg-gray-50 rounded-lg">
            <p className="text-sm text-gray-600">版本号</p>
            <p className="text-lg font-semibold text-gray-900 mt-1">v1.0.0</p>
          </div>
          <div className="p-4 bg-gray-50 rounded-lg">
            <p className="text-sm text-gray-600">运行时间</p>
            <p className="text-lg font-semibold text-gray-900 mt-1">3 天 5 小时</p>
          </div>
          <div className="p-4 bg-gray-50 rounded-lg">
            <p className="text-sm text-gray-600">Dashboard 端口</p>
            <p className="text-lg font-semibold text-gray-900 mt-1">8080</p>
          </div>
          <div className="p-4 bg-gray-50 rounded-lg">
            <p className="text-sm text-gray-600">访问地址</p>
            <p className="text-sm font-mono text-gray-900 mt-1">http://192.168.1.1:8080</p>
          </div>
        </div>
      </div>

      {/* Language and Theme */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Globe className="w-5 h-5" />
          界面设置
        </h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">语言</label>
            <select className="w-full max-w-xs px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
              <option value="zh-CN">简体中文</option>
              <option value="en-US">English</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">主题</label>
            <select className="w-full max-w-xs px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
              <option value="light">浅色</option>
              <option value="dark">深色</option>
              <option value="auto">跟随系统</option>
            </select>
          </div>
        </div>
      </div>

      {/* UI Mode */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Palette className="w-5 h-5" />
          UI 模式
        </h2>
        <div className="space-y-3">
          <label className="flex items-center gap-3 p-4 border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50">
            <input type="radio" name="mode" value="router" defaultChecked className="w-4 h-4" />
            <div>
              <p className="font-medium text-gray-900">Router Mode（路由模式）</p>
              <p className="text-sm text-gray-600">面向家庭用户，简化界面</p>
            </div>
          </label>
          <label className="flex items-center gap-3 p-4 border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50">
            <input type="radio" name="mode" value="ops" className="w-4 h-4" />
            <div>
              <p className="font-medium text-gray-900">Ops Mode（运维模式）</p>
              <p className="text-sm text-gray-600">显示更多监控指标和对象详情</p>
            </div>
          </label>
          <label className="flex items-center gap-3 p-4 border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50">
            <input type="radio" name="mode" value="developer" className="w-4 h-4" />
            <div>
              <p className="font-medium text-gray-900">Developer Mode（开发者模式）</p>
              <p className="text-sm text-gray-600">完整的调试功能和日志面板</p>
            </div>
          </label>
        </div>
      </div>

      {/* Security */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5" />
          安全设置
        </h2>
        <div className="space-y-4">
          <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
            <p className="text-sm text-green-900">
              ✓ 127.0.0.1 访问已启用免授权
            </p>
          </div>
          <div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" className="w-4 h-4" />
              <span className="text-sm text-gray-900">要求远程访问使用 HTTPS</span>
            </label>
          </div>
          <div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" className="w-4 h-4" />
              <span className="text-sm text-gray-900">启用登录密码保护</span>
            </label>
          </div>
        </div>
      </div>

      {/* API Tokens */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
            <Key className="w-5 h-5" />
            API Tokens
          </h2>
          <button
            onClick={addToken}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            新建 Token
          </button>
        </div>
        <div className="space-y-3">
          {tokens.map((token) => (
            <div
              key={token.id}
              className="flex items-center justify-between p-4 border border-gray-200 rounded-lg"
            >
              <div>
                <p className="font-medium text-gray-900">{token.name}</p>
                <p className="text-sm font-mono text-gray-600 mt-1">{token.token}</p>
                <p className="text-xs text-gray-500 mt-1">创建于: {token.created}</p>
              </div>
              <button
                onClick={() => deleteToken(token.id)}
                className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
