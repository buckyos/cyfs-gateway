import { useState } from 'react';
import { Shield, AlertTriangle, Download, RefreshCw, Power, Users } from 'lucide-react';
import { mockDevices } from '@/app/lib/mockData';

export default function TLSInterception() {
  const [enabled, setEnabled] = useState(false);
  const [scope, setScope] = useState<'selected' | 'all'>('selected');
  const [selectedDevices, setSelectedDevices] = useState<Set<string>>(new Set(['1', '4']));

  const toggleTLS = () => {
    if (!enabled) {
      if (
        confirm(
          '警告：TLS 拦截是高价值高风险功能！\n\n' +
            '启用后需要设备安装自定义根证书，可能造成兼容性/隐私/合规风险。\n\n' +
            '确认启用吗？'
        )
      ) {
        setEnabled(true);
      }
    } else {
      if (confirm('确认关闭 TLS 拦截功能？')) {
        setEnabled(false);
      }
    }
  };

  const generateCA = () => {
    alert('正在生成新的 CA 证书...\n\n证书已生成！请下载并安装到目标设备。');
  };

  const regenerateCA = () => {
    if (
      confirm(
        '警告：重新生成 CA 会导致已安装设备失效！\n\n所有设备需要重新安装新证书。\n\n确认重新生成吗？'
      )
    ) {
      alert('CA 证书已重新生成！请重新安装到所有设备。');
    }
  };

  const downloadCA = () => {
    alert('CA 证书下载已开始...');
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">TLS 拦截</h1>
        <p className="text-gray-600 mt-2">HTTPS 流量探测与分析</p>
      </div>

      {/* Warning banner */}
      <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
        <div className="flex gap-3">
          <AlertTriangle className="w-6 h-6 text-red-600 flex-shrink-0" />
          <div>
            <h3 className="font-semibold text-red-900 mb-1">高风险功能警告</h3>
            <p className="text-sm text-red-800">
              TLS 拦截需要设备安装自定义根证书，可能造成兼容性、隐私和合规风险。仅在完全理解其工作原理和风险的情况下使用。
            </p>
          </div>
        </div>
      </div>

      {/* Main toggle */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">TLS 拦截功能</h2>
            <p className="text-sm text-gray-600 mt-1">
              当前状态: {enabled ? '已启用' : '已关闭'}
            </p>
          </div>
          <button
            onClick={toggleTLS}
            className={`flex items-center gap-2 px-6 py-3 rounded-lg transition-colors ${
              enabled
                ? 'bg-red-600 text-white hover:bg-red-700'
                : 'bg-blue-600 text-white hover:bg-blue-700'
            }`}
          >
            <Power className="w-5 h-5" />
            {enabled ? '紧急关闭' : '启用功能'}
          </button>
        </div>
      </div>

      {enabled && (
        <>
          {/* CA Management */}
          <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5" />
              CA 证书管理
            </h2>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-600">证书指纹</p>
                  <p className="text-xs font-mono text-gray-900 mt-1">
                    A1:B2:C3:D4:E5:F6:A7:B8:C9:D0:E1:F2:A3:B4:C5:D6
                  </p>
                </div>
                <div className="p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-600">有效期</p>
                  <p className="text-sm font-semibold text-gray-900 mt-1">
                    2024-01-01 至 2025-01-01
                  </p>
                </div>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={generateCA}
                  className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
                >
                  <Shield className="w-4 h-4" />
                  生成 CA 证书
                </button>
                <button
                  onClick={downloadCA}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  下载 CA 证书
                </button>
                <button
                  onClick={regenerateCA}
                  className="flex items-center gap-2 px-4 py-2 border border-red-300 text-red-600 rounded-lg hover:bg-red-50 transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                  重新生成（危险）
                </button>
              </div>
            </div>
          </div>

          {/* Scope settings */}
          <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
              <Users className="w-5 h-5" />
              生效范围
            </h2>

            <div className="space-y-4">
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="scope"
                    checked={scope === 'selected'}
                    onChange={() => setScope('selected')}
                    className="w-4 h-4"
                  />
                  <span className="text-sm text-gray-900">仅对选中设备生效（推荐）</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="scope"
                    checked={scope === 'all'}
                    onChange={() => setScope('all')}
                    className="w-4 h-4"
                  />
                  <span className="text-sm text-gray-900">对全部设备生效</span>
                </label>
              </div>

              {scope === 'selected' && (
                <div className="mt-4">
                  <p className="text-sm font-medium text-gray-700 mb-3">
                    选中的设备 ({selectedDevices.size})
                  </p>
                  <div className="space-y-2">
                    {mockDevices.map((device) => (
                      <label
                        key={device.id}
                        className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50"
                      >
                        <input
                          type="checkbox"
                          checked={selectedDevices.has(device.id)}
                          onChange={(e) => {
                            const newSelected = new Set(selectedDevices);
                            if (e.target.checked) {
                              newSelected.add(device.id);
                            } else {
                              newSelected.delete(device.id);
                            }
                            setSelectedDevices(newSelected);
                          }}
                          className="w-4 h-4"
                        />
                        <div className="flex-1">
                          <p className="font-medium text-gray-900">{device.name}</p>
                          <p className="text-sm text-gray-600">{device.ip}</p>
                        </div>
                        {selectedDevices.has(device.id) && (
                          <span className="px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded">
                            已选中
                          </span>
                        )}
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Installation guide */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">安装指引</h2>
            <div className="space-y-3 text-sm text-gray-600">
              <p>请按照以下步骤在各平台安装 CA 证书：</p>
              <div className="pl-4 space-y-2">
                <p>• <strong>iOS/iPadOS:</strong> 下载证书 → 设置 → 通用 → VPN 与设备管理 → 安装描述文件</p>
                <p>• <strong>Android:</strong> 下载证书 → 设置 → 安全 → 加密与凭据 → 从存储设备安装</p>
                <p>• <strong>Windows:</strong> 下载证书 → 双击 → 安装证书 → 受信任的根证书颁发机构</p>
                <p>• <strong>macOS:</strong> 下载证书 → 钥匙串访问 → 系统 → 导入 → 设置为始终信任</p>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
