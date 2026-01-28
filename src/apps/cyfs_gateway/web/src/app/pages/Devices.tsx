import { useState } from 'react';
import { Search, Smartphone, Laptop, Tablet, Circle, Shield } from 'lucide-react';
import { mockDevices, formatBytes, type Device } from '@/app/lib/mockData';

const DeviceIcon = ({ type }: { type: string }) => {
  switch (type) {
    case 'smartphone':
      return <Smartphone className="w-5 h-5" />;
    case 'laptop':
      return <Laptop className="w-5 h-5" />;
    case 'tablet':
      return <Tablet className="w-5 h-5" />;
    default:
      return <Circle className="w-5 h-5" />;
  }
};

export default function Devices() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedDevices, setSelectedDevices] = useState<Set<string>>(new Set());

  const filteredDevices = mockDevices.filter(
    (device) =>
      device.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      device.ip.includes(searchTerm)
  );

  const toggleDevice = (id: string) => {
    const newSelected = new Set(selectedDevices);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedDevices(newSelected);
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">设备</h1>
        <p className="text-gray-600 mt-2">管理网络中的所有设备</p>
      </div>

      {/* Search and filters */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
        <div className="flex items-center gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="搜索设备名称或 IP 地址..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
            TLS 拦截设置
          </button>
        </div>
      </div>

      {/* Selected devices info */}
      {selectedDevices.size > 0 && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
          <p className="text-blue-900">
            已选择 {selectedDevices.size} 个设备
            <button
              onClick={() => setSelectedDevices(new Set())}
              className="ml-4 text-blue-700 hover:text-blue-900 underline"
            >
              清除选择
            </button>
          </p>
        </div>
      )}

      {/* Devices list */}
      <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="px-6 py-3 text-left">
                <input
                  type="checkbox"
                  checked={selectedDevices.size === filteredDevices.length && filteredDevices.length > 0}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setSelectedDevices(new Set(filteredDevices.map((d) => d.id)));
                    } else {
                      setSelectedDevices(new Set());
                    }
                  }}
                  className="rounded border-gray-300"
                />
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                设备
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                IP 地址
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                MAC 地址
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                状态
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                数据用量
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                TLS 拦截
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                操作
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {filteredDevices.map((device) => (
              <tr key={device.id} className="hover:bg-gray-50">
                <td className="px-6 py-4">
                  <input
                    type="checkbox"
                    checked={selectedDevices.has(device.id)}
                    onChange={() => toggleDevice(device.id)}
                    className="rounded border-gray-300"
                  />
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-gray-100 rounded-lg">
                      <DeviceIcon type={device.type} />
                    </div>
                    <div>
                      <p className="font-medium text-gray-900">{device.name}</p>
                      <p className="text-sm text-gray-500">{device.manufacturer}</p>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 text-sm text-gray-900">{device.ip}</td>
                <td className="px-6 py-4 text-sm text-gray-600 font-mono">{device.mac}</td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <div
                      className={`w-2 h-2 rounded-full ${
                        device.online ? 'bg-green-500' : 'bg-gray-300'
                      }`}
                    />
                    <span className="text-sm text-gray-900">
                      {device.online ? '在线' : '离线'}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">{device.lastSeen}</p>
                </td>
                <td className="px-6 py-4 text-sm text-gray-900">
                  {formatBytes(device.dataUsage)}
                </td>
                <td className="px-6 py-4">
                  {device.tlsEnabled ? (
                    <div className="flex items-center gap-2 text-blue-600">
                      <Shield className="w-4 h-4" />
                      <span className="text-sm">已启用</span>
                    </div>
                  ) : (
                    <span className="text-sm text-gray-400">未启用</span>
                  )}
                </td>
                <td className="px-6 py-4">
                  <button className="text-blue-600 hover:text-blue-700 text-sm font-medium">
                    查看详情
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filteredDevices.length === 0 && (
        <div className="text-center py-12 text-gray-500">
          没有找到匹配的设备
        </div>
      )}
    </div>
  );
}
