import { Database, Search, Plus } from 'lucide-react';

const databases = [
  { name: 'Hostname TagDB', type: '订阅库', entries: 15420, lastUpdate: '2 小时前', readonly: true },
  { name: 'IP TagDB', type: '订阅库', entries: 8920, lastUpdate: '2 小时前', readonly: true },
  { name: 'IP→Host DB', type: '混合库', entries: 45230, lastUpdate: '5 分钟前', readonly: false },
  { name: 'IP→GEO DB', type: '订阅库', entries: 125000, lastUpdate: '1 天前', readonly: true },
  { name: 'Custom Tags', type: '自定义库', entries: 125, lastUpdate: '1 小时前', readonly: false },
];

export default function Databases() {
  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">数据库</h1>
        <p className="text-gray-600 mt-2">管理 TagDB、IP 知识库和 GeoIP 数据库</p>
      </div>

      {/* Search */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
        <div className="flex items-center gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="查询 hostname、IP 或 tag..."
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
            查询
          </button>
        </div>
        <p className="text-sm text-gray-600 mt-2">
          💡 提示：查询操作仅在本地数据库中进行，不会执行在线反查
        </p>
      </div>

      {/* Databases list */}
      <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">数据库名称</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">类型</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">记录数</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">最后更新</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">权限</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {databases.map((db, index) => (
              <tr key={index} className="hover:bg-gray-50">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <Database className="w-5 h-5 text-gray-600" />
                    <span className="font-medium text-gray-900">{db.name}</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    db.type === '订阅库' ? 'bg-blue-100 text-blue-700' :
                    db.type === '自定义库' ? 'bg-green-100 text-green-700' :
                    'bg-gray-100 text-gray-700'
                  }`}>
                    {db.type}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-900">{db.entries.toLocaleString()}</td>
                <td className="px-6 py-4 text-sm text-gray-600">{db.lastUpdate}</td>
                <td className="px-6 py-4">
                  <span className={`text-sm ${db.readonly ? 'text-gray-500' : 'text-green-600'}`}>
                    {db.readonly ? '只读' : '可编辑'}
                  </span>
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
    </div>
  );
}
