import { useState } from 'react';
import { ChevronRight, ChevronDown, Circle, Server, Network, FileCode } from 'lucide-react';

interface TreeNode {
  id: string;
  name: string;
  type: 'stack' | 'server' | 'chain' | 'tunnel';
  status: 'active' | 'idle' | 'error';
  children?: TreeNode[];
  details?: Record<string, any>;
}

const mockObjectTree: TreeNode[] = [
  {
    id: 'stack1',
    name: 'Transparent Stack (0.0.0.0:1080)',
    type: 'stack',
    status: 'active',
    details: {
      bind: '0.0.0.0:1080',
      protocol: 'transparent',
      connections: 45,
    },
    children: [
      {
        id: 'chain1',
        name: 'Process Chain',
        type: 'chain',
        status: 'active',
        details: {
          hooks: ['pre_route', 'post_route'],
          rules: 5,
        },
      },
    ],
  },
  {
    id: 'server1',
    name: 'SOCKS5 Server (127.0.0.1:1080)',
    type: 'server',
    status: 'active',
    details: {
      bind: '127.0.0.1:1080',
      protocol: 'socks5',
      clients: 3,
    },
    children: [
      {
        id: 'chain2',
        name: 'Process Chain',
        type: 'chain',
        status: 'active',
        details: {
          hooks: ['server_request'],
          rules: 3,
        },
      },
    ],
  },
  {
    id: 'tunnel1',
    name: 'Tunnel: HK-01 (wireguard)',
    type: 'tunnel',
    status: 'active',
    details: {
      schema: 'wireguard',
      endpoint: 'hk01.example.com:51820',
      streams: 12,
    },
  },
  {
    id: 'tunnel2',
    name: 'Tunnel: US-01 (shadowsocks)',
    type: 'tunnel',
    status: 'active',
    details: {
      schema: 'shadowsocks',
      endpoint: 'us01.example.com:8388',
      streams: 8,
    },
  },
];

const TreeItem = ({ node, level = 0 }: { node: TreeNode; level?: number }) => {
  const [expanded, setExpanded] = useState(true);

  const Icon = {
    stack: Circle,
    server: Server,
    chain: FileCode,
    tunnel: Network,
  }[node.type];

  const statusColor = {
    active: 'text-green-600',
    idle: 'text-gray-400',
    error: 'text-red-600',
  }[node.status];

  return (
    <div>
      <div
        className={`flex items-center gap-2 py-2 px-4 hover:bg-gray-50 cursor-pointer`}
        style={{ paddingLeft: `${level * 1.5 + 1}rem` }}
        onClick={() => node.children && setExpanded(!expanded)}
      >
        {node.children && (
          <button className="p-0.5">
            {expanded ? (
              <ChevronDown className="w-4 h-4 text-gray-600" />
            ) : (
              <ChevronRight className="w-4 h-4 text-gray-600" />
            )}
          </button>
        )}
        {!node.children && <div className="w-5" />}
        <Icon className={`w-5 h-5 ${statusColor}`} />
        <span className="font-medium text-gray-900">{node.name}</span>
        <span className={`text-xs px-2 py-0.5 rounded ${
          node.status === 'active' ? 'bg-green-100 text-green-700' :
          node.status === 'idle' ? 'bg-gray-100 text-gray-600' :
          'bg-red-100 text-red-700'
        }`}>
          {node.status}
        </span>
      </div>
      {expanded && node.children && (
        <div>
          {node.children.map((child) => (
            <TreeItem key={child.id} node={child} level={level + 1} />
          ))}
        </div>
      )}
    </div>
  );
};

export default function ObjectTree() {
  const [selectedNode, setSelectedNode] = useState<TreeNode | null>(mockObjectTree[0]);

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-gray-900">对象树</h1>
        <p className="text-gray-600 mt-2">查看运行时对象结构和状态</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Tree view */}
        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <div className="bg-gray-50 border-b border-gray-200 px-6 py-3">
            <h2 className="text-sm font-semibold text-gray-900">对象列表</h2>
          </div>
          <div className="overflow-y-auto max-h-[700px]">
            {mockObjectTree.map((node) => (
              <div key={node.id} onClick={() => setSelectedNode(node)}>
                <TreeItem node={node} />
              </div>
            ))}
          </div>
        </div>

        {/* Details panel */}
        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <div className="bg-gray-50 border-b border-gray-200 px-6 py-3">
            <h2 className="text-sm font-semibold text-gray-900">对象详情</h2>
          </div>
          <div className="p-6">
            {selectedNode ? (
              <div className="space-y-4">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">{selectedNode.name}</h3>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded">
                      {selectedNode.type}
                    </span>
                    <span className={`px-2 py-1 text-xs rounded ${
                      selectedNode.status === 'active' ? 'bg-green-100 text-green-700' :
                      selectedNode.status === 'idle' ? 'bg-gray-100 text-gray-600' :
                      'bg-red-100 text-red-700'
                    }`}>
                      {selectedNode.status}
                    </span>
                  </div>
                </div>

                {selectedNode.details && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">详细信息</h4>
                    <div className="bg-gray-900 rounded-lg p-4">
                      <pre className="text-green-400 text-sm font-mono">
                        {JSON.stringify(selectedNode.details, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}

                {selectedNode.children && selectedNode.children.length > 0 && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">
                      子对象 ({selectedNode.children.length})
                    </h4>
                    <div className="space-y-2">
                      {selectedNode.children.map((child) => (
                        <div
                          key={child.id}
                          onClick={() => setSelectedNode(child)}
                          className="p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer"
                        >
                          <p className="font-medium text-gray-900">{child.name}</p>
                          <p className="text-sm text-gray-600">{child.type}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="pt-4 border-t border-gray-200">
                  <button className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                    查看日志
                  </button>
                </div>
              </div>
            ) : (
              <p className="text-gray-500 text-center py-12">选择一个对象查看详情</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
