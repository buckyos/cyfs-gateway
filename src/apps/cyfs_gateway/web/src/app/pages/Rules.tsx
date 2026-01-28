import { useState } from 'react';
import { Plus, Power, GripVertical, Copy, Trash2, FileCode, Settings } from 'lucide-react';
import { mockRules, type Rule } from '@/app/lib/mockData';
import { DndProvider, useDrag, useDrop } from 'react-dnd';
import { HTML5Backend } from 'react-dnd-html5-backend';

const DraggableRule = ({ rule, index, moveRule, toggleRule, deleteRule }: any) => {
  const [{ isDragging }, drag] = useDrag({
    type: 'rule',
    item: { index },
    collect: (monitor) => ({
      isDragging: monitor.isDragging(),
    }),
    canDrag: rule.type === 'post',
  });

  const [, drop] = useDrop({
    accept: 'rule',
    hover: (draggedItem: { index: number }) => {
      if (draggedItem.index !== index && rule.type === 'post') {
        moveRule(draggedItem.index, index);
        draggedItem.index = index;
      }
    },
  });

  return (
    <div
      ref={(node) => drag(drop(node))}
      className={`bg-white rounded-lg border border-gray-200 p-6 ${
        isDragging ? 'opacity-50' : ''
      } ${rule.type === 'config' ? 'bg-gray-50' : ''}`}
    >
      <div className="flex items-start gap-4">
        {/* Drag handle */}
        {rule.type === 'post' ? (
          <GripVertical className="w-5 h-5 text-gray-400 cursor-move mt-1" />
        ) : (
          <Settings className="w-5 h-5 text-gray-400 mt-1" />
        )}

        <div className="flex-1">
          {/* Header */}
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="text-lg font-semibold text-gray-900">{rule.name}</h3>
              <p className="text-sm text-gray-600 mt-1">{rule.description}</p>
              <div className="flex items-center gap-3 mt-2">
                <span
                  className={`px-2 py-1 rounded text-xs font-medium ${
                    rule.type === 'post'
                      ? 'bg-blue-100 text-blue-700'
                      : 'bg-gray-200 text-gray-700'
                  }`}
                >
                  {rule.type === 'post' ? 'Post 规则' : '配置规则'}
                </span>
                {rule.type === 'config' && (
                  <span className="text-xs text-gray-500">来源: {rule.source}</span>
                )}
                <span className="text-xs text-gray-500">优先级: {rule.priority}</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {rule.type === 'post' && (
                <>
                  <button
                    onClick={() => toggleRule(rule.id)}
                    className={`p-2 rounded-lg transition-colors ${
                      rule.enabled
                        ? 'bg-green-100 text-green-700 hover:bg-green-200'
                        : 'bg-gray-100 text-gray-400 hover:bg-gray-200'
                    }`}
                  >
                    <Power className="w-4 h-4" />
                  </button>
                  <button className="p-2 text-gray-600 hover:bg-gray-100 rounded-lg transition-colors">
                    <Copy className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => deleteRule(rule.id)}
                    className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </>
              )}
              {rule.type === 'config' && (
                <span className="px-3 py-1 bg-gray-200 text-gray-600 text-xs rounded-lg">
                  只读
                </span>
              )}
            </div>
          </div>

          {/* Script */}
          <div className="bg-gray-900 rounded-lg p-4 mb-3">
            <pre className="text-green-400 text-sm font-mono overflow-x-auto">{rule.script}</pre>
          </div>

          {/* Stats */}
          <div className="flex items-center gap-6 text-sm text-gray-600">
            <span>命中次数: {rule.hitCount}</span>
            <span>最后触发: {rule.lastTriggered}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

function RulesContent() {
  const [rules, setRules] = useState<Rule[]>(mockRules);
  const [showNewRuleDialog, setShowNewRuleDialog] = useState(false);
  const [naturalLanguage, setNaturalLanguage] = useState('');
  const [generatedScript, setGeneratedScript] = useState('');

  const moveRule = (fromIndex: number, toIndex: number) => {
    const newRules = [...rules];
    const [movedRule] = newRules.splice(fromIndex, 1);
    newRules.splice(toIndex, 0, movedRule);
    setRules(newRules);
  };

  const toggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const deleteRule = (id: string) => {
    if (confirm('确定要删除这条规则吗？')) {
      setRules((prev) => prev.filter((r) => r.id !== id));
    }
  };

  const generatePrompt = () => {
    const prompt = `你是一个 CYFS Gateway 规则脚本生成器。请根据以下需求生成规则脚本：

需求：${naturalLanguage}

可用变量：
- \${REQ.src_ip} - 源 IP 地址
- \${REQ.dest_host} - 目标主机名
- \${REQ.dest_ip} - 目标 IP 地址
- \${REQ.dest_host_tag} - 目标主机标签
- \${REQ.dest_ip_geo} - 目标 IP 地理位置

可用指令：
- forward("tunnel://tunnel_id/stream_id") - 转发到指定 tunnel
- accept() - 直接放行
- reject("reason") - 拒绝请求
- return - 终止规则链

请生成符合语法的规则脚本：`;

    navigator.clipboard.writeText(prompt);
    alert('提示词已复制到剪贴板！\n\n请在 ChatGPT 中粘贴并获取生成的脚本，然后粘贴回这里。');
  };

  const applyRule = () => {
    if (!generatedScript.trim()) {
      alert('请先粘贴生成的脚本');
      return;
    }

    // 简单的语法校验
    if (!generatedScript.includes('${REQ') && !generatedScript.includes('forward') && !generatedScript.includes('accept') && !generatedScript.includes('reject')) {
      alert('脚本语法可能有误，请检查后重试');
      return;
    }

    const newRule: Rule = {
      id: `rule-${Date.now()}`,
      name: `新规则 ${rules.length + 1}`,
      description: naturalLanguage,
      script: generatedScript,
      enabled: true,
      type: 'post',
      source: 'dashboard',
      priority: rules.filter((r) => r.type === 'post').length + 1,
      hitCount: 0,
      lastTriggered: '从未',
    };

    setRules([newRule, ...rules]);
    setShowNewRuleDialog(false);
    setNaturalLanguage('');
    setGeneratedScript('');
    alert('规则已创建并生效！');
  };

  const postRules = rules.filter((r) => r.type === 'post');
  const configRules = rules.filter((r) => r.type === 'config');

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-gray-900">规则</h1>
          <p className="text-gray-600 mt-2">管理 process-chain 规则脚本</p>
          <p className="text-sm text-amber-600 mt-2">
            💡 提示：Post 规则支持拖拽排序，从上到下顺序执行
          </p>
        </div>
        <button
          onClick={() => setShowNewRuleDialog(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-5 h-5" />
          新建规则
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">Post 规则（可编辑）</p>
          <p className="text-2xl font-semibold text-blue-600 mt-1">{postRules.length}</p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">配置规则（只读）</p>
          <p className="text-2xl font-semibold text-gray-600 mt-1">{configRules.length}</p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-sm text-gray-600">启用规则</p>
          <p className="text-2xl font-semibold text-green-600 mt-1">
            {rules.filter((r) => r.enabled).length}
          </p>
        </div>
      </div>

      {/* Post Rules */}
      {postRules.length > 0 && (
        <div className="mb-8">
          <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <FileCode className="w-5 h-5" />
            Post 规则（可拖拽排序）
          </h2>
          <div className="space-y-4">
            {postRules.map((rule, index) => (
              <DraggableRule
                key={rule.id}
                rule={rule}
                index={index}
                moveRule={moveRule}
                toggleRule={toggleRule}
                deleteRule={deleteRule}
              />
            ))}
          </div>
        </div>
      )}

      {/* Config Rules */}
      {configRules.length > 0 && (
        <div>
          <h2 className="text-xl font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Settings className="w-5 h-5" />
            配置规则（只读）
          </h2>
          <div className="space-y-4">
            {configRules.map((rule, index) => (
              <DraggableRule
                key={rule.id}
                rule={rule}
                index={postRules.length + index}
                moveRule={() => {}}
                toggleRule={() => {}}
                deleteRule={() => {}}
              />
            ))}
          </div>
        </div>
      )}

      {/* New rule dialog */}
      {showNewRuleDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">新建规则（离线模式）</h2>

            <div className="space-y-6">
              {/* Step 1: Natural language */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  步骤 1: 用自然语言描述需求
                </label>
                <textarea
                  value={naturalLanguage}
                  onChange={(e) => setNaturalLanguage(e.target.value)}
                  className="w-full h-24 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="例如：某设备在某时段访问某类网站走代理"
                />
              </div>

              {/* Step 2: Generate prompt */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  步骤 2: 生成并复制提示词
                </label>
                <button
                  onClick={generatePrompt}
                  disabled={!naturalLanguage.trim()}
                  className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors disabled:bg-gray-300 disabled:cursor-not-allowed"
                >
                  生成提示词并复制
                </button>
                <p className="text-sm text-gray-600 mt-2">
                  点击后会将提示词复制到剪贴板，请在 ChatGPT 中粘贴并获取生成的脚本
                </p>
              </div>

              {/* Step 3: Paste script */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  步骤 3: 粘贴 ChatGPT 生成的脚本
                </label>
                <textarea
                  value={generatedScript}
                  onChange={(e) => setGeneratedScript(e.target.value)}
                  className="w-full h-48 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm bg-gray-900 text-green-400"
                  placeholder="粘贴脚本..."
                />
              </div>

              {/* Validation info */}
              {generatedScript && (
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                  <p className="text-sm text-blue-900">
                    ✅ 脚本已填入，点击"应用规则"进行语法校验并生效
                  </p>
                </div>
              )}
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setShowNewRuleDialog(false);
                  setNaturalLanguage('');
                  setGeneratedScript('');
                }}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
              >
                取消
              </button>
              <button
                onClick={applyRule}
                disabled={!generatedScript.trim()}
                className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:bg-gray-300 disabled:cursor-not-allowed"
              >
                应用规则
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Rules() {
  return (
    <DndProvider backend={HTML5Backend}>
      <RulesContent />
    </DndProvider>
  );
}
