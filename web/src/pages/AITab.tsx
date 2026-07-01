import React, { useState, useEffect } from 'react';
import { Button, Card, Input, Space, List, Typography, Tag, Select, message, Collapse, Popconfirm } from 'antd';
import { RobotOutlined, UserOutlined, ToolOutlined, SettingOutlined, ApiOutlined, DeleteOutlined, ReloadOutlined } from '@ant-design/icons';
import { api } from '../services/api';

const { Text } = Typography;

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; host: string; activeTarget: string | null; }

interface AISessionSummary {
  id: string;
  target_id?: string;
  status?: string;
  created_at?: string;
  pending_actions?: any[];
  history?: Array<{ role: string; content: string }>;
}

function formatSessionLabel(session: AISessionSummary) {
  if (!session.created_at) return session.id.slice(0, 8);
  const created = new Date(session.created_at);
  if (Number.isNaN(created.getTime())) return session.id.slice(0, 8);
  return created.toLocaleString();
}

function historyToMessages(history?: Array<{ role: string; content: string }>) {
  if (!history || history.length === 0) return [];
  return history
    .filter((entry) => entry.role === 'assistant' || entry.role === 'user' || entry.role === 'system')
    .map((entry) => ({ role: entry.role, content: entry.content }));
}

export default function AITab({ getAuth, addLog, host, activeTarget }: Props) {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Array<{ role: string; content: string; traces?: any[] }>>([]);
  const [pendingActions, setPendingActions] = useState<any[]>([]);
  const [sessions, setSessions] = useState<AISessionSummary[]>([]);
  const [input, setInput] = useState('');
  const [plan, setPlan] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [sessionLoading, setSessionLoading] = useState(false);
  const [sessionPage, setSessionPage] = useState(1);
  const [sessionPageSize, setSessionPageSize] = useState(10);

  // LLM config
  const [llmProvider, setLlmProvider] = useState('openai');
  const [llmModel, setLlmModel] = useState('');
  const [llmApiKey, setLlmApiKey] = useState('');
  const [llmBaseURL, setLlmBaseURL] = useState('');
  const [llmSaving, setLlmSaving] = useState(false);
  const [hasSavedApiKey, setHasSavedApiKey] = useState(false);

  useEffect(() => {
    api.ai.getConfig().then((cfg: any) => {
      if (cfg?.provider) setLlmProvider(cfg.provider);
      if (cfg?.model) setLlmModel(cfg.model);
      if (cfg?.base_url) setLlmBaseURL(cfg.base_url);
      setHasSavedApiKey(!!cfg?.has_api_key);
    }).catch(() => {});

    loadSessions();
  }, []);

  const loadSessions = async () => {
    setSessionLoading(true);
    try {
      const list = await api.ai.listSessions();
      const sessionList = Array.isArray(list) ? list : [];
      sessionList.sort((a: AISessionSummary, b: AISessionSummary) => {
        const at = new Date(a.created_at || 0).getTime();
        const bt = new Date(b.created_at || 0).getTime();
        return bt - at;
      });
      setSessions(sessionList);
    } catch (e) {
      addLog('[AI] Failed to load sessions: ' + e);
    } finally {
      setSessionLoading(false);
    }
  };

  const saveLLMConfig = async () => {
    setLlmSaving(true);
    try {
      await api.ai.updateConfig({
        provider: llmProvider,
        model: llmModel || undefined,
        api_key: llmApiKey || undefined,
        base_url: llmBaseURL || undefined,
      });
      if (llmApiKey.trim()) setHasSavedApiKey(true);
      setLlmApiKey('');
      message.success('LLM 配置已保存');
      addLog(`[AI] LLM config updated: ${llmProvider}/${llmModel || 'default'}`);
    } catch (e) { message.error('保存失败: ' + e); }
    finally { setLlmSaving(false); }
  };

  const clearSavedApiKey = async () => {
    setLlmSaving(true);
    try {
      await api.ai.updateConfig({ clear_api_key: true });
      setLlmApiKey('');
      setHasSavedApiKey(false);
      message.success('已清除已保存 API Key');
      addLog('[AI] Saved API key cleared');
    } catch (e) {
      message.error('清除 API Key 失败: ' + e);
    } finally {
      setLlmSaving(false);
    }
  };

  const auth = getAuth();

  const createSession = async () => {
    try {
      const targetId = activeTarget || host || 'default';
      const r = await api.ai.createSession(targetId, auth);
      setSessionId(r.id);
      setPendingActions([]);
      setMessages([{ role: 'assistant', content: `AI session created for target ${auth.host || targetId}. I can help plan and execute penetration testing steps. Type "plan" to generate an attack plan, or describe your goal (e.g. "分析这个集群能否逃逸/提权/打Dashboard").` }]);
      addLog('[AI] Session created: ' + r.id);
      loadSessions();
    } catch (e) { addLog('[AI] Failed to create session: ' + e); }
  };

  const selectSession = async (id: string) => {
    setSessionLoading(true);
    try {
      const r = await api.ai.getSession(id);
      setSessionId(r.id);
      // Old sessions may have stale pending_actions. Only keep unresolved ones.
      const unresolved = (r.pending_actions || []).filter(
        (a: any) => a.status !== 'completed' && a.status !== 'cancelled'
      );
      setPendingActions(unresolved);
      setPlan(r.plan || null);
      setMessages(historyToMessages(r.history));
      addLog('[AI] Session loaded: ' + id);
    } catch (e) {
      message.error('加载 AI session 失败: ' + e);
    } finally {
      setSessionLoading(false);
    }
  };

  const closeSession = () => {
    setSessionId(null);
    setMessages([]);
    setPendingActions([]);
    setPlan(null);
    addLog('[AI] Session closed');
  };

  const deleteSession = async (id: string) => {
    try {
      await api.ai.deleteSession(id);
      setSessions((prev) => prev.filter((session) => session.id !== id));
      if (sessionId === id) {
        setSessionId(null);
        setMessages([]);
        setPendingActions([]);
        setPlan(null);
      }
      addLog('[AI] Session deleted: ' + id);
      message.success('AI session 已删除');
    } catch (e) {
      message.error('删除 AI session 失败: ' + e);
    }
  };

  const sendMessage = async () => {
    if (!sessionId || !input.trim()) return;
    setLoading(true);
    const userMsg = input;
    setMessages((prev) => [...prev, { role: 'user', content: userMsg }]);
    setInput('');

    try {
      if (userMsg.toLowerCase().includes('plan') || userMsg.toLowerCase().includes('attack plan') || userMsg.includes('攻击计划')) {
        const r = await api.ai.generatePlan(sessionId, 'Complete penetration test of target K8s cluster');
        if (r?.error) throw new Error(r.error);
        setPlan(r);
        setMessages((prev) => [...prev, { role: 'assistant', content: `Attack plan generated: ${r.steps?.length || 0} steps. Review and approve each step to proceed.` }]);
        addLog('[AI] Attack plan generated');
      } else {
        const r = await api.ai.chat(sessionId, userMsg);
        if (r?.error) {
          setPendingActions(r.pending_actions || []);
          throw new Error(r.error);
        }
        const content = r.response?.content || 'Response received';
        const traces = r.tool_traces || [];
        setPendingActions(r.pending_actions || []);
        setMessages((prev) => [...prev, { role: 'assistant', content, traces }]);
        const toolCount = traces.length;
        addLog(`[AI] Chat done: ${toolCount} tools executed, ${traces.filter((t: any) => t.status === 'needs_approval').length} need approval`);
      }
    } catch (e) {
      setMessages((prev) => [...prev, { role: 'assistant', content: `Error: ${e}\n\nTip: Ensure LLM backend is configured (API key, base URL). Without LLM, the fallback rule-based engine can only provide general guidance.` }]);
    }
    setLoading(false);
  };

  const approveStep = async (index: number) => {
    if (!sessionId) return;
    try {
      const r = await api.ai.approveStep(sessionId, index);
      if (r?.error) throw new Error(r.error);
      setPlan(r);
      addLog(`[AI] Step ${index} approved`);
    } catch (e) { addLog('[AI] Failed to approve step: ' + e); }
  };

  const approveAction = async (actionId: string) => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const r = await api.ai.approveAction(sessionId, actionId);
      if (r?.error) throw new Error(r.error);
      const content = r.response?.content || 'Action approved';
      const traces = r.tool_traces || [];
      setPendingActions(r.pending_actions || []);
      setMessages((prev) => [...prev, { role: 'assistant', content, traces }]);
      addLog(`[AI] Action approved: ${actionId}`);
    } catch (e) {
      setMessages((prev) => [...prev, { role: 'assistant', content: `Approval error: ${e}` }]);
      addLog('[AI] Failed to approve action: ' + e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: 'calc(100vh - 300px)', overflow: 'auto' }}>
      {/* LLM Config */}
      <Collapse ghost size="small" style={{ flexShrink: 0 }}
        items={[{
          key: 'llm-config',
          label: <span style={{ fontSize: 12 }}><SettingOutlined /> LLM 配置</span>,
          children: (
            <Space direction="vertical" style={{ width: '100%' }} size={4}>
              <Space size={8} wrap>
                <Select value={llmProvider} onChange={setLlmProvider} size="small" style={{ width: 110 }}
                  options={[
                    { value: 'openai', label: 'OpenAI 兼容 (推荐)' },
                    { value: 'ollama', label: 'Ollama (本地)' },
                    { value: 'anthropic', label: 'Anthropic/Claude' },
                    { value: 'custom', label: '自定义' },
                  ]} />
                <Input size="small" placeholder="模型名称，如 deepseek-v4-pro" value={llmModel}
                  onChange={(e) => setLlmModel(e.target.value)} style={{ width: 180 }} />
              </Space>
              <Space size={8} wrap>
                <Input.Password size="small" placeholder="API Key (留空不修改)" value={llmApiKey}
                  onChange={(e) => setLlmApiKey(e.target.value)} style={{ width: 280 }}
                  prefix={<ApiOutlined />} />
                <Input size="small" placeholder="Base URL (如 https://api.deepseek.com/v1)" value={llmBaseURL}
                  onChange={(e) => setLlmBaseURL(e.target.value)} style={{ width: 280 }} />
              </Space>
              <Space size={8} wrap>
                <Button size="small" type="primary" onClick={saveLLMConfig} loading={llmSaving}
                  disabled={!llmProvider && !llmModel && !llmApiKey && !llmBaseURL}>
                  保存配置
                </Button>
                <Button size="small" danger onClick={clearSavedApiKey} loading={llmSaving} disabled={!hasSavedApiKey}>
                  清除已保存 Key
                </Button>
              </Space>
              <Text type="secondary" style={{ fontSize: 10 }}>
                支持 OpenAI 兼容 API (DeepSeek/GPT等) / Ollama 本地模型 / Anthropic Claude / 自定义。API Key 保存在服务端，不会回显，可在此处清除。
              </Text>
            </Space>
          ),
        }]}
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, flex: 1, minHeight: 0 }}>
        <Card title={<span><RobotOutlined /> AI Chat</span>} size="small" style={{ display: 'flex', flexDirection: 'column' }}
        extra={
          <Space size={4}>
            {!sessionId ? (
              <Button size="small" type="primary" onClick={createSession}>新建会话</Button>
            ) : (
              <>
                <Button size="small" onClick={closeSession}>关闭</Button>
                <Button size="small" type="primary" onClick={createSession}>新建会话</Button>
              </>
            )}
          </Space>
        }>
        <div style={{ flex: 1, overflow: 'auto', maxHeight: 400, marginBottom: 12 }}>
          {messages.map((m, i) => (
            <div key={i} style={{ marginBottom: 8, padding: 8, background: m.role === 'user' ? '#e6f7ff' : m.role === 'system' ? '#f6ffed' : '#f0f0f0', borderRadius: 8 }}>
              <Typography.Text strong style={{ fontSize: 11 }}>
                {m.role === 'user' ? <UserOutlined /> : <RobotOutlined />} {m.role}
              </Typography.Text>
              <Typography.Paragraph style={{ fontSize: 12, margin: '4px 0 0', whiteSpace: 'pre-wrap' }}>{m.content}</Typography.Paragraph>
              {m.traces && m.traces.length > 0 && (
                <div style={{ marginTop: 6, padding: 6, background: '#fafafa', borderRadius: 4 }}>
                  <Typography.Text style={{ fontSize: 10, color: '#888' }}><ToolOutlined /> Tools executed ({m.traces.length}):</Typography.Text>
                  {m.traces.map((t: any, j: number) => (
                    <div key={j} style={{ fontSize: 10, padding: '2px 0' }}>
                      <Tag color={t.status === 'ok' ? 'green' : t.status === 'needs_approval' ? 'orange' : 'red'} style={{ fontSize: 9 }}>{t.status}</Tag>
                      <code style={{ fontSize: 10 }}>{t.tool}</code>
                      <span style={{ color: '#666' }}> {t.result_preview?.substring(0, 80)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
          {messages.length === 0 && <Typography.Text type="secondary">Start an AI session to begin automated penetration testing</Typography.Text>}
        </div>
        <Space style={{ width: '100%' }}>
          <Input placeholder="Message or 'plan'..." value={input} onChange={(e) => setInput(e.target.value)}
            onPressEnter={sendMessage} disabled={!sessionId || loading || pendingActions.length > 0} style={{ flex: 1 }} />
          <Button type="primary" onClick={sendMessage} loading={loading} disabled={!sessionId || pendingActions.length > 0}>Send</Button>
        </Space>
      </Card>
      <Card title={pendingActions.length > 0 ? 'Pending Actions' : 'Attack Plan'} size="small">
        {pendingActions.length > 0 ? (
          <List size="small" dataSource={pendingActions} renderItem={(action: any) => (
            <List.Item actions={[
              <Tag color="orange">{action.status}</Tag>,
              <Button size="small" type="primary" onClick={() => approveAction(action.id)} loading={loading}>Approve</Button>
            ]}>
              <div>
                <Typography.Text strong>{action.tool_call?.function?.name || action.id}</Typography.Text>
                <br/><Typography.Text style={{ fontSize: 11, wordBreak: 'break-all' }}>{action.tool_call?.function?.arguments || '{}'}</Typography.Text>
              </div>
            </List.Item>
          )} />
        ) : plan ? (
          <div>
            <Typography.Text strong>Objective: {plan.objective}</Typography.Text>
            <List size="small" dataSource={plan.steps || []} renderItem={(step: any, i: number) => (
              <List.Item actions={[
                <Tag color={step.status === 'completed' ? 'green' : 'blue'}>{step.status}</Tag>,
                step.status === 'pending' && <Button size="small" onClick={() => approveStep(i)}>Approve</Button>
              ]}>
                <div>
                  <Typography.Text strong>{step.phase}/{step.action}</Typography.Text>
                  <br/><Typography.Text style={{ fontSize: 11 }}>{step.description}</Typography.Text>
                </div>
              </List.Item>
            )} />
          </div>
        ) : (
          <Typography.Text type="secondary">Generate an attack plan by typing "plan" in the chat</Typography.Text>
        )}
      </Card>
      </div>

      <Card
        title={<span><RobotOutlined /> AI Sessions</span>}
        size="small"
        extra={<Button size="small" icon={<ReloadOutlined />} onClick={loadSessions} loading={sessionLoading}>刷新</Button>}
      >
        <List
          size="small"
          loading={sessionLoading}
          dataSource={sessions}
          locale={{ emptyText: '暂无 AI sessions，先点 Start Session 创建一个' }}
          pagination={{
            current: sessionPage,
            pageSize: sessionPageSize,
            total: sessions.length,
            showSizeChanger: true,
            pageSizeOptions: ['10', '20', '30', '50'],
            showTotal: (total: number) => `共 ${total} 个 session`,
            onChange: (page: number) => setSessionPage(page),
            onShowSizeChange: (_current: number, size: number) => {
              setSessionPage(1);
              setSessionPageSize(size);
            },
          }}
          renderItem={(session) => (
            <List.Item
              style={{
                background: sessionId === session.id ? '#e6f7ff' : 'transparent',
                borderRadius: 6,
                paddingLeft: 8,
                paddingRight: 8,
              }}
              actions={[
                <Tag color={session.status === 'awaiting_approval' ? 'orange' : session.status === 'active' ? 'green' : 'blue'}>
                  {session.status || 'unknown'}
                </Tag>,
                <Button size="small" onClick={() => selectSession(session.id)}>打开</Button>,
                <Popconfirm
                  title="删除 AI session"
                  description="删除后该会话历史会一并移除。"
                  okText="删除"
                  cancelText="取消"
                  onConfirm={() => deleteSession(session.id)}
                >
                  <Button size="small" danger icon={<DeleteOutlined />} />
                </Popconfirm>,
              ]}
            >
              <div style={{ minWidth: 0 }}>
                <Typography.Text strong copyable={{ text: session.id }}>{session.id.slice(0, 8)}</Typography.Text>
                <br />
                <Typography.Text style={{ fontSize: 11, color: '#666' }}>
                  target: {session.target_id || 'unknown'} | {formatSessionLabel(session)}
                </Typography.Text>
                {!!session.pending_actions?.length && (
                  <>
                    <br />
                    <Typography.Text style={{ fontSize: 11, color: '#d48806' }}>
                      pending approvals: {session.pending_actions.length}
                    </Typography.Text>
                  </>
                )}
              </div>
            </List.Item>
          )}
        />
      </Card>
    </div>
  );
}
