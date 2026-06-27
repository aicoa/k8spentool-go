import React, { useState } from 'react';
import { Button, Card, Input, Space, List, Typography, Tag, Alert } from 'antd';
import { RobotOutlined, UserOutlined, ToolOutlined } from '@ant-design/icons';
import { api } from '../services/api';

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; host: string; }

export default function AITab({ getAuth, addLog, host }: Props) {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Array<{ role: string; content: string; traces?: any[] }>>([]);
  const [input, setInput] = useState('');
  const [plan, setPlan] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const auth = getAuth();

  const createSession = async () => {
    try {
      const r = await api.ai.createSession(host || 'default', auth);
      setSessionId(r.id);
      setMessages([{ role: 'assistant', content: 'AI session created. I can help plan and execute penetration testing steps. Type "plan" to generate an attack plan, or describe your goal (e.g. "分析这个集群能否逃逸/提权/打Dashboard").' }]);
      addLog('[AI] Session created: ' + r.id);
    } catch (e) { addLog('[AI] Failed to create session: ' + e); }
  };

  const sendMessage = async () => {
    if (!sessionId || !input.trim()) return;
    setLoading(true);
    const userMsg = input;
    setMessages((prev) => [...prev, { role: 'user', content: userMsg }]);
    setInput('');

    try {
      if (userMsg.toLowerCase().includes('plan') && userMsg.length < 20) {
        const r = await api.ai.generatePlan(sessionId, 'Complete penetration test of target K8s cluster');
        setPlan(r);
        setMessages((prev) => [...prev, { role: 'assistant', content: `Attack plan generated: ${r.steps?.length || 0} steps. Review and approve each step to proceed.` }]);
        addLog('[AI] Attack plan generated');
      } else {
        const r = await api.ai.chat(sessionId, userMsg);
        const content = r.response?.content || 'Response received';
        const traces = r.tool_traces || [];
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
      await api.ai.approveStep(sessionId, index);
      addLog(`[AI] Step ${index} approved`);
    } catch (e) { addLog('[AI] Failed to approve step: ' + e); }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, height: 'calc(100vh - 300px)' }}>
      <Card title={<span><RobotOutlined /> AI Chat</span>} size="small" style={{ display: 'flex', flexDirection: 'column' }}
        extra={!sessionId && <Button size="small" onClick={createSession}>Start Session</Button>}>
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
            onPressEnter={sendMessage} disabled={!sessionId || loading} style={{ flex: 1 }} />
          <Button type="primary" onClick={sendMessage} loading={loading} disabled={!sessionId}>Send</Button>
        </Space>
      </Card>
      <Card title="Attack Plan" size="small">
        {plan ? (
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
  );
}
