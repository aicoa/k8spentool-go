import React, { useState } from 'react';
import { Button, Card, Input, Select, Space, Tag, Table, Typography, Alert } from 'antd';
import { api, targetParams } from '../services/api';
import ResultView from '../components/ResultView';

const { Text } = Typography;

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; }

export default function EscapeTab({ getAuth, addLog }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [checks, setChecks] = useState<any[]>([]);
  const [lhost, setLhost] = useState('');
  const [lport, setLport] = useState('4444');
  const [escapeType, setEscapeType] = useState('chroot');
  const [vulns, setVulns] = useState<any[]>([]);
  // Batch escape assessment
  const [assessment, setAssessment] = useState<any>(null);

  const run = async (fn: () => Promise<any>, label: string) => {
    setLoading(true); setResult(null);
    try { const r = await fn(); setResult(r); addLog(`[+] ${label}`); }
    catch (e) { setResult({ error: String(e) }); addLog(`[-] ${label}`); }
    finally { setLoading(false); }
  };
  const t = targetParams(getAuth());

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      {/* Batch Auto-Detection */}
      <Card title="🔍 批量自动检测所有Pod" size="small" style={{ gridColumn: '1 / -1', border: '2px solid #1890ff' }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Button type="primary" size="large" loading={loading}
              onClick={async () => {
                setLoading(true);
                try {
                  const r = await api.cdk.assessEscape(t);
                  setAssessment(r);
                  addLog(`[Escape] Assessed ${r.total_pods} pods, ${r.risky_count} have escape potential`);
                } catch (e) {
                  addLog(`[-] Escape assessment failed: ${e}`);
                }
                setLoading(false);
              }}>
              一键评估所有Pod逃逸风险
            </Button>
            <Text type="secondary" style={{ fontSize: 11 }}>
              检测所有Pod的 Privileged、hostPID、hostNetwork、docker.sock、hostPath 挂载等
            </Text>
          </Space>
          {assessment && (
            <div style={{ marginTop: 8 }}>
              <Space wrap>
                <Tag color="red">🔴 特权限: {assessment.summary?.critical_privileged || 0}</Tag>
                <Tag color="orange">🟠 主机命名空间: {assessment.summary?.host_namespace || 0}</Tag>
                <Tag color="gold">🟡 主机挂载: {assessment.summary?.host_mounts || 0}</Tag>
                <Tag color="volcano">🐳 Docker.sock: {assessment.summary?.docker_sock || 0}</Tag>
                <Tag>总计风险Pod: {assessment.risky_count} / {assessment.total_pods}</Tag>
              </Space>
              {assessment.high_risk?.length > 0 && (
                <Table
                  dataSource={assessment.high_risk.map((r: any, i: number) => ({ ...r, _key: i }))}
                  columns={[
                    { title: 'Pod', dataIndex: 'name', key: 'name', render: (v: string, r: any) => <Text>{r.namespace}/{v}</Text> },
                    { title: 'Risk', dataIndex: 'risk_level', key: 'risk', width: 80,
                      render: (v: string) => <Tag color={v === 'critical' ? 'red' : 'orange'}>{v}</Tag> },
                    { title: 'Node', dataIndex: 'node', key: 'node', width: 120 },
                    { title: 'Flags', dataIndex: 'risk_reasons', key: 'flags',
                      render: (reasons: string[]) => <Space size={2} wrap>{(reasons || []).map((r, i) => <Tag key={i} color="red" style={{ fontSize: 10 }}>{r}</Tag>)}</Space> },
                  ]}
                  size="small"
                  pagination={false}
                  rowKey="_key"
                  style={{ marginTop: 8 }}
                  title={() => <Text strong style={{ color: '#ff4d4f' }}>⚠️ 高风险Pod ({assessment.high_risk.length}个)</Text>}
                />
              )}
            </div>
          )}
        </Space>
      </Card>

      {/* Manual Escape Checks */}
      <Card title="Escape Condition Checks" size="small">
        <Button onClick={async () => { const r = await api.escape.checks(); setChecks(r.checks); addLog('Loaded escape checks'); }}>加载手动检测命令</Button>
        <div style={{ maxHeight: 250, overflow: 'auto', marginTop: 8 }}>
          {(checks as any[]).map((c, i) => (
            <div key={i} style={{ fontSize: 11, padding: 4, borderBottom: '1px solid #eee' }}>
              <b>{c.check}</b>: {c.desc}<br/><code>{c.cmd}</code>
            </div>
          ))}
        </div>
      </Card>
      <Card title="Privileged Escape" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Input placeholder="LHOST" value={lhost} onChange={(e) => setLhost(e.target.value)} style={{ width: 130 }} />
            <Input placeholder="LPORT" value={lport} onChange={(e) => setLport(e.target.value)} style={{ width: 80 }} />
          </Space>
          <Button danger onClick={() => run(() => api.escape.privileged({ ...t, pod_name: 'current', lhost, lport }), 'Gen privileged escape')}>生成 Privileged Escape</Button>
        </Space>
      </Card>
      <Card title="挂载 Escape" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Select value={escapeType} onChange={setEscapeType} style={{ width: 200 }}
            options={['chroot','crontab','docker.sock','procfs'].map(s => ({ value: s, label: s }))} />
          <Space>
            <Input placeholder="LHOST" value={lhost} onChange={(e) => setLhost(e.target.value)} style={{ width: 130 }} />
            <Input placeholder="LPORT" value={lport} onChange={(e) => setLport(e.target.value)} style={{ width: 80 }} />
          </Space>
          <Button onClick={() => run(() => api.escape.mount({ escape_type: escapeType, lhost, lport }), 'Gen mount escape')}>生成 挂载 Escape</Button>
        </Space>
      </Card>
      <Card title="Kernel Vulnerabilities" size="small">
        <Button onClick={async () => { const r = await api.escape.kernelVulns(); setVulns(r.vulnerabilities); addLog('Loaded kernel vulns'); }}>加载 Vulnerabilities</Button>
        <div style={{ maxHeight: 200, overflow: 'auto', marginTop: 8 }}>
          {(vulns as any[]).map((v, i) => (
            <div key={i} style={{ fontSize: 11, padding: 4 }}><b>{v.cve}</b> - {v.name} ({v.affected})</div>
          ))}
        </div>
      </Card>
      <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}>
        <ResultView result={result} loading={loading} emptyHint="点击按钮生成逃逸命令，或使用上方「批量自动检测」评估全部Pod" />
      </Card>
    </div>
  );
}
