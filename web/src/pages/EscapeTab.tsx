import React, { useState } from 'react';
import { Button, Card, Input, Select, Space } from 'antd';
import { api, targetParams, recordTargetStep } from '../services/api';
import ResultView from '../components/ResultView';

interface Props {
  getAuth: () => import('../services/api').AuthConfig;
  addLog: (msg: string) => void;
  activeTarget: string | null;
}

export default function EscapeTab({ getAuth, addLog, activeTarget }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [checks, setChecks] = useState<any[]>([]);
  const [lhost, setLhost] = useState('');
  const [lport, setLport] = useState('4444');
  const [escapeType, setEscapeType] = useState('chroot');
  const [vulns, setVulns] = useState<any[]>([]);

  const run = async (fn: () => Promise<any>, label: string) => {
    setLoading(true);
    setResult(null);
    try {
      const r = await fn();
      setResult(r);
      addLog(r?.error ? `[-] ${label} failed: ${r.error}` : `[+] ${label}`);
      recordTargetStep(activeTarget, {
        phase: 'escape',
        tool: 'escape',
        action: label,
        success: !r?.error,
        summary: r?.error ? `${label} failed: ${r.error}` : `${label} completed`,
        data: r,
        output: r?.output || r?.yaml,
        error: r?.error,
      }).catch(() => {});
    } catch (e) {
      setResult({ error: String(e) });
      addLog(`[-] ${label}`);
      recordTargetStep(activeTarget, {
        phase: 'escape',
        tool: 'escape',
        action: label,
        success: false,
        summary: `${label} failed`,
        error: String(e),
      }).catch(() => {});
    } finally {
      setLoading(false);
    }
  };

  const t = targetParams(getAuth());

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      <Card title="Escape Condition Checks" size="small">
        <Button onClick={async () => {
          try {
            const r = await api.escape.checks();
            setChecks(r.checks);
            addLog('Loaded escape checks');
          } catch (e) {
            addLog('[-] Failed to load escape checks: ' + e);
          }
        }}>
          加载手动检测命令
        </Button>
        <div style={{ maxHeight: 250, overflow: 'auto', marginTop: 8 }}>
          {(checks as any[]).map((c, i) => (
            <div key={i} style={{ fontSize: 11, padding: 4, borderBottom: '1px solid #eee' }}>
              <b>{c.check}</b>: {c.desc}
              <br />
              <code>{c.cmd}</code>
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
          <Button
            danger
            onClick={() => run(() => api.escape.privileged({ ...t, pod_name: 'current', lhost, lport }), 'Gen privileged escape')}
          >
            生成 Privileged Escape
          </Button>
        </Space>
      </Card>

      <Card title="挂载 Escape" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Select
            value={escapeType}
            onChange={setEscapeType}
            style={{ width: 200 }}
            options={['chroot', 'crontab', 'docker.sock', 'procfs'].map((value) => ({ value, label: value }))}
          />
          <Space>
            <Input placeholder="LHOST" value={lhost} onChange={(e) => setLhost(e.target.value)} style={{ width: 130 }} />
            <Input placeholder="LPORT" value={lport} onChange={(e) => setLport(e.target.value)} style={{ width: 80 }} />
          </Space>
          <Button onClick={() => run(() => api.escape.mount({ ...t, escape_type: escapeType, lhost, lport }), 'Gen mount escape')}>
            生成 挂载 Escape
          </Button>
        </Space>
      </Card>

      <Card title="Kernel Vulnerabilities" size="small">
        <Button onClick={async () => {
          try {
            const r = await api.escape.kernelVulns();
            setVulns(r.vulnerabilities);
            addLog('Loaded kernel vulns');
          } catch (e) {
            addLog('[-] Failed to load kernel vulns: ' + e);
          }
        }}>
          加载 Vulnerabilities
        </Button>
        <div style={{ maxHeight: 200, overflow: 'auto', marginTop: 8 }}>
          {(vulns as any[]).map((v, i) => (
            <div key={i} style={{ fontSize: 11, padding: 4 }}>
              <b>{v.cve}</b> - {v.name} ({v.affected})
            </div>
          ))}
        </div>
      </Card>

      <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}>
        <ResultView result={result} loading={loading} emptyHint="点击按钮生成逃逸命令备忘录" />
      </Card>
    </div>
  );
}
