import React, { useState } from 'react';
import { Button, Card, Input, Space } from 'antd';
import { api, targetParams, recordTargetStep } from '../services/api';
import ResultView from '../components/ResultView';

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; activeTarget: string | null; }

export default function LateralTab({ getAuth, addLog, activeTarget }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [ns, setNs] = useState('');
  const [secretName, setSecretName] = useState('');
  const [secretNs, setSecretNs] = useState('default');
  const [taintNode, setTaintNode] = useState('');
  const [taintNs, setTaintNs] = useState('default');

  const run = async (fn: () => Promise<any>, label: string) => {
    setLoading(true); setResult(null);
    try {
      const r = await fn();
      setResult(r);
      addLog(`[+] ${label}`);
      recordTargetStep(activeTarget, {
        phase: 'lateral',
        tool: 'lateral',
        action: label,
        success: !r?.error,
        summary: r?.error ? `${label} failed: ${r.error}` : `${label} completed`,
        data: r,
        output: r?.output || r?.body,
        error: r?.error,
      }).catch(() => {});
    }
    catch (e) {
      setResult({ error: String(e) });
      addLog(`[-] ${label}`);
      recordTargetStep(activeTarget, {
        phase: 'lateral',
        tool: 'lateral',
        action: label,
        success: false,
        summary: `${label} failed`,
        error: String(e),
      }).catch(() => {});
    }
    finally { setLoading(false); }
  };
  const t = targetParams(getAuth());

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      <Card title="Credential Access" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Input placeholder="命名空间 (empty=all)" value={ns} onChange={(e) => setNs(e.target.value)} style={{ width: 200 }} />
          <Button danger onClick={() => run(() => api.lateral.secrets({ ...t, namespace: ns }), 'List secrets')}>List Secrets</Button>
          <Space>
            <Input placeholder="Secret namespace" value={secretNs} onChange={(e) => setSecretNs(e.target.value)} style={{ width: 130 }} />
            <Input placeholder="Secret name" value={secretName} onChange={(e) => setSecretName(e.target.value)} style={{ width: 200 }} />
            <Button onClick={() => run(() => api.lateral.viewSecret({ ...t, namespace: secretNs, secret_name: secretName }), 'View secret')}>View & 解码</Button>
          </Space>
        </Space>
      </Card>
      <Card title="服务 Discovery" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button onClick={() => run(() => api.lateral.services(t), 'List services')}>List 服务s</Button>
          <Button onClick={() => run(() => api.lateral.endpoints(t), 'List endpoints')}>List 端点</Button>
          <Button onClick={() => run(() => api.lateral.nodes(t), 'List nodes')}>List 节点</Button>
          <Button onClick={() => run(() => api.lateral.netPols(t), 'List network policies')}>List 网络策略</Button>
        </Space>
      </Card>
      <Card title="Taint Toleration" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button onClick={() => run(() => api.lateral.taints(t), 'Show taints')}>Show Node 污点</Button>
          <Space>
            <Input placeholder="Namespace" value={taintNs} onChange={(e) => setTaintNs(e.target.value)} style={{ width: 120 }} />
            <Input placeholder="Target node" value={taintNode} onChange={(e) => setTaintNode(e.target.value)} style={{ width: 150 }} />
            <Button onClick={() => run(() => api.lateral.taintPod({ ...t, namespace: taintNs, node_name: taintNode, host_mount: true }), 'Gen taint pod')}>生成 污点容忍Pod YAML</Button>
          </Space>
        </Space>
      </Card>
      <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}>
        <ResultView result={result} loading={loading} emptyHint="点击上方按钮执行横向移动操作" />
      </Card>
    </div>
  );
}
