import React, { useState } from 'react';
import { Button, Card, Input, Space } from 'antd';
import { api, targetParams } from '../services/api';
import ResultView from '../components/ResultView';

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; }

export default function KubectlTab({ getAuth, addLog }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [customCmd, setCustomCmd] = useState('get namespaces');
  const [applyYaml, setApplyYaml] = useState('');

  const run = async (fn: () => Promise<any>, label: string) => {
    setLoading(true); setResult(null);
    try { const r = await fn(); setResult(r); addLog(`[+] ${label}`); }
    catch (e) { setResult({ error: String(e) }); addLog(`[-] ${label}`); }
    finally { setLoading(false); }
  };
  const t = targetParams(getAuth());

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      <Card title="资源枚举" size="small">
        <Space wrap>
          <Button onClick={() => run(() => api.kubectl.getPods(t), 'get pods')}>Get Pods</Button>
          <Button onClick={() => run(() => api.kubectl.getNodes(t), 'get nodes')}>Get Nodes</Button>
          <Button onClick={() => run(() => api.kubectl.getServices(t), 'get services')}>Get Services</Button>
          <Button onClick={() => run(() => api.kubectl.getDeployments(t), 'get deployments')}>Get Deployments</Button>
          <Button danger onClick={() => run(() => api.kubectl.getSecrets(t), 'get secrets')}>Get Secrets</Button>
          <Button onClick={() => run(() => api.kubectl.getSA(t), 'get sa')}>Get SA</Button>
          <Button onClick={() => run(() => api.kubectl.getCRB(t), 'get crb')}>Get CRB</Button>
          <Button onClick={() => run(() => api.kubectl.getImages(t), 'get images')}>Get Images</Button>
        </Space>
      </Card>
      <Card title="集群信息 & 权限" size="small">
        <Space wrap>
          <Button onClick={() => run(() => api.kubectl.clusterInfo(t), 'cluster-info')}>Cluster Info</Button>
          <Button type="primary" onClick={() => run(() => api.kubectl.authCanI(t), 'auth can-i')}>Auth Can-I</Button>
        </Space>
      </Card>
      <Card title="自定义命令" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Input placeholder="kubectl command (without 'kubectl')" value={customCmd} onChange={(e) => setCustomCmd(e.target.value)} />
          <Space>
            <Button type="primary" onClick={() => run(() => api.kubectl.exec({ ...t, command: customCmd }), `kubectl ${customCmd}`)}>执行</Button>
            <Button onClick={() => setResult(null)}>清空</Button>
          </Space>
        </Space>
      </Card>
      <Card title="Apply & Delete" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Input.TextArea placeholder="粘贴 YAML (或从持久化/CDK标签页复制)" rows={4} style={{ width: 280, fontSize: 10, fontFamily: 'monospace' }}
              value={applyYaml} onChange={(e) => setApplyYaml(e.target.value)} />
          </Space>
          <Space>
            <Button danger onClick={() => {
              if (!applyYaml) { addLog('[-] 请先粘贴 YAML'); return; }
              run(() => api.kubectl.apply({ ...t, yaml: applyYaml }), 'kubectl apply');
            }}>Apply YAML</Button>
            <Button onClick={() => {
              if (!applyYaml) { addLog('[-] 请先粘贴 YAML'); return; }
              run(() => api.kubectl.del({ ...t, yaml: applyYaml }), 'kubectl delete');
            }}>删除资源</Button>
          </Space>
          <span style={{ fontSize: 10, color: '#888' }}>从持久化或CDK标签页复制YAML，粘贴后点击Apply部署</span>
        </Space>
      </Card>
      <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}>
        <ResultView result={result} loading={loading} emptyHint="点击上方按钮执行 kubectl 命令" />
      </Card>
    </div>
  );
}
