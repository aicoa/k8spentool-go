import React, { useState } from 'react';
import { Button, Card, Input, Space, Select } from 'antd';
import { api, targetParams } from '../services/api';
import ResultView from '../components/ResultView';

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; }

export default function AccessTab({ getAuth, addLog }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [customPath, setCustomPath] = useState('/api/v1/namespaces/default/secrets');
  const [customMethod, setCustomMethod] = useState('GET');
  const [kubeletNs, setKubeletNs] = useState('default');
  const [kubeletPod, setKubeletPod] = useState('');
  const [kubeletCmd, setKubeletCmd] = useState('id');
  const [etcdKey, setEtcdKey] = useState('/registry/secrets/default');

  const run = async (fn: () => Promise<any>, label: string) => {
    setLoading(true); setResult(null);
    try { const r = await fn(); setResult(r); addLog(`[+] ${label} succeeded`); }
    catch (e) { setResult({ error: String(e) }); addLog(`[-] ${label} failed`); }
    finally { setLoading(false); }
  };

  const t = targetParams(getAuth());

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      <Card title="API服务器访问" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Button danger onClick={() => run(() => api.access.apiServer(t), 'API 服务器 check')}>检测6443</Button>
            <Button onClick={() => run(() => api.access.apiServerInsecure(t), 'Insecure port')}>检测8080</Button>
          </Space>
          <Space style={{ width: '100%' }}>
            <Input placeholder="自定义路径" value={customPath} onChange={(e) => setCustomPath(e.target.value)} style={{ flex: 1 }} />
            <Select value={customMethod} onChange={setCustomMethod} style={{ width: 90 }}
              options={['GET','POST','PUT','DELETE'].map(m => ({ value: m, label: m }))} />
            <Button type="primary" onClick={() => run(() => api.access.apiServerRequest({ ...t, path: customPath, method: customMethod }), '自定义请求')}>发送</Button>
          </Space>
        </Space>
      </Card>
      <Card title="Kubelet访问(10250)" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button danger onClick={() => run(() => api.access.kubelet(t), 'Kubelet check')}>检测Kubelet</Button>
          <Space>
            <Input placeholder="命名空间" value={kubeletNs} onChange={(e) => setKubeletNs(e.target.value)} style={{ width: 100 }} />
            <Input placeholder="Pod name" value={kubeletPod} onChange={(e) => setKubeletPod(e.target.value)} style={{ width: 150 }} />
            <Input placeholder="命令" value={kubeletCmd} onChange={(e) => setKubeletCmd(e.target.value)} style={{ width: 150 }} />
            <Button onClick={() => run(() => api.access.kubeletExec({ ...t, namespace: kubeletNs, pod_name: kubeletPod, command: kubeletCmd }), 'Kubelet exec')}>执行</Button>
          </Space>
        </Space>
      </Card>
      <Card title="Etcd访问(2379)" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button danger onClick={() => run(() => api.access.etcdCheck(t), 'Etcd check')}>检测Etcd</Button>
          <Button onClick={() => run(() => api.access.etcdKeys(t), 'Etcd keys')}>列出Key</Button>
          <Space>
            <Input placeholder="Key路径" value={etcdKey} onChange={(e) => setEtcdKey(e.target.value)} style={{ width: 250 }} />
            <Button onClick={() => run(() => api.access.etcdRead({ ...t, key: etcdKey }), 'Etcd read key')}>读取</Button>
          </Space>
        </Space>
      </Card>
      <Card title="Dashboard与Kubeconfig" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button onClick={() => run(() => api.access.dashboard(t), 'Dashboard check')}>检测Dashboard</Button>
          <Button onClick={() => {
            const kc = prompt('粘贴 Kubeconfig 内容:');
            if (kc) run(() => api.access.kubeconfigParse(kc), 'Kubeconfig parse');
          }}>解析Kubeconfig</Button>
        </Space>
      </Card>
      <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}>
        <ResultView result={result} loading={loading} emptyHint="点击上方按钮执行访问检测" />
      </Card>
    </div>
  );
}
