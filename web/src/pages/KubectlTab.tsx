import React, { useState } from 'react';
import { Button, Card, Input, Space, Select, Tag, Typography } from 'antd';
import { api, targetParams, recordTargetStep, PodListSource, PodRecord, PodSelection } from '../services/api';
import ResultView from '../components/ResultView';

const { Text } = Typography;

interface Props {
  getAuth: () => import('../services/api').AuthConfig;
  addLog: (msg: string) => void;
  activeTarget: string | null;
  sharedPods: PodRecord[];
  sharedPodSource: PodListSource | null;
  sharedPodSelection: PodSelection | null;
  onUpdateSharedPods: (pods: PodRecord[], source: PodListSource, options?: { namespaceFilter?: string; autoSelectFirst?: boolean }) => void;
  onSelectSharedPod: (selection: PodSelection | null) => void;
}

export default function KubectlTab({ getAuth, addLog, activeTarget, sharedPods, sharedPodSource, sharedPodSelection, onUpdateSharedPods, onSelectSharedPod }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [customCmd, setCustomCmd] = useState('get namespaces');
  const [applyYaml, setApplyYaml] = useState('');

  const run = async (fn: () => Promise<any>, label: string, sharePodsSource?: PodListSource) => {
    setLoading(true); setResult(null);
    try {
      const r = await fn();
      setResult(r);
      if (sharePodsSource && Array.isArray(r?.pods)) {
        onUpdateSharedPods(r.pods, sharePodsSource, { autoSelectFirst: !sharedPodSelection });
      }
      addLog(r?.error ? `[-] ${label} failed: ${r.error}` : `[+] ${label}`);
      recordTargetStep(activeTarget, {
        phase: 'kubectl',
        tool: 'kubectl',
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
        phase: 'kubectl',
        tool: 'kubectl',
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
      <Card title="资源枚举" size="small">
        <Space wrap>
          <Button onClick={() => run(() => api.kubectl.getPods(t), 'get pods', 'kubectl')}>Get Pods</Button>
          <Button onClick={() => run(() => api.kubectl.getNodes(t), 'get nodes')}>Get Nodes</Button>
          <Button onClick={() => run(() => api.kubectl.getServices(t), 'get services')}>Get Services</Button>
          <Button onClick={() => run(() => api.kubectl.getDeployments(t), 'get deployments')}>Get Deployments</Button>
          <Button danger onClick={() => run(() => api.kubectl.getSecrets(t), 'get secrets')}>Get Secrets</Button>
          <Button onClick={() => run(() => api.kubectl.getSA(t), 'get sa')}>Get SA</Button>
          <Button onClick={() => run(() => api.kubectl.getCRB(t), 'get crb')}>Get CRB</Button>
          <Button onClick={() => run(() => api.kubectl.getImages(t), 'get images')}>Get Images</Button>
        </Space>
      </Card>
      <Card title="共享 Pod 上下文" size="small">
        <Space direction="vertical" style={{ width: '100%' }} size={6}>
          <Text type="secondary" style={{ fontSize: 11 }}>
            {sharedPods.length > 0
              ? `当前已缓存 ${sharedPods.length} 个 Pod（来源: ${sharedPodSourceLabel}）。这里切的当前 Pod，会同步给初始访问和命令执行面板。`
              : '当前还没有共享 Pod 缓存。点一次 Get Pods，其他面板就能直接复用。'}
          </Text>
          {sharedPodSelection && (
            <Tag color="blue" style={{ width: 'fit-content' }}>
              当前 Pod: {sharedPodSelection.namespace}/{sharedPodSelection.name}
            </Tag>
          )}
          {sharedPods.length > 0 && (
            <Select
              allowClear
              showSearch
              value={sharedPodValue}
              placeholder="选择一个当前 Pod"
              optionFilterProp="label"
              style={{ width: '100%' }}
              onClear={() => onSelectSharedPod(null)}
              onChange={(value: string, option: any) => {
                const parts = value.split('/'); const namespace = parts.length > 1 ? parts[0] : 'default'; const podName = parts.length > 1 ? parts[1] : parts[0];
                onSelectSharedPod({ namespace, name: podName, container: option?.container || undefined });
              }}
              options={sharedPods.map((item) => ({
                value: `${item.namespace}/${item.name}`,
                label: `${item.namespace}/${item.name}`,
                container: item.containers?.split(',').map((entry) => entry.trim()).filter(Boolean)[0],
              }))}
            />
          )}
        </Space>
      </Card>
      <Card title="集群信息 & 权限" size="small">
        <Space wrap>
          <Button onClick={() => run(() => api.kubectl.clusterInfo(t), 'cluster-info')}>Cluster Info</Button>
          <Button type="primary" onClick={() => run(() => api.kubectl.authCanI(t), 'auth can-i')}>Auth Can-I</Button>
          <Button onClick={() => setResult(null)}>清除输出</Button>
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
