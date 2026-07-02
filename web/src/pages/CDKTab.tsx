import React, { useEffect, useMemo, useState } from 'react';
import { Button, Card, Input, Space, Select, Typography, Divider, Popconfirm } from 'antd';
import { RocketOutlined, SearchOutlined, KeyOutlined, ApiOutlined, BugOutlined, ContainerOutlined } from '@ant-design/icons';
import { api, targetParams, recordTargetStep, PodListSource, PodRecord, PodSelection } from '../services/api';
import ResultView from '../components/ResultView';

const { Text, Paragraph } = Typography;

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

export default function CDKTab({ getAuth, addLog, activeTarget, sharedPods, sharedPodSource, sharedPodSelection, onUpdateSharedPods, onSelectSharedPod }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [escapeMode, setEscapeMode] = useState('privileged');
  const [escapeNs, setEscapeNs] = useState('default');
  const [escapeNode, setEscapeNode] = useState('');
  const [escapeCmd, setEscapeCmd] = useState('');
  const [lhost, setLhost] = useState('');
  const [lport, setLport] = useState(4444);
  const [mitmIP, setMitmIP] = useState('');
  const [mitmPort, setMitmPort] = useState(443);
  const [evalNs, setEvalNs] = useState('');
  const [evalPod, setEvalPod] = useState('');
  const [evalPods, setEvalPods] = useState<any[]>([]);
  const [evalPodsLoading, setEvalPodsLoading] = useState(false);

  useEffect(() => {
    if (!sharedPodSelection) return;
    setEvalNs(sharedPodSelection.namespace || 'default');
    setEvalPod(sharedPodSelection.name || '');
  }, [sharedPodSelection?.namespace, sharedPodSelection?.name, activeTarget]);

  const run = async (fn: () => Promise<any>, label: string, phase: 'info' | 'access' | 'escape' | 'persist' | 'lateral' = 'escape') => {
    setLoading(true); setResult(null);
    try { const r = await fn(); setResult(r); addLog(r?.error ? `[CDK] ${label} failed: ${r.error}` : `[CDK] ${label}`);
      recordTargetStep(activeTarget, { phase, tool: 'cdk', action: label, success: !r?.error, summary: r?.error ? `${label} failed: ${r.error}` : `${label} completed`, data: r, output: r?.output || r?.yaml, error: r?.error }).catch(() => {}); }
    catch (e) { setResult({ error: String(e) }); addLog(`[CDK] ${label} failed`);
      recordTargetStep(activeTarget, { phase, tool: 'cdk', action: label, success: false, summary: `${label} failed`, error: String(e) }).catch(() => {}); }
    finally { setLoading(false); }
  };
  const t = targetParams(getAuth());
  const em = [{ value: 'privileged', label: '🔴 特权容器逃逸 (cgroup/mount)', desc: '部署特权Pod，挂载宿主机根目录，利用cgroup release_agent或直接挂载磁盘逃逸' }, { value: 'docker-sock', label: '🟠 Docker Socket 逃逸', desc: '挂载docker.sock，通过Docker API创建特权容器逃逸' }, { value: 'host-proc', label: '🟡 core_pattern 逃逸', desc: '挂载宿主机/proc，覆写core_pattern实现命令执行' }, { value: 'cap-dac', label: '🟢 CAP_DAC_READ_SEARCH', desc: '利用capability绕过文件权限，读取宿主机敏感文件' }, { value: 'kubelet-log', label: '🔵 Kubelet /var/log 逃逸', desc: '利用/var/log挂载创建符号链接，通过kubelet读取任意文件' }];

  const loadEvalPods = async () => {
    setEvalPodsLoading(true);
    try {
      const r = await api.exec.apiListPods({ ...t, namespace: evalNs });
      const pods = Array.isArray(r?.pods) ? r.pods : [];
      setEvalPods(pods);
      onUpdateSharedPods(pods, r?.source === 'kubelet' ? 'kubelet' : 'api-server', {
        namespaceFilter: evalNs || '',
        autoSelectFirst: !sharedPodSelection,
      });
      const currentNamespace = sharedPodSelection?.namespace || evalNs || 'default';
      const currentName = sharedPodSelection?.name || evalPod;
      const currentExists = pods.some((p: any) => p.name === currentName && (p.namespace || 'default') === currentNamespace);
      if (pods.length === 0) {
        setEvalPod('');
      } else if (!currentExists) {
        setEvalPod(pods[0].name);
        setEvalNs(pods[0].namespace || evalNs);
        onSelectSharedPod({
          namespace: pods[0].namespace || 'default',
          name: pods[0].name,
          container: pods[0].containers?.split(',').map((entry: string) => entry.trim()).filter(Boolean)[0] || undefined,
        });
      }
      addLog(`[CDK] loaded ${pods.length} pods for evaluate`);
    } catch (e) {
      setEvalPods([]);
      addLog(`[CDK] load evaluate pods failed: ${e}`);
    } finally {
      setEvalPodsLoading(false);
    }
  };

  const sharedPodSourceLabel = sharedPodSource === 'kubelet' ? 'Kubelet' : sharedPodSource === 'kubectl' ? 'kubectl' : 'API Server';
  const availableEvalPods = useMemo(() => {
    const sourcePods = evalPods.length > 0 ? evalPods : sharedPods;
    const namespaceFilter = evalNs.trim();
    return sourcePods.filter((item: any) => !namespaceFilter || (item.namespace || 'default') === namespaceFilter);
  }, [evalPods, sharedPods, evalNs]);
  const evalSelectValue = evalPod ? `${evalNs || sharedPodSelection?.namespace || 'default'}/${evalPod}` : undefined;
  const selectedEvalContainer = useMemo(() => {
    const targetNamespace = evalNs || sharedPodSelection?.namespace || 'default';
    if (sharedPodSelection?.name === evalPod && (sharedPodSelection.namespace || 'default') === targetNamespace) {
      return sharedPodSelection.container || '';
    }
    const matchedPod = availableEvalPods.find((item: any) => item.name === evalPod && (item.namespace || 'default') === targetNamespace);
    return matchedPod?.containers?.split(',').map((entry: string) => entry.trim()).filter(Boolean)[0] || '';
  }, [availableEvalPods, evalNs, evalPod, sharedPodSelection?.container, sharedPodSelection?.name, sharedPodSelection?.namespace]);

  return (<div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
    <Card title={<span><KeyOutlined /> 凭据获取</span>} size="small"><Space direction="vertical" style={{ width: '100%' }}>
      <Button icon={<SearchOutlined />} onClick={() => run(() => api.cdk.configmaps(t), 'Dump ConfigMaps', 'access')}>Dump ConfigMaps (全集群)</Button>
      <Text type="secondary" style={{ fontSize: 10 }}>列出所有命名空间的 ConfigMap，发现可能的凭据泄露</Text>
      <Divider style={{ margin: '4px 0' }} />
      <Button icon={<ApiOutlined />} onClick={() => run(() => api.cdk.dockerAPI(t), 'Check Docker API', 'access')}>检测 Docker Remote API (2375/2376)</Button>
      <Text type="secondary" style={{ fontSize: 10 }}>检测目标是否暴露未授权的 Docker Remote API，包括 2376 TLS 场景</Text>
      <Divider style={{ margin: '4px 0' }} />
      <Button icon={<SearchOutlined />} onClick={() => run(() => api.cdk.servicesScan(t), 'Internal services scan', 'info')}>集群内网服务发现</Button>
      <Text type="secondary" style={{ fontSize: 10 }}>扫描所有Service并自动分类：DNS / Dashboard / 监控 / 服务网格 / Ingress / Etcd</Text>
    </Space></Card>

    <Card title={<span><SearchOutlined /> 信息发现</span>} size="small"><Space direction="vertical" style={{ width: '100%' }}>
      <Button onClick={() => run(() => api.cdk.psp(t), 'Dump PSP', 'info')}>Dump PodSecurityPolicies</Button>
      <Text type="secondary" style={{ fontSize: 10 }}>列出所有 PSP 规则，识别允许特权/主机网络的策略（K8s &lt;1.25）</Text>
      <Divider style={{ margin: '4px 0' }} />
      <Button icon={<BugOutlined />} onClick={() => run(() => api.cdk.shadowAPIServer(t), 'Shadow API Server check', 'access')}>检测 Shadow API Server 可行性</Button>
      <Text type="secondary" style={{ fontSize: 10 }}>分析 kube-apiserver 配置，评估是否可以部署影子 API Server</Text>
      <Divider style={{ margin: '4px 0' }} />
      <Button icon={<ContainerOutlined />} onClick={() => run(() => api.cdk.assessEscape(t), 'Assess escape surface', 'escape')}>评估逃逸面</Button>
      <Text type="secondary" style={{ fontSize: 10 }}>批量评估全局 Pod 的特权、主机命名空间、hostPath、docker.sock 等逃逸面</Text>
      <Divider style={{ margin: '4px 0' }} />
      {sharedPods.length > 0 && (
        <Text type="secondary" style={{ fontSize: 10 }}>
          当前共享缓存里有 {sharedPods.length} 个 Pod（来源: {sharedPodSourceLabel}）。你在命令执行 / kubectl 里选中的 Pod，这里会直接复用。
        </Text>
      )}
      <Space wrap>
        <Input placeholder="评估命名空间 (留空=全部)" value={evalNs} onChange={(e) => setEvalNs(e.target.value)} style={{ width: 160 }} />
        <Button loading={evalPodsLoading} onClick={loadEvalPods}>列出 Pod</Button>
      </Space>
      {availableEvalPods.length > 0 && (
        <Select
          showSearch
          allowClear
          value={evalSelectValue}
          onClear={() => {
            setEvalPod('');
            onSelectSharedPod(null);
          }}
          onChange={(value: string, option: any) => {
            const parts = value.split('/'); const namespace = parts.length > 1 ? parts[0] : 'default'; const podName = parts.length > 1 ? parts[1] : parts[0];
            setEvalPod(podName);
            setEvalNs(option.namespace || namespace);
            onSelectSharedPod({ namespace: option.namespace || namespace, name: podName, container: option?.container || undefined });
          }}
          style={{ width: '100%' }}
          placeholder="选择一个 Pod 进行 CDK Evaluate"
          optionFilterProp="label"
          options={availableEvalPods.map((p: any) => ({
            value: `${p.namespace}/${p.name}`,
            label: `${p.namespace}/${p.name}`,
            namespace: p.namespace,
            container: p.containers?.split(',').map((entry: string) => entry.trim()).filter(Boolean)[0],
          }))}
        />
      )}
      <Button disabled={!evalPod} onClick={() => {
        const targetNs = sharedPodSelection?.namespace || evalNs || 'default';
        const targetContainer = selectedEvalContainer || undefined;
        onSelectSharedPod({ namespace: targetNs, name: evalPod, container: targetContainer });
        run(() => api.cdk.evaluatePod({
          ...t,
          namespace: targetNs,
          pod_name: evalPod,
          container_name: targetContainer,
        }), 'Evaluate pod', 'info');
      }}>Evaluate Pod (CDK)</Button>
      <Text type="secondary" style={{ fontSize: 10 }}>在选中的 Pod 内执行 CDK evaluate，自动检查 seccomp、docker.sock、hostPath、敏感文件与 SA Token。</Text>
    </Space></Card>

    <Card title={<span><RocketOutlined /> 持久化 & 横向移动</span>} size="small"><Space direction="vertical" style={{ width: '100%' }}>
      <Space><Input placeholder="被劫持目标IP (默认1.1.1.1)" value={mitmIP} onChange={(e) => setMitmIP(e.target.value)} style={{ width: 160 }} /><Input placeholder="端口" value={mitmPort} onChange={(e) => setMitmPort(+e.target.value)} style={{ width: 70 }} /></Space>
      <Button danger onClick={() => run(() => api.cdk.clusterIPMITM({ ...t, victim_ip: mitmIP || '1.1.1.1', target_ip: mitmIP || '1.1.1.1', target_port: mitmPort }), 'CVE-2020-8554 MITM', 'lateral')}>生成 CVE-2020-8554 MITM YAML</Button>
      <Text type="secondary" style={{ fontSize: 10 }}>CVE-2020-8554: 通过声明受害目标的 ExternalIP，把发往该 IP 的流量重定向到攻击者后端 Pod</Text>
    </Space></Card>

    <Card title={<span><ContainerOutlined /> 逃逸 Pod 生成器 + 自动逃逸</span>} size="small" style={{ border: '2px solid #ff4d4f' }}><Space direction="vertical" style={{ width: '100%' }}>
      <Select value={escapeMode} onChange={setEscapeMode} style={{ width: '100%' }} options={em.map(m => ({ value: m.value, label: m.label }))} />
      <Text type="secondary" style={{ fontSize: 10 }}>{em.find(m => m.value === escapeMode)?.desc}</Text>
      <Space><Input placeholder="命名空间" value={escapeNs} onChange={(e) => setEscapeNs(e.target.value)} style={{ width: 100 }} /><Input placeholder="目标节点(可选)" value={escapeNode} onChange={(e) => setEscapeNode(e.target.value)} style={{ width: 140 }} /></Space>
      <Input placeholder="自定义命令(可选, 默认读取宿主机shadow)" value={escapeCmd} onChange={(e) => setEscapeCmd(e.target.value)} />
      <Button type="primary" danger icon={<BugOutlined />} onClick={() => run(() => api.cdk.escapePod({ ...t, escape_mode: escapeMode, namespace: escapeNs, node_name: escapeNode, command: escapeCmd }), `Generate ${escapeMode} escape pod`, 'escape')}>生成逃逸 Pod YAML</Button>
      <Divider style={{ margin: '2px 0' }} />
      <Text strong style={{ fontSize: 11, color: '#ff4d4f' }}>CDK Auto-Escape</Text>
      <Space><Input placeholder="反弹LHOST" value={lhost} onChange={(e) => setLhost(e.target.value)} style={{ width: 120 }} /><Input placeholder="LPORT" value={lport} onChange={(e) => setLport(+e.target.value)} style={{ width: 70 }} /></Space>
      <Space>
        <Button danger onClick={() => run(() => api.cdk.autoEscape({ ...t, dry_run: true }), 'Auto-escape dry run', 'escape')}>Dry Run</Button>
        <Popconfirm title="确认一键自动逃逸" description="将选择最优逃逸Pod并执行逃逸命令" okText="确认执行" cancelText="取消" onConfirm={() => run(() => api.cdk.autoEscape({ ...t, dry_run: false, lhost: lhost || undefined, lport: String(lport || 4444) }), 'Auto-escape', 'escape')}><Button danger type="primary">一键自动逃逸</Button></Popconfirm>
      </Space>
      <Text type="secondary" style={{ fontSize: 10 }}>Dry Run扫描全部Pod评估最佳逃逸路径。一键逃逸自动执行chroot/cgroup/docker.sock逃逸</Text>
    </Space></Card>

    <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}><ResultView result={result} loading={loading} emptyHint="选择上方 CDK 战术进行攻击" /></Card>
  </div>);
}
