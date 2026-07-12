import React, { useEffect, useState } from 'react';
import { Button, Card, Input, Select, Space, Table, Typography, Spin } from 'antd';
import { api, targetParams, recordTargetStep } from '../services/api';
import ResultView from '../components/ResultView';

interface Props { getAuth: () => import('../services/api').AuthConfig; addLog: (msg: string) => void; activeTarget: string | null; }

interface CmdItem { cmd: string; desc: string; }

export default function InfoTab({ getAuth, addLog, activeTarget }: Props) {
  const [envCmds, setEnvCmds] = useState<CmdItem[]>([]);
  const [privCmds, setPrivCmds] = useState<CmdItem[]>([]);
  const [saCmds, setSaCmds] = useState<CmdItem[]>([]);
  const [portRef, setPortRef] = useState<any[]>([]);
  const [capHex, setCapHex] = useState('');
  const [capResult, setCapResult] = useState<any>(null);
  const [portScanResult, setPortScanResult] = useState<any>(null);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [profileID, setProfileID] = useState('basic');
  const [profileResult, setProfileResult] = useState<any>(null);
  const [capLoading, setCapLoading] = useState(false);
  const [loadingStates, setLoadingStates] = useState<Record<string, boolean>>({});

  const setLoading = (key: string, v: boolean) => setLoadingStates(prev => ({ ...prev, [key]: v }));

  const loadEnv = async () => {
    setLoading('env', true);
    try { const r = await api.info.envCheckCmds(); setEnvCmds(r.commands || []); addLog('已加载环境检测命令'); }
    catch (e) { addLog('[-] 环境检测命令加载失败: ' + e); }
    finally { setLoading('env', false); }
  };
  const loadPriv = async () => {
    setLoading('priv', true);
    try { const r = await api.info.privCheckCmds(); setPrivCmds(r.commands || []); addLog('已加载特权检测命令'); }
    catch (e) { addLog('[-] 特权检测命令加载失败: ' + e); }
    finally { setLoading('priv', false); }
  };
  const loadSA = async () => {
    setLoading('sa', true);
    try { const r = await api.info.saTokenCmds(); setSaCmds(r.commands || []); addLog('已加载SA Token命令'); }
    catch (e) { addLog('[-] SA Token命令加载失败: ' + e); }
    finally { setLoading('sa', false); }
  };
  const loadPortRef = async () => {
    setLoading('port', true);
    try { const r = await api.info.portReference(); setPortRef(r.ports || []); addLog('已加载端口参考'); }
    catch (e) { addLog('[-] 端口参考加载失败: ' + e); }
    finally { setLoading('port', false); }
  };
  const decodeCaps = async () => {
    setCapLoading(true);
    try { const r = await api.info.decodeCaps(capHex); setCapResult(r); addLog(`Capabilities解码: ${capHex}`); }
    catch (e) { setCapResult({ error: String(e) }); addLog('[-] Capabilities解码失败: ' + e); }
    finally { setCapLoading(false); }
  };
  const portScan = async () => {
    setLoading('scan', true);
    try {
      const r = await api.info.portScan({ ...targetParams(getAuth()), host: getAuth().host, timeout_sec: 3 });
      setPortScanResult(r);
      addLog('端口扫描完成');
      recordTargetStep(activeTarget, {
        phase: 'info',
        tool: 'info',
        action: 'Port scan',
        success: !r?.error,
        summary: r?.error ? `Port scan failed: ${r.error}` : 'Port scan completed',
        data: r,
        error: r?.error,
      }).catch(() => {});
    }
    catch (e) {
      setPortScanResult({ error: String(e) }); addLog('[-] 端口扫描失败: ' + e);
      recordTargetStep(activeTarget, {
        phase: 'info',
        tool: 'info',
        action: 'Port scan',
        success: false,
        summary: 'Port scan failed',
        error: String(e),
      }).catch(() => {});
    }
    finally { setLoading('scan', false); }
  };

  useEffect(() => {
    api.info.profiles().then((r: any) => {
      const items = Array.isArray(r) ? r : [];
      setProfiles(items);
      if (items.length > 0 && !items.some((item: any) => item.id === profileID)) setProfileID(items[0].id);
    }).catch((e) => addLog('[-] 评估配置加载失败: ' + e));
  }, []);

  const runProfile = async () => {
    setLoading('profile', true);
    try {
      const r = await api.info.runProfile(profileID, {
        ...targetParams(getAuth()),
        mode: 'remote-k8s',
      });
      setProfileResult(r);
      addLog(r?.error ? `[-] ${profileID} 评估失败: ${r.error}` : `[+] ${profileID} 评估完成`);
      recordTargetStep(activeTarget, {
        phase: 'info', tool: 'info/evaluate', action: `Run ${profileID} profile`,
        success: !r?.error, summary: r?.error ? `Profile failed: ${r.error}` : 'Profile evaluation completed',
        data: r, error: r?.error,
      }).catch(() => {});
    } catch (e) {
      setProfileResult({ error: String(e) });
      addLog('[-] 评估执行失败: ' + e);
    } finally { setLoading('profile', false); }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      <Card title="环境检测" size="small" extra={<Button onClick={loadEnv} size="small" loading={loadingStates['env']}>加载</Button>}>
        {loadingStates['env'] ? <div style={{ textAlign: 'center', padding: 16 }}><Spin size="small" /></div> :
          envCmds.map((c, i) => (
            <div key={i} style={{ marginBottom: 6 }}>
              <Typography.Text code style={{ fontSize: 11 }}>{c.cmd}</Typography.Text>
              <br/><Typography.Text style={{ fontSize: 11, color: '#666' }}>{c.desc}</Typography.Text>
            </div>
          ))}
      </Card>
      <Card title="Capabilities解码" size="small">
        <Space style={{ marginBottom: 8 }}>
          <Input placeholder="CapEff hex值" value={capHex} onChange={e => setCapHex(e.target.value)} style={{ width: 220 }} />
          <Button onClick={decodeCaps} size="small" loading={capLoading}>解码</Button>
        </Space>
        <ResultView result={capResult} loading={capLoading} emptyHint="输入 /proc/1/status 中的 CapEff hex 值进行解码" />
      </Card>
      <Card title="特权检测" size="small" extra={<Button onClick={loadPriv} size="small" loading={loadingStates['priv']}>加载</Button>}>
        {loadingStates['priv'] ? <div style={{ textAlign: 'center', padding: 16 }}><Spin size="small" /></div> :
          privCmds.map((c, i) => (
            <div key={i} style={{ marginBottom: 6 }}>
              <Typography.Text code style={{ fontSize: 11 }}>{c.cmd}</Typography.Text>
              <br/><Typography.Text style={{ fontSize: 11, color: '#666' }}>{c.desc}</Typography.Text>
            </div>
          ))}
      </Card>
      <Card title="SA Token 命令" size="small" extra={<Button onClick={loadSA} size="small" loading={loadingStates['sa']}>加载</Button>}>
        {loadingStates['sa'] ? <div style={{ textAlign: 'center', padding: 16 }}><Spin size="small" /></div> :
          saCmds.map((c, i) => (
            <div key={i} style={{ marginBottom: 6 }}>
              <Typography.Text code style={{ fontSize: 11 }}>{c.cmd}</Typography.Text>
              <br/><Typography.Text style={{ fontSize: 11, color: '#666' }}>{c.desc}</Typography.Text>
            </div>
          ))}
      </Card>
      <Card title="端口参考" size="small" extra={<Button onClick={loadPortRef} size="small" loading={loadingStates['port']}>加载</Button>}>
        {loadingStates['port'] ? <div style={{ textAlign: 'center', padding: 16 }}><Spin size="small" /></div> :
          <Table dataSource={portRef.map((p: any, i: number) => ({ ...p, _key: i }))}
            columns={[
              { title: '端口', dataIndex: 'port', key: 'port', width: 80 },
              { title: '服务', dataIndex: 'service', key: 'service', width: 120 },
              { title: '描述', dataIndex: 'desc', key: 'desc' },
            ]} size="small" pagination={false} rowKey="_key" />}
      </Card>
      <Card title="端口扫描" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Button onClick={portScan} loading={loadingStates['scan']}>扫描 {getAuth().host} 常用端口</Button>
          <Typography.Text style={{ fontSize: 10, color: '#888' }}>使用配置的目标地址进行端口扫描</Typography.Text>
          <ResultView result={portScanResult} emptyHint="执行端口扫描查看结果" />
        </Space>
      </Card>
      <Card title="目标评估" size="small">
        <Space direction="vertical" style={{ width: '100%' }}>
          <Space>
            <Select value={profileID} onChange={setProfileID} style={{ width: 180 }}
              options={profiles.map((profile: any) => ({ value: profile.id, label: `${profile.name} (${profile.checks})` }))} />
            <Button onClick={runProfile} loading={loadingStates['profile']} disabled={!profileID}>运行评估</Button>
          </Space>
          <Typography.Text style={{ fontSize: 10, color: '#888' }}>
            此模式从控制端检查目标 API、Kubelet 与 Etcd 暴露面；容器本地检查会明确标记为跳过。
          </Typography.Text>
          <ResultView result={profileResult} loading={loadingStates['profile']} emptyHint="选择评估配置并运行" />
        </Space>
      </Card>
    </div>
  );
}
