import React from 'react';
import { List, Typography } from 'antd';
import { Target } from '../services/api';

interface Props {
  targets: Target[];
  active: string | null;
  onSelect: (target: Target) => void;
}

export default function TargetPanel({ targets, active, onSelect }: Props) {
  const authLabel = (t: Target) => {
    if (t.auth_type === 'token' || t.token) return `🔑 ${t.token ? 'token' : '无token'}`;
    if (t.auth_type === 'userpass' || t.username) return `👤 ${t.username || '?'}`;
    if (t.auth_type === 'none') return '⚠️ 匿名';
    return '🔓 未认证';
  };
  return (
    <div style={{ padding: 12 }}>
      <Typography.Text style={{ color: '#fff', fontSize: 12 }}>Saved Targets ({targets.length})</Typography.Text>
      <List
        size="small"
        dataSource={targets}
        renderItem={(t) => (
          <List.Item style={{ cursor: 'pointer', padding: '4px 8px', background: active === t.id ? '#1890ff' : 'transparent', borderRadius: 4 }}
            onClick={() => onSelect(t)}>
            <div>
              <Typography.Text style={{ color: '#fff', fontSize: 12 }}>{t.host}:{t.port}</Typography.Text>
              <br/><Typography.Text style={{ color: '#aaa', fontSize: 10 }}>{authLabel(t)}</Typography.Text>
            </div>
          </List.Item>
        )}
      />
    </div>
  );
}
