import React from 'react';
import { Button, List, Popconfirm, Space, Typography } from 'antd';
import { ClearOutlined, DeleteOutlined } from '@ant-design/icons';
import { Target } from '../services/api';

interface Props {
  targets: Target[];
  active: string | null;
  onSelect: (target: Target) => void;
  onDelete: (target: Target) => void;
  onClearAll: () => void;
}

export default function TargetPanel({ targets, active, onSelect, onDelete, onClearAll }: Props) {
  const authLabel = (t: Target) => {
    if (t.auth_type === 'token' || t.token) return `🔑 ${t.token ? 'token' : '无token'}`;
    if (t.auth_type === 'userpass' || t.username) return `👤 ${t.username || '?'}`;
    if (t.auth_type === 'none') return '⚠️ 匿名';
    return '🔓 未认证';
  };
  return (
    <div style={{ padding: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <Typography.Text style={{ color: '#fff', fontSize: 12 }}>Saved Targets ({targets.length})</Typography.Text>
        <Popconfirm
          title="清空全部目标"
          description="会删除当前保存的所有 targets。"
          okText="清空"
          cancelText="取消"
          disabled={targets.length === 0}
          onConfirm={onClearAll}
        >
          <Button
            size="small"
            type="text"
            disabled={targets.length === 0}
            icon={<ClearOutlined style={{ color: targets.length === 0 ? '#666' : '#fff' }} />}
          />
        </Popconfirm>
      </div>
      <List
        size="small"
        dataSource={targets}
        renderItem={(t) => (
          <List.Item
            style={{ padding: '4px 8px', background: active === t.id ? '#1890ff' : 'transparent', borderRadius: 4 }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', gap: 8 }}>
              <div style={{ cursor: 'pointer', flex: 1, minWidth: 0 }} onClick={() => onSelect(t)}>
                <Typography.Text style={{ color: '#fff', fontSize: 12 }}>{t.host}:{t.port}</Typography.Text>
                <br /><Typography.Text style={{ color: '#aaa', fontSize: 10 }}>{authLabel(t)}</Typography.Text>
              </div>
              <Space size={4}>
                <Popconfirm
                  title="删除目标"
                  description={`确认删除 ${t.host}:${t.port} 吗？`}
                  okText="删除"
                  cancelText="取消"
                  onConfirm={() => onDelete(t)}
                >
                  <Button size="small" type="text" icon={<DeleteOutlined style={{ color: '#fff' }} />} />
                </Popconfirm>
              </Space>
            </div>
          </List.Item>
        )}
      />
    </div>
  );
}
