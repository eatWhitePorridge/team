import { useState } from 'react';
import { Button, Card, Dropdown, Input, Space, Table, Tooltip, Typography } from 'antd';
import { DownOutlined, ReloadOutlined } from '@ant-design/icons';
import { IndexNotice, RequestError } from '../components';
import { useResource } from '../hooks';
import type { Batch, Page } from '../types';
import TeamOperationModal from '../TeamOperationModal';
export default function Batches({ onJobsChanged, onViewAccounts }: { onJobsChanged: () => void; onViewAccounts: (batchId: string) => void }) {
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [operation, setOperation] = useState<{ kind: 'switch' | 'remove'; batch_id: string }>();
  const data = useResource<Page<Batch>>('/api/batches', { q: query, page, page_size: 50 }, 6000);
  return <><Card className="data-card">
    <RequestError value={data.error} /><IndexNotice value={data.data?.index} />
    <div className="table-toolbar"><div className="toolbar-controls">
      <Input.Search aria-label="搜索批次 ID" className="search-control" placeholder="搜索批次 ID" allowClear onSearch={(q) => { setQuery(q); setPage(1); }} />
    </div><Tooltip title="刷新列表"><Button aria-label="刷新批次列表" icon={<ReloadOutlined />} onClick={data.reload} loading={data.loading} /></Tooltip></div>
    <Table<Batch> size="middle" rowKey="batch_id" dataSource={data.data?.items || []} loading={data.loading && !data.data} scroll={{ x: 690, y: 'max(280px, calc(100dvh - 310px))' }}
      columns={[{ title: '批次', dataIndex: 'batch_id', width: 190, render: (value: string) => <Tooltip title={value}><Typography.Text copyable={{ text: value }}>{value.slice(0, 8)}</Typography.Text></Tooltip> }, { title: '账号数', dataIndex: 'account_total', width: 90 }, { title: '导入时间', dataIndex: 'created_at', width: 190 }, { title: '操作', width: 200, render: (_, row) => <Space size={4}><Button type="link" size="small" onClick={() => onViewAccounts(row.batch_id)}>查看账号</Button><Dropdown trigger={['click']} menu={{ items: [
        { key: 'switch', label: '切换席位', onClick: () => setOperation({ kind: 'switch', batch_id: row.batch_id }) },
        { key: 'remove', label: '移出 Team', danger: true, onClick: () => setOperation({ kind: 'remove', batch_id: row.batch_id }) },
      ] }}><Button type="text" size="small">更多 <DownOutlined /></Button></Dropdown></Space> }]}
      pagination={{ current: data.data?.page || page, pageSize: 50, total: data.data?.total || 0, showTotal: (total) => '共 ' + total + ' 个批次', showSizeChanger: false, onChange: setPage }} />
  </Card>{operation && <TeamOperationModal kind={operation.kind} scope={{ batch_id: operation.batch_id }} onClose={() => setOperation(undefined)} onSubmitted={() => { onJobsChanged(); data.reload(); }} />}</>;
}
