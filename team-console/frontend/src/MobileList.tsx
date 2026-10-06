import type { Key, ReactNode } from 'react';
import { useRef } from 'react';
import { Checkbox, Empty, Pagination, Select, Spin } from 'antd';
import { pageNumber, pageSelection, selectPage, toggleSelection } from './responsive';

export interface MobilePagination {
  page: number; pageSize: number; total: number;
  onChange: (page: number, pageSize: number) => void; pageSizeOptions?: number[];
}

export default function MobileList<T>({ rows, rowKey, label, renderItem, loading = false, selection, pagination }: {
  rows: T[]; rowKey: (row: T) => Key; label: (row: T) => string; renderItem: (row: T) => ReactNode;
  loading?: boolean;
  selection?: { keys: Key[]; onChange: (keys: Key[]) => void; disabled?: boolean };
  pagination?: MobilePagination;
}) {
  const listRef = useRef<HTMLDivElement>(null);
  const pageKeys = rows.map(rowKey);
  const chosen = new Set(selection?.keys || []);
  const changePage = (page: number, size: number) => {
    pagination?.onChange(page, size);
    // Only explicit pagination scrolls; background polling never moves the page.
    listRef.current?.scrollIntoView({ block: 'start', behavior: 'instant' });
  };
  return <div ref={listRef} className={'mobile-list' + (selection?.keys.length ? ' has-selection' : '')}>
    {selection && <div className="mobile-list-meta"><Checkbox {...pageSelection(selection.keys, pageKeys)} disabled={selection.disabled || loading || !rows.length}
      onChange={event => selection.onChange(selectPage(selection.keys, pageKeys, event.target.checked))}>全选本页</Checkbox><span>{rows.length} 条</span></div>}
    <Spin spinning={loading}><div className="mobile-records" aria-busy={loading}>
      {rows.map(row => <article className={'mobile-record ' + (chosen.has(rowKey(row)) ? 'is-selected' : '')} key={rowKey(row)}>
        {selection && <Checkbox className="mobile-record-check" aria-label={'选择 ' + label(row)} checked={chosen.has(rowKey(row))} disabled={selection.disabled || loading}
          onChange={event => selection.onChange(toggleSelection(selection.keys, rowKey(row), event.target.checked))} />}
        <div className="mobile-record-main">{renderItem(row)}</div>
      </article>)}
      {!rows.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={loading ? '正在加载…' : '暂无记录'} />}
    </div></Spin>
    {pagination && <div className="mobile-pagination">
      <div className="mobile-pagination-meta"><span>共 {pagination.total} 条</span>{pagination.pageSizeOptions && <Select aria-label="每页显示条数" value={pagination.pageSize}
        options={pagination.pageSizeOptions.map(value => ({ value, label: value + ' 条 / 页' }))} onChange={size => changePage(1, size)} />}</div>
      <Pagination simple={{ readOnly: true }} current={pageNumber(pagination.page, pagination.total, pagination.pageSize)} pageSize={pagination.pageSize}
        total={pagination.total} showSizeChanger={false} onChange={changePage} />
    </div>}
  </div>;
}
