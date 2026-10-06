import { parentBillingView } from './parentBillingSummary';
import type { Parent } from './types';

export default function ParentBilling({ parent }: { parent: Parent }) {
  const view = parentBillingView(parent);
  return <span className="parent-billing" title={view.details || undefined}>
    <span className="parent-billing-label">{view.label}{view.time.state === 'valid' ? ' · 北京时间' : view.time.state === 'date_only' ? ' · 时区未提供' : ''}</span>
    <span className="parent-billing-value">
      {view.time.state === 'valid' ? <time className="tabular" dateTime={view.time.iso}>{view.time.text}</time> : <span>{view.text}</span>}
      {view.note && <span className="parent-billing-note">{view.note}</span>}
    </span>
  </span>;
}
