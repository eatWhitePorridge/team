import type { ReactNode } from 'react';

export function Brand({ compact = false }: { compact?: boolean }) {
  return <div className="brand"><span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M2 4a2 2 0 0 1 2-2h5v20H4a2 2 0 0 1-2-2V4Zm10-2h8a2 2 0 0 1 2 2v5H12V2Zm0 10h10v8a2 2 0 0 1-2 2h-8V12Z" /></svg></span>{!compact && <span className="brand-wordmark">Team<span>Console</span></span>}</div>;
}

export function ListHeading({ title, count, action }: { title: string; count?: number; action?: ReactNode }) {
  return <div className="list-heading">
    <div className="list-heading-title"><h2>{title}</h2><span className="list-count">{count?.toLocaleString('zh-CN') ?? '—'}</span></div>
    {action}
  </div>;
}

export function BentoStat({ title, value, icon, note, tone = 'plain', className = '' }: {
  title: string; value: ReactNode; icon: ReactNode; note?: ReactNode; tone?: 'plain' | 'lime' | 'dark'; className?: string;
}) {
  return <section className={`bento-tile bento-stat tone-${tone} ${className}`} aria-label={title}>
    <div className="tile-heading"><span className="tile-label">{title}</span><span className="tile-icon" aria-hidden="true">{icon}</span></div>
    <strong className="bento-value">{value ?? '—'}</strong>
    {note && <div className="tile-note">{note}</div>}
  </section>;
}

export function BentoLead({ title, value, icon, note, action }: {
  title: string; value: ReactNode; icon: ReactNode; note?: ReactNode; action?: ReactNode;
}) {
  return <section className="bento-tile bento-lead bento-wide" aria-label={title}>
    <div className="tile-heading"><span className="tile-label">{title}</span><span className="tile-icon" aria-hidden="true">{icon}</span></div>
    <div className="lead-value-row"><strong className="bento-value">{value ?? '—'}</strong>{action}</div>
    {note && <div className="tile-note">{note}</div>}
  </section>;
}
