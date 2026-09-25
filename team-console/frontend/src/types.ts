export type Numeric = number | string | null;
export interface IndexStatus { ready: boolean; refreshing: boolean; last_updated_at: string | null; error: string | null }
export interface Page<T> { items: T[]; total: number; page: number; page_size: number; index?: IndexStatus }
export interface Quota {
  quota_status?: string; quota_primary_used_percent?: Numeric; quota_secondary_used_percent?: Numeric;
  quota_primary_limit_window_seconds?: Numeric; quota_secondary_limit_window_seconds?: Numeric;
  quota_checked_at?: string;
}
export interface Account extends Quota {
  id: number; email: string; registration_batch_id?: string;
  codex_connection_state?: string; codex_status?: string; codex_plan_type?: string;
  totp_status?: string; team_status?: string; team_seat_type?: string; updated_at?: string;
}
export interface Batch {
  batch_id: string; account_total: number; created_at?: string;
}
export interface Parent { id: number; email: string; label?: string; status?: string; workspace_count?: number; updated_at?: string; active_job_id?: string | null }
export interface Workspace {
  id: string; name?: string; member_count?: number; is_usage_based_seat_enabled?: boolean;
  can_manage?: boolean; role?: string; members_stale?: boolean; members_error?: string;
  assigned?: Record<string, number>; seat_type_counts?: Record<string, number>;
  seat_capacity?: { type: string; available?: number; paid?: number; held?: number }[];
  summary_error?: string; holds_error?: string; holds_stale?: boolean; holds_synced_at?: string;
}
export interface Member {
  id: string; email?: string; seat_type?: string; reclaimable_seat_type?: string; status?: string | number;
  role?: string; name?: string; pending_seat_type?: string; deactivated_time?: string;
  local_account?: Quota | null; local_account_match?: string;
}
export type TeamScope = { account_ids: number[]; batch_id?: never } | { batch_id: string; account_ids?: never };
export interface TeamOperationPreview {
  selection_hash: string; eligible_count: number; skipped_count: number; total: number;
  items: { account_id: number; email: string; user_id: string; status: string; message: string }[];
}
export interface NetworkSettings {
  source: 'deployment' | 'override'; pool_count: number; pool_preview: string[];
  quota_proxy_mode: 'auto' | 'proxy' | 'direct'; quota_proxy_configured: boolean; quota_proxy_preview: string;
}
export interface Detail { id?: number; account_id?: number; email?: string; reason?: string; error?: string }
export interface QueueResult {
  ok: boolean; error?: string; batch_id?: string; started_count: number;
  busy_count?: number; skipped_count?: number; failed_count?: number; no_token_count?: number;
  busy?: Detail[]; skipped?: Detail[]; failed?: Detail[]; no_token?: Detail[];
}
export interface ImportResult {
  ok: boolean; imported_count: number; skipped: Detail[]; batch_id: string | null;
  authorization?: QueueResult;
}
export interface ExportResult {
  ok: boolean; exported_count: number; failed_count: number; failed: Detail[]; warnings: Detail[];
  export_marked: boolean; filename: string; data: unknown;
}
export interface TotpExportResult extends Omit<ExportResult, 'export_marked' | 'data'> { data: string }
export interface Job {
  id: string; batch_id?: string; email?: string; account_id?: number; parent_email?: string;
  stage?: string; status?: string; kind?: string; message?: string; error?: string;
  total?: number; completed?: number; updated_at?: string; created_at?: string; team_authorization?: boolean;
}
export interface AuthorizationBatch {
  batch_id: string; team_authorization: boolean; total: number; active: number; finished: number; completed: boolean;
}
export interface AuthorizationRuntime { workers: number; running: number; queued: number; available: number; peak_running: number; fixed: boolean }
export interface Jobs { team: Job[]; pipeline: Job[]; authorization: AuthorizationBatch[]; runtime?: AuthorizationRuntime }
export interface Overview { accounts: Record<string, number>; parents: Parent[]; index: IndexStatus }
