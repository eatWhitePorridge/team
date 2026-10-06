export type Numeric = number | string | null;
export interface IndexStatus { ready: boolean; refreshing: boolean; last_updated_at: string | null; error: string | null }
export interface Page<T> { items: T[]; total: number; page: number; page_size: number; index?: IndexStatus }
export interface Quota {
  quota_status?: string; quota_primary_used_percent?: Numeric; quota_secondary_used_percent?: Numeric;
  quota_primary_limit_window_seconds?: Numeric; quota_secondary_limit_window_seconds?: Numeric;
  quota_checked_at?: string; quota_last_success_at?: string; quota_plan_type?: string;
  quota_credits_balance?: Numeric;
  quota_credits_has_credits?: boolean | 0 | 1 | null; quota_credits_unlimited?: boolean | 0 | 1 | null;
  quota_allowed?: boolean | 0 | 1 | null; quota_limit_reached?: boolean | 0 | 1 | null;
}
export interface Account extends Quota {
  id: number; email: string; registration_batch_id?: string;
  codex_connection_state?: string; codex_status?: string; codex_plan_type?: string;
  totp_status?: string; team_status?: string; team_seat_type?: string; updated_at?: string;
}
export interface Batch {
  batch_id: string; account_total: number; created_at?: string;
}
export interface MergeBatchesResult {
  ok: boolean; target_batch_id: string; merged_batch_ids: string[]; merged_count: number;
  moved_accounts: number; already_merged: boolean; warnings: Detail[];
}
export interface SplitBatchResult {
  ok: boolean; batch_id: string; source_batch_ids: string[];
  moved_accounts: number; already_split: boolean; warnings: Detail[];
}
export interface DeleteBatchesResult {
  ok: boolean; deleted_batch_ids: string[]; deleted_count: number; deleted_account_count: number;
  deleted_job_count: number; warnings: Detail[];
}
export interface ParentProxy { configured: boolean; preview: string; revision: string; source: string; updated_at: string }
export interface Parent { id: number; email: string; label?: string; status?: string; workspace_count?: number; updated_at?: string; active_job_id?: string | null; has_access_token?: boolean; proxy?: ParentProxy; billing_workspaces?: ParentBillingWorkspace[] }
export interface ParentBillingWorkspace {
  id: string; name?: string; renewal_date?: string | number; billing_renewal_date?: string | number;
  expiration_checked_at?: string | number; query_failed?: boolean;
}
export interface Workspace {
  id: string; name?: string; member_count?: number; is_usage_based_seat_enabled?: boolean;
  renewal_date?: string | number; billing_renewal_date?: string | number; expires_at?: string | number;
  expiration_checked_at?: string; expiration_succeeded_at?: string; expiration_error?: string;
  can_manage?: boolean; role?: string; members_synced_at?: string; members_stale?: boolean; members_error?: string;
  assigned?: Record<string, number>; seat_type_counts?: Record<string, number>;
  seat_capacity?: { type: string; available?: number; paid?: number; held?: number }[];
  summary_error?: string; holds_error?: string; holds_stale?: boolean; holds_synced_at?: string;
  invite_count?: number; invites_synced_at?: string; invites_stale?: boolean; invites_error?: string;
}
export interface Invitation { id: string; email: string; seat_type?: string; status?: number; role?: string; created_time?: string }
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
export interface DeleteAccountsResult {
  ok: boolean; deleted: { id: number; email?: string }[]; deleted_count: number;
  skipped: Detail[]; skipped_count: number; warnings: Detail[];
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
  cancel_requested?: boolean;
  expected_workspace_id?: string;
  concurrency?: number; running?: number;
  codex_job_id?: number; codex_plan_type?: string; progress_status?: string; progress_stage?: string;
  codex_attempt_count?: number; codex_max_attempts?: number;
  progress_message?: string; progress_updated_at?: string;
}
export interface AuthorizationBatch {
  batch_id: string; team_authorization: boolean; total: number; active: number; finished: number; completed: boolean;
  queued?: number; running?: number; retrying?: number; confirming?: number;
  known?: number; missing?: number; success?: number; failed?: number; cancelled?: number;
  created_at?: string; updated_at?: string; expected_workspace_id?: string;
}
export interface AuthorizationDetail { batch: AuthorizationBatch; items: Job[]; total: number }
export interface AuthorizationRuntime { workers: number; running: number; queued: number; available: number; peak_running: number; fixed: boolean }
export interface Jobs { team: Job[]; pipeline: Job[]; authorization: AuthorizationBatch[]; runtime?: AuthorizationRuntime }
export interface Overview { accounts: Record<string, number>; parents: Parent[]; index: IndexStatus }
