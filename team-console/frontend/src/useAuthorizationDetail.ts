import { useEffect, useMemo, useRef, useState } from 'react';
import { useResource } from './hooks';
import { authorizationTaskStatus, mergeAuthorizationItems } from './taskHierarchy';
import type { AuthorizationBatch, AuthorizationDetail, Job } from './types';

// Shared by the full task dialog and the single expanded floating task. Mount
// only for the selected task; collapsing it aborts/stops its detail reads.
export function useAuthorizationDetail({ batchId, summary, pipeline }: {
  batchId: string; summary?: AuthorizationBatch; pipeline: Job[];
}) {
  const [remembered, setRemembered] = useState<Job[]>([]);
  const resource = useResource<AuthorizationDetail>('/api/jobs/authorization/' + encodeURIComponent(batchId), {}, summary?.active ? 5000 : 0);
  const revision = `${summary?.finished}:${summary?.active}`;
  const previousRevision = useRef(revision);
  useEffect(() => {
    if (previousRevision.current !== revision) { previousRevision.current = revision; resource.reload(); }
  }, [revision, resource.reload]);
  useEffect(() => {
    setRemembered(old => mergeAuthorizationItems(old, resource.data?.items || [], pipeline, batchId));
  }, [resource.data, pipeline, batchId]);
  const rows = useMemo(() => mergeAuthorizationItems(remembered, resource.data?.items || [], pipeline, batchId), [remembered, resource.data, pipeline, batchId]);
  const fetchedBatch = resource.data?.batch;
  const batch = summary && (!fetchedBatch || summary.finished >= fetchedBatch.finished) ? summary : fetchedBatch;
  return { resource, rows, batch, status: batch ? authorizationTaskStatus(batch) : '' };
}
