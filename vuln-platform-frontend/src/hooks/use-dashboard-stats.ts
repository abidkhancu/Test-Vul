"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api-client";

interface ListResponse {
  total: number;
}

function useCount(key: string, path: string) {
  return useQuery({
    queryKey: ["stats", key],
    queryFn: () => api.get<ListResponse>(path),
  });
}

// Mirrors internal/usecase/reporting.StatsCollector.ExecutiveSummary
// on the backend: no dedicated aggregate endpoint exists yet, so this
// counts via the same `total` field the paginated list endpoints
// already return, one small request per breakdown. Fine at current
// scale; if this page's load time becomes noticeable, add a real
// GET /api/v1/stats/summary endpoint on the backend rather than
// firing more of these from the client.
//
// Individual named useQuery calls rather than a single useQueries
// array: with TypeScript's noUncheckedIndexedAccess on, destructuring
// fixed positions out of a useQueries result array makes every
// element type `T | undefined` regardless of the array's actual
// fixed length, which either means non-null-asserting twelve times or
// this — named queries sidestep the whole problem.
export function useDashboardStats() {
  const findingsTotal = useCount("findings-total", "/api/v1/findings?page_size=1");
  const critical = useCount("findings-critical", "/api/v1/findings?severity=critical&page_size=1");
  const high = useCount("findings-high", "/api/v1/findings?severity=high&page_size=1");
  const medium = useCount("findings-medium", "/api/v1/findings?severity=medium&page_size=1");
  const low = useCount("findings-low", "/api/v1/findings?severity=low&page_size=1");
  const hostsTotal = useCount("hosts-total", "/api/v1/hosts?page_size=1");
  const remediationTotal = useCount("remediation-total", "/api/v1/remediation?page_size=1");
  const pendingApproval = useCount("remediation-pending-approval", "/api/v1/remediation?status=pending_approval&page_size=1");
  const approved = useCount("remediation-approved", "/api/v1/remediation?status=approved&page_size=1");
  const remediated = useCount("remediation-remediated", "/api/v1/remediation?status=remediated&page_size=1");
  const patchFailed = useCount("remediation-patch-failed", "/api/v1/remediation?status=patch_failed&page_size=1");
  const sshFailed = useCount("remediation-ssh-failed", "/api/v1/remediation?status=ssh_failed&page_size=1");

  const isLoading = [
    findingsTotal,
    critical,
    high,
    medium,
    low,
    hostsTotal,
    remediationTotal,
    pendingApproval,
    approved,
    remediated,
    patchFailed,
    sshFailed,
  ].some((q) => q.isLoading);

  return {
    isLoading,
    findingsTotal: findingsTotal.data?.total ?? 0,
    bySeverity: {
      critical: critical.data?.total ?? 0,
      high: high.data?.total ?? 0,
      medium: medium.data?.total ?? 0,
      low: low.data?.total ?? 0,
    },
    hostsTotal: hostsTotal.data?.total ?? 0,
    remediationTotal: remediationTotal.data?.total ?? 0,
    remediationByStatus: {
      pending_approval: pendingApproval.data?.total ?? 0,
      approved: approved.data?.total ?? 0,
      remediated: remediated.data?.total ?? 0,
      patch_failed: patchFailed.data?.total ?? 0,
      ssh_failed: sshFailed.data?.total ?? 0,
    },
  };
}
