"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import type { ColumnDef } from "@tanstack/react-table";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api-client";
import type { RemediationTask, RemediationStatus, Severity } from "@/types/api";
import { DataTable } from "@/components/data-table";
import { usePagination } from "@/hooks/use-pagination";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface RemediationResponse {
  tasks: RemediationTask[];
  total: number;
}

const columns: ColumnDef<RemediationTask>[] = [
  { accessorKey: "rhsa_id", header: "RHSA", cell: ({ row }) => row.original.rhsa_id ?? "—" },
  { accessorKey: "host_id", header: "Host ID", cell: ({ row }) => <span className="font-mono text-xs">{row.original.host_id.slice(0, 8)}</span> },
  { accessorKey: "severity", header: "Severity", cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
  { accessorKey: "status", header: "Status", cell: ({ row }) => <StatusBadge status={row.original.status} /> },
  {
    accessorKey: "last_verified_at",
    header: "Last Verified",
    cell: ({ row }) =>
      row.original.last_verified_at ? formatDistanceToNow(new Date(row.original.last_verified_at), { addSuffix: true }) : "Never",
  },
];

export default function RemediationPage() {
  const router = useRouter();
  const [status, setStatus] = useState<RemediationStatus | "all">("all");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const { page, pageSize, setPage, setPageSize } = usePagination(`${status}|${severity}`);

  const params = new URLSearchParams();
  if (status !== "all") params.set("status", status);
  if (severity !== "all") params.set("severity", severity);
  params.set("page", String(page));
  params.set("page_size", String(pageSize));

  const { data, isLoading } = useQuery({
    queryKey: ["remediation", status, severity, page, pageSize],
    queryFn: () => api.get<RemediationResponse>(`/api/v1/remediation?${params.toString()}`),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Remediation</h1>
        <p className="text-sm text-muted-foreground">
          {data ? `${data.total.toLocaleString()} remediation tasks` : "Correlated remediation tasks"}
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Select value={status} onValueChange={(v) => setStatus(v as RemediationStatus | "all")}>
          <SelectTrigger className="w-56">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="pending_verification">Pending Verification</SelectItem>
            <SelectItem value="verified_vulnerable">Verified Vulnerable</SelectItem>
            <SelectItem value="pending_approval">Pending Approval</SelectItem>
            <SelectItem value="approved">Approved</SelectItem>
            <SelectItem value="patching">Patching</SelectItem>
            <SelectItem value="remediated">Remediated</SelectItem>
            <SelectItem value="patch_failed">Patch Failed</SelectItem>
            <SelectItem value="ssh_failed">SSH Failed</SelectItem>
            <SelectItem value="rejected">Rejected</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severity} onValueChange={(v) => setSeverity(v as Severity | "all")}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <DataTable
        columns={columns}
        data={data?.tasks ?? []}
        isLoading={isLoading}
        onRowClick={(task) => router.push(`/remediation/${task.id}`)}
        emptyMessage="No remediation tasks match these filters."
        pagination={{ page, pageSize, total: data?.total ?? 0, onPageChange: setPage, onPageSizeChange: setPageSize }}
      />
    </div>
  );
}
