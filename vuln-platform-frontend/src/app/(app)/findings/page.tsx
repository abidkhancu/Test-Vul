"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { api } from "@/lib/api-client";
import type { ScannerFinding, Severity, FindingStatus } from "@/types/api";
import { DataTable } from "@/components/data-table";
import { usePagination } from "@/hooks/use-pagination";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface FindingsResponse {
  findings: ScannerFinding[];
  total: number;
}

const columns: ColumnDef<ScannerFinding>[] = [
  { accessorKey: "name", header: "Finding" },
  { accessorKey: "host_raw", header: "Host" },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
  },
  {
    id: "cves",
    header: "CVEs",
    cell: ({ row }) => (row.original.extracted_cves ?? []).join(", ") || "—",
  },
  {
    id: "rhsas",
    header: "RHSAs",
    cell: ({ row }) => (row.original.extracted_rhsas ?? []).join(", ") || "—",
  },
];

export default function FindingsPage() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [status, setStatus] = useState<FindingStatus | "all">("all");
  const { page, pageSize, setPage, setPageSize } = usePagination(`${search}|${severity}|${status}`);

  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (severity !== "all") params.set("severity", severity);
  if (status !== "all") params.set("status", status);
  params.set("page", String(page));
  params.set("page_size", String(pageSize));

  const { data, isLoading } = useQuery({
    queryKey: ["findings", search, severity, status, page, pageSize],
    queryFn: () => api.get<FindingsResponse>(`/api/v1/findings?${params.toString()}`),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <p className="text-sm text-muted-foreground">
          {data ? `${data.total.toLocaleString()} findings` : "Scanner findings across all imports"}
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Input
          placeholder="Search name, description, host…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
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
        <Select value={status} onValueChange={(v) => setStatus(v as FindingStatus | "all")}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="pending_verification">Pending Verification</SelectItem>
            <SelectItem value="verified">Verified</SelectItem>
            <SelectItem value="already_remediated">Already Remediated</SelectItem>
            <SelectItem value="closed">Closed</SelectItem>
            <SelectItem value="false_positive">False Positive</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <DataTable
        columns={columns}
        data={data?.findings ?? []}
        isLoading={isLoading}
        emptyMessage="No findings match these filters."
        pagination={{ page, pageSize, total: data?.total ?? 0, onPageChange: setPage, onPageSizeChange: setPageSize }}
      />
    </div>
  );
}
