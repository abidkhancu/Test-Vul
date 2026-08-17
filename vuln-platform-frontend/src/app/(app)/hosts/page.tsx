"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { formatDistanceToNow } from "date-fns";
import { api } from "@/lib/api-client";
import type { Host } from "@/types/api";
import { DataTable } from "@/components/data-table";
import { usePagination } from "@/hooks/use-pagination";
import { StatusBadge } from "@/components/status-badge";
import { Input } from "@/components/ui/input";

interface HostsResponse {
  hosts: Host[];
  total: number;
}

const columns: ColumnDef<Host>[] = [
  { accessorKey: "hostname", header: "Hostname" },
  { accessorKey: "ip_address", header: "IP Address" },
  { accessorKey: "environment", header: "Environment" },
  { accessorKey: "os_family", header: "OS" },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
  },
  {
    accessorKey: "last_seen_at",
    header: "Last Seen",
    cell: ({ row }) => (row.original.last_seen_at ? formatDistanceToNow(new Date(row.original.last_seen_at), { addSuffix: true }) : "Never"),
  },
];

export default function HostsPage() {
  const [search, setSearch] = useState("");
  const { page, pageSize, setPage, setPageSize } = usePagination(search);

  const { data, isLoading } = useQuery({
    queryKey: ["hosts", search, page, pageSize],
    queryFn: () =>
      api.get<HostsResponse>(`/api/v1/hosts?search=${encodeURIComponent(search)}&page=${page}&page_size=${pageSize}`),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Hosts</h1>
        <p className="text-sm text-muted-foreground">{data ? `${data.total.toLocaleString()} managed hosts` : "Managed fleet"}</p>
      </div>

      <Input placeholder="Search hostname or IP…" value={search} onChange={(e) => setSearch(e.target.value)} className="max-w-xs" />

      <DataTable
        columns={columns}
        data={data?.hosts ?? []}
        isLoading={isLoading}
        emptyMessage="No hosts found."
        pagination={{ page, pageSize, total: data?.total ?? 0, onPageChange: setPage, onPageSizeChange: setPageSize }}
      />
    </div>
  );
}
