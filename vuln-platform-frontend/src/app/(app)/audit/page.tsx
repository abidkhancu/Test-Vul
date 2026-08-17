"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { api } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-context";
import { usePagination } from "@/hooks/use-pagination";
import type { AuditLog } from "@/types/api";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

interface AuditResponse {
  entries: AuditLog[];
  total: number;
}

const columns: ColumnDef<AuditLog>[] = [
  { accessorKey: "timestamp", header: "Time", cell: ({ row }) => format(new Date(row.original.timestamp), "yyyy-MM-dd HH:mm:ss") },
  { accessorKey: "username", header: "User" },
  { accessorKey: "action", header: "Action" },
  {
    accessorKey: "result",
    header: "Result",
    cell: ({ row }) => (
      <Badge variant={row.original.result === "success" ? "success" : row.original.result === "denied" ? "outline" : "destructive"}>
        {row.original.result}
      </Badge>
    ),
  },
  {
    accessorKey: "executed_command",
    header: "Command",
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.executed_command ?? "—"}</span>,
  },
  { accessorKey: "detail", header: "Detail" },
];

export default function AuditPage() {
  const { user } = useAuth();
  const [username, setUsername] = useState("");
  const [action, setAction] = useState("");
  const { page, pageSize, setPage, setPageSize } = usePagination(`${username}|${action}`);

  const params = new URLSearchParams();
  if (username) params.set("username", username);
  if (action) params.set("action", action);
  params.set("page", String(page));
  params.set("page_size", String(pageSize));

  const { data, isLoading } = useQuery({
    queryKey: ["audit", username, action, page, pageSize],
    queryFn: () => api.get<AuditResponse>(`/api/v1/audit?${params.toString()}`),
    enabled: user?.role === "administrator",
  });

  if (user && user.role !== "administrator") {
    return (
      <Card className="max-w-md">
        <CardHeader>
          <CardTitle>Access restricted</CardTitle>
          <CardDescription>The audit log is available to administrators only.</CardDescription>
        </CardHeader>
        <CardContent />
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audit Log</h1>
        <p className="text-sm text-muted-foreground">{data ? `${data.total.toLocaleString()} entries` : "Every command executed by this platform"}</p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Input placeholder="Filter by username…" value={username} onChange={(e) => setUsername(e.target.value)} className="max-w-xs" />
        <Input placeholder="Filter by action (e.g. patch.execute)…" value={action} onChange={(e) => setAction(e.target.value)} className="max-w-xs" />
      </div>

      <DataTable
        columns={columns}
        data={data?.entries ?? []}
        isLoading={isLoading}
        emptyMessage="No audit entries match these filters."
        pagination={{ page, pageSize, total: data?.total ?? 0, onPageChange: setPage, onPageSizeChange: setPageSize }}
      />
    </div>
  );
}
