"use client";

import { useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { formatDistanceToNow } from "date-fns";
import { Upload } from "lucide-react";
import { api, ApiError } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-context";
import { canWriteFindings } from "@/lib/rbac";
import type { ImportBatch } from "@/types/api";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";

const columns: ColumnDef<ImportBatch>[] = [
  { accessorKey: "filename", header: "File" },
  { accessorKey: "file_type", header: "Type" },
  { accessorKey: "status", header: "Status", cell: ({ row }) => <StatusBadge status={row.original.status} /> },
  {
    id: "progress",
    header: "Progress",
    cell: ({ row }) => {
      const b = row.original;
      return `${b.processed_rows.toLocaleString()} processed${b.failed_rows ? `, ${b.failed_rows} failed` : ""}${b.total_rows ? ` / ${b.total_rows.toLocaleString()}` : ""}`;
    },
  },
  {
    accessorKey: "created_at",
    header: "Uploaded",
    cell: ({ row }) => formatDistanceToNow(new Date(row.original.created_at), { addSuffix: true }),
  },
];

export default function ImportsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["imports"],
    queryFn: () => api.get<ImportBatch[]>("/api/v1/imports?limit=50"),
    // Polling here trades a little request volume for a much simpler
    // page than a WebSocket/SSE progress stream would need — worth
    // revisiting if imports become large/frequent enough to matter.
    refetchInterval: 5000,
  });

  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      return api.postForm<ImportBatch>("/api/v1/imports", formData);
    },
    onSuccess: () => {
      toast({ title: "Import started", description: "The file is queued for processing." });
      queryClient.invalidateQueries({ queryKey: ["imports"] });
    },
    onError: (err) => {
      toast({
        variant: "destructive",
        title: "Upload failed",
        description: err instanceof ApiError ? err.message : "Something went wrong",
      });
    },
  });

  const canUpload = user && canWriteFindings(user.role);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Imports</h1>
          <p className="text-sm text-muted-foreground">Upload scanner reports (CSV or XLSX)</p>
        </div>
        {canUpload && (
          <>
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,.xlsx"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) uploadMutation.mutate(file);
                e.target.value = "";
              }}
            />
            <Button onClick={() => fileInputRef.current?.click()} disabled={uploadMutation.isPending}>
              <Upload className="mr-2 h-4 w-4" />
              {uploadMutation.isPending ? "Uploading…" : "Upload Report"}
            </Button>
          </>
        )}
      </div>

      {!canUpload && (
        <Card>
          <CardHeader>
            <CardTitle>Read-only access</CardTitle>
            <CardDescription>Your role can view import history but not upload new scanner reports.</CardDescription>
          </CardHeader>
          <CardContent />
        </Card>
      )}

      <DataTable columns={columns} data={data ?? []} isLoading={isLoading} emptyMessage="No imports yet." />
    </div>
  );
}
