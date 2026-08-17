"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileDown } from "lucide-react";
import { api, ApiError } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-context";
import type { Report } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { format } from "date-fns";

const REPORT_TYPES = [
  { value: "executive_summary", label: "Executive Summary", formats: ["pdf"] },
  { value: "technical", label: "Technical (Findings)", formats: ["pdf", "csv", "xlsx"] },
  { value: "host", label: "Host", formats: ["pdf", "csv", "xlsx"] },
  { value: "verification", label: "Verification / Remediation", formats: ["pdf", "csv", "xlsx"] },
  { value: "patch", label: "Patch", formats: ["pdf", "csv", "xlsx"] },
  { value: "audit", label: "Audit", formats: ["pdf", "csv", "xlsx"] },
] as const;

export default function ReportsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [reportType, setReportType] = useState<string>("executive_summary");
  const [reportFormat, setReportFormat] = useState<string>("pdf");

  const { data: reports, isLoading } = useQuery({
    queryKey: ["reports"],
    queryFn: () => api.get<Report[]>("/api/v1/reports"),
  });

  const canGenerate = user && (user.role === "administrator" || user.role === "security_analyst");

  const generateMutation = useMutation({
    mutationFn: () => api.postBlob(`/api/v1/reports?type=${reportType}&format=${reportFormat}`),
    onSuccess: (blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${reportType}.${reportFormat}`;
      a.click();
      URL.revokeObjectURL(url);
      toast({ title: "Report generated", variant: "success" });
      queryClient.invalidateQueries({ queryKey: ["reports"] });
    },
    onError: (err) => toast({ variant: "destructive", title: "Failed to generate report", description: err instanceof ApiError ? err.message : "Something went wrong" }),
  });

  async function download(report: Report) {
    try {
      const blob = await api.getBlob(`/api/v1/reports/${report.id}/download`);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${report.report_type}.${report.format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast({
        variant: "destructive",
        title: "Download failed",
        description: err instanceof ApiError ? err.message : "Something went wrong",
      });
    }
  }

  const selectedType = REPORT_TYPES.find((t) => t.value === reportType);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Reports</h1>
        <p className="text-sm text-muted-foreground">Generate and download executive, technical, and audit reports</p>
      </div>

      {canGenerate && (
        <Card>
          <CardHeader>
            <CardTitle>Generate a report</CardTitle>
            <CardDescription>Executive summary is available as PDF only; other report types also support CSV and XLSX.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap items-end gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Report type</label>
              <Select
                value={reportType}
                onValueChange={(v) => {
                  setReportType(v);
                  const t = REPORT_TYPES.find((rt) => rt.value === v);
                  if (t && !(t.formats as readonly string[]).includes(reportFormat)) setReportFormat(t.formats[0]);
                }}
              >
                <SelectTrigger className="w-56">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {REPORT_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Format</label>
              <Select value={reportFormat} onValueChange={setReportFormat}>
                <SelectTrigger className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {selectedType?.formats.map((f) => (
                    <SelectItem key={f} value={f}>
                      {f.toUpperCase()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button onClick={() => generateMutation.mutate()} disabled={generateMutation.isPending}>
              <FileDown className="mr-2 h-4 w-4" />
              {generateMutation.isPending ? "Generating…" : "Generate & Download"}
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Previously generated</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>Format</TableHead>
                <TableHead>Generated</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground">
                    Loading…
                  </TableCell>
                </TableRow>
              ) : reports && reports.length > 0 ? (
                reports.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>{r.report_type}</TableCell>
                    <TableCell className="uppercase">{r.format}</TableCell>
                    <TableCell>{format(new Date(r.created_at), "yyyy-MM-dd HH:mm")}</TableCell>
                    <TableCell>
                      <Button variant="ghost" size="sm" onClick={() => download(r)}>
                        <FileDown className="mr-2 h-3.5 w-3.5" />
                        Download
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground">
                    No reports generated yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
