"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { ShieldQuestion, CheckCircle2, XCircle, Play, Wrench } from "lucide-react";
import { api, ApiError } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-context";
import { canApprovePatches, canRunVerification } from "@/lib/rbac";
import type { RemediationTask, PatchJob, VerificationResult } from "@/types/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogClose,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";

export default function RemediationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [rejectReason, setRejectReason] = useState("");
  const [rejectOpen, setRejectOpen] = useState(false);
  const [patchConfirmOpen, setPatchConfirmOpen] = useState(false);

  const { data: task, isLoading } = useQuery({
    queryKey: ["remediation", id],
    queryFn: () => api.get<RemediationTask>(`/api/v1/remediation/${id}`),
  });

  const { data: patchJobs } = useQuery({
    queryKey: ["patches", "by-task", id],
    queryFn: () => api.get<PatchJob[]>(`/api/v1/patches/by-task/${id}`),
    enabled: !!task,
  });

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ["remediation", id] });
    queryClient.invalidateQueries({ queryKey: ["remediation"] });
    queryClient.invalidateQueries({ queryKey: ["patches", "by-task", id] });
  }

  const verifyMutation = useMutation({
    mutationFn: () => api.post<VerificationResult>(`/api/v1/remediation/${id}/verify`),
    onSuccess: (result) => {
      toast({ title: "Verification complete", description: `Outcome: ${result.outcome}` });
      invalidate();
    },
    onError: (err) => toast({ variant: "destructive", title: "Verification failed", description: errMsg(err) }),
  });

  const approveMutation = useMutation({
    mutationFn: () => api.post(`/api/v1/remediation/${id}/approve`),
    onSuccess: () => {
      toast({ title: "Task approved", variant: "success" });
      invalidate();
    },
    onError: (err) => toast({ variant: "destructive", title: "Approval failed", description: errMsg(err) }),
  });

  const rejectMutation = useMutation({
    mutationFn: () => api.post(`/api/v1/remediation/${id}/reject`, { reason: rejectReason }),
    onSuccess: () => {
      toast({ title: "Task rejected" });
      setRejectOpen(false);
      setRejectReason("");
      invalidate();
    },
    onError: (err) => toast({ variant: "destructive", title: "Rejection failed", description: errMsg(err) }),
  });

  const executeMutation = useMutation({
    mutationFn: () => api.post<PatchJob>(`/api/v1/patches/execute`, { remediation_task_id: id }),
    onSuccess: () => {
      toast({ title: "Patch execution started", description: "This will run the approved RHSA update on the host." });
      setPatchConfirmOpen(false);
      invalidate();
    },
    onError: (err) => toast({ variant: "destructive", title: "Patch execution failed", description: errMsg(err) }),
  });

  if (isLoading || !task) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }

  const canVerify = user && canRunVerification(user.role);
  const canApprove = user && canApprovePatches(user.role);

  return (
    <div className="max-w-3xl space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{task.rhsa_id ?? "CVE-only task"}</h1>
          <p className="text-sm text-muted-foreground">Remediation task {task.id}</p>
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={task.severity} />
          <StatusBadge status={task.status} />
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Details</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 text-sm">
          <Field label="Host ID" value={task.host_id} mono />
          <Field label="Approval Required" value={task.approval_required ? "Yes" : "No"} />
          <Field label="CVEs" value={task.cve_ids?.join(", ") || "—"} />
          <Field label="Packages" value={task.package_names?.join(", ") || "—"} />
          <Field
            label="Last Verified"
            value={task.last_verified_at ? formatDistanceToNow(new Date(task.last_verified_at), { addSuffix: true }) : "Never"}
          />
          <Field label="Approved By" value={task.approved_by ?? "—"} />
        </CardContent>
        {task.verification_notes && (
          <CardContent className="pt-0">
            <p className="mb-1 text-xs font-medium text-muted-foreground">Verification Notes</p>
            <pre className="whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">{task.verification_notes}</pre>
          </CardContent>
        )}
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Actions</CardTitle>
          <CardDescription>
            Every action here is re-checked against live authorization state on the server — a role that can initiate
            an action here is not the same as it always succeeding.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {canVerify && (
            <Button variant="outline" onClick={() => verifyMutation.mutate()} disabled={verifyMutation.isPending}>
              <ShieldQuestion className="mr-2 h-4 w-4" />
              {verifyMutation.isPending ? "Verifying…" : "Run Verification"}
            </Button>
          )}

          {canApprove && task.status === "pending_approval" && (
            <>
              <Button onClick={() => approveMutation.mutate()} disabled={approveMutation.isPending}>
                <CheckCircle2 className="mr-2 h-4 w-4" />
                Approve
              </Button>

              <Dialog open={rejectOpen} onOpenChange={setRejectOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline">
                    <XCircle className="mr-2 h-4 w-4" />
                    Reject
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Reject remediation task</DialogTitle>
                    <DialogDescription>A reason is required and will be recorded in the audit log.</DialogDescription>
                  </DialogHeader>
                  <Textarea
                    placeholder="Why is this task being rejected?"
                    value={rejectReason}
                    onChange={(e) => setRejectReason(e.target.value)}
                  />
                  <DialogFooter>
                    <DialogClose asChild>
                      <Button variant="ghost">Cancel</Button>
                    </DialogClose>
                    <Button
                      variant="destructive"
                      disabled={!rejectReason.trim() || rejectMutation.isPending}
                      onClick={() => rejectMutation.mutate()}
                    >
                      Confirm Rejection
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </>
          )}

          {canApprove && task.status === "approved" && (
            <Dialog open={patchConfirmOpen} onOpenChange={setPatchConfirmOpen}>
              <DialogTrigger asChild>
                <Button variant="destructive">
                  <Play className="mr-2 h-4 w-4" />
                  Execute Patch
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Execute patch on production host</DialogTitle>
                  <DialogDescription>
                    This runs <code className="rounded bg-muted px-1 py-0.5">dnf update --advisory={task.rhsa_id}</code>{" "}
                    over SSH on the target host. This is a real, immediate action against production infrastructure —
                    it is not a dry run.
                  </DialogDescription>
                </DialogHeader>
                <DialogFooter>
                  <DialogClose asChild>
                    <Button variant="ghost">Cancel</Button>
                  </DialogClose>
                  <Button variant="destructive" disabled={executeMutation.isPending} onClick={() => executeMutation.mutate()}>
                    {executeMutation.isPending ? "Executing…" : "Yes, execute this patch"}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )}

          {!canVerify && !canApprove && <p className="text-sm text-muted-foreground">Your role has read-only access to this task.</p>}
        </CardContent>
      </Card>

      {patchJobs && patchJobs.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Wrench className="h-4 w-4" />
              Patch Job History
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {patchJobs.map((job) => (
              <div key={job.id} className="rounded-md border p-3 text-sm">
                <div className="mb-1 flex items-center justify-between">
                  <span className="font-mono text-xs">{job.command}</span>
                  <StatusBadge status={job.status} />
                </div>
                <div className="flex gap-4 text-xs text-muted-foreground">
                  <span>Approved by {job.approved_by}</span>
                  {job.exit_code !== undefined && <span>Exit code: {job.exit_code}</span>}
                  {job.post_verify_passed !== undefined && (
                    <span>Post-verify: {job.post_verify_passed ? "passed" : "failed"}</span>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <p className={mono ? "font-mono text-xs" : ""}>{value}</p>
    </div>
  );
}

function errMsg(err: unknown): string {
  return err instanceof ApiError ? err.message : "Something went wrong";
}
