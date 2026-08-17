"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { UserPlus } from "lucide-react";
import { api, ApiError } from "@/lib/api-client";
import { useAuth } from "@/lib/auth-context";
import { roleLabel } from "@/lib/rbac";
import { usePagination } from "@/hooks/use-pagination";
import type { User, Role } from "@/types/api";
import { DataTable } from "@/components/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger, DialogClose } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";

interface UsersResponse {
  users: User[];
  total: number;
}

const roles: Role[] = ["administrator", "security_analyst", "operator", "patch_approver", "viewer"];

export default function UsersPage() {
  const { user: currentUser } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "viewer" as Role });

  const { page, pageSize, setPage, setPageSize } = usePagination("");

  const { data, isLoading } = useQuery({
    queryKey: ["users", page, pageSize],
    queryFn: () => api.get<UsersResponse>(`/api/v1/users?page=${page}&page_size=${pageSize}`),
    enabled: currentUser?.role === "administrator",
  });

  const createMutation = useMutation({
    mutationFn: () => api.post<User>("/api/v1/users", form),
    onSuccess: () => {
      toast({ title: "User created", variant: "success" });
      setDialogOpen(false);
      setForm({ username: "", email: "", password: "", role: "viewer" });
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (err) => toast({ variant: "destructive", title: "Failed to create user", description: err instanceof ApiError ? err.message : "Something went wrong" }),
  });

  const setActiveMutation = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) => api.patch(`/api/v1/users/${id}/active`, { active }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  const setRoleMutation = useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) => api.patch(`/api/v1/users/${id}/role`, { role }),
    onSuccess: () => {
      toast({ title: "Role updated" });
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
  });

  const columns: ColumnDef<User>[] = [
    { accessorKey: "username", header: "Username" },
    { accessorKey: "email", header: "Email" },
    {
      accessorKey: "role",
      header: "Role",
      cell: ({ row }) => (
        <Select
          value={row.original.role}
          onValueChange={(v) => setRoleMutation.mutate({ id: row.original.id, role: v as Role })}
        >
          <SelectTrigger className="w-44">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {roles.map((r) => (
              <SelectItem key={r} value={r}>
                {roleLabel(r)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ),
    },
    {
      accessorKey: "is_active",
      header: "Status",
      cell: ({ row }) => <Badge variant={row.original.is_active ? "success" : "outline"}>{row.original.is_active ? "Active" : "Inactive"}</Badge>,
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <Button
          variant="outline"
          size="sm"
          disabled={row.original.id === currentUser?.id}
          onClick={() => setActiveMutation.mutate({ id: row.original.id, active: !row.original.is_active })}
        >
          {row.original.is_active ? "Deactivate" : "Activate"}
        </Button>
      ),
    },
  ];

  if (currentUser && currentUser.role !== "administrator") {
    return (
      <Card className="max-w-md">
        <CardHeader>
          <CardTitle>Access restricted</CardTitle>
          <CardDescription>User management is available to administrators only.</CardDescription>
        </CardHeader>
        <CardContent />
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
          <p className="text-sm text-muted-foreground">{data ? `${data.total} accounts` : "Manage platform accounts and roles"}</p>
        </div>

        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <UserPlus className="mr-2 h-4 w-4" />
              New User
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create user</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label>Username</Label>
                <Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
              </div>
              <div className="space-y-1.5">
                <Label>Email</Label>
                <Input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
              </div>
              <div className="space-y-1.5">
                <Label>Password (min. 12 characters)</Label>
                <Input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              </div>
              <div className="space-y-1.5">
                <Label>Role</Label>
                <Select value={form.role} onValueChange={(v) => setForm({ ...form, role: v as Role })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {roles.map((r) => (
                      <SelectItem key={r} value={r}>
                        {roleLabel(r)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <DialogClose asChild>
                <Button variant="ghost">Cancel</Button>
              </DialogClose>
              <Button
                disabled={!form.username || !form.email || form.password.length < 12 || createMutation.isPending}
                onClick={() => createMutation.mutate()}
              >
                Create
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <DataTable
        columns={columns}
        data={data?.users ?? []}
        isLoading={isLoading}
        emptyMessage="No users."
        pagination={{ page, pageSize, total: data?.total ?? 0, onPageChange: setPage, onPageSizeChange: setPageSize }}
      />
    </div>
  );
}
