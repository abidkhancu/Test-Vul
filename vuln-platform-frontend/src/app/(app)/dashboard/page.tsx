"use client";

import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { AlertTriangle, Server, Wrench, ShieldCheck } from "lucide-react";
import { useDashboardStats } from "@/hooks/use-dashboard-stats";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "hsl(0 72% 51%)",
  High: "hsl(24 95% 53%)",
  Medium: "hsl(45 93% 47%)",
  Low: "hsl(199 89% 48%)",
};

export default function DashboardPage() {
  const stats = useDashboardStats();

  const severityData = [
    { name: "Critical", value: stats.bySeverity.critical },
    { name: "High", value: stats.bySeverity.high },
    { name: "Medium", value: stats.bySeverity.medium },
    { name: "Low", value: stats.bySeverity.low },
  ];

  const remediationData = [
    { name: "Pending Approval", value: stats.remediationByStatus.pending_approval },
    { name: "Approved", value: stats.remediationByStatus.approved },
    { name: "Remediated", value: stats.remediationByStatus.remediated },
    { name: "Patch Failed", value: stats.remediationByStatus.patch_failed },
    { name: "SSH Failed", value: stats.remediationByStatus.ssh_failed },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground">Fleet-wide vulnerability and remediation overview</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard title="Total Findings" value={stats.findingsTotal} icon={AlertTriangle} loading={stats.isLoading} />
        <StatCard title="Managed Hosts" value={stats.hostsTotal} icon={Server} loading={stats.isLoading} />
        <StatCard title="Remediation Tasks" value={stats.remediationTotal} icon={Wrench} loading={stats.isLoading} />
        <StatCard
          title="Remediated"
          value={stats.remediationByStatus.remediated}
          icon={ShieldCheck}
          loading={stats.isLoading}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Findings by Severity</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            {stats.isLoading ? (
              <Skeleton className="h-full w-full" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={60} outerRadius={90} paddingAngle={2}>
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Remediation Pipeline</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            {stats.isLoading ? (
              <Skeleton className="h-full w-full" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={remediationData} layout="vertical" margin={{ left: 24 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} />
                  <YAxis type="category" dataKey="name" width={110} tick={{ fontSize: 12 }} />
                  <Tooltip />
                  <Bar dataKey="value" fill="hsl(var(--primary))" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function StatCard({
  title,
  value,
  icon: Icon,
  loading,
}: {
  title: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  loading: boolean;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle>{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        {loading ? <Skeleton className="h-8 w-16" /> : <div className="text-2xl font-bold">{value.toLocaleString()}</div>}
      </CardContent>
    </Card>
  );
}
