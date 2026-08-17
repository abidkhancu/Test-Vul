"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  ShieldAlert,
  Server,
  Wrench,
  ScrollText,
  Users,
  FileBarChart,
  Upload,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth-context";
import { canManageUsers } from "@/lib/rbac";

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/findings", label: "Findings", icon: ShieldAlert },
  { href: "/hosts", label: "Hosts", icon: Server },
  { href: "/remediation", label: "Remediation", icon: Wrench },
  { href: "/imports", label: "Imports", icon: Upload },
  { href: "/reports", label: "Reports", icon: FileBarChart },
] as const;

export function Sidebar() {
  const pathname = usePathname();
  const { user } = useAuth();

  return (
    <aside className="hidden w-56 shrink-0 flex-col border-r bg-card md:flex">
      <div className="flex h-14 items-center border-b px-4">
        <span className="text-sm font-semibold">VulnPlatform</span>
      </div>
      <nav className="flex-1 space-y-0.5 p-2">
        {navItems.map(({ href, label, icon: Icon }) => {
          const active = pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                active ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </Link>
          );
        })}

        {user?.role === "administrator" && (
          <>
            <div className="px-3 pt-4 pb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Administration
            </div>
            <Link
              href="/audit"
              className={cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                pathname.startsWith("/audit") ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              )}
            >
              <ScrollText className="h-4 w-4" />
              Audit Log
            </Link>
            {canManageUsers(user.role) && (
              <Link
                href="/users"
                className={cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  pathname.startsWith("/users") ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                )}
              >
                <Users className="h-4 w-4" />
                Users
              </Link>
            )}
          </>
        )}
      </nav>
    </aside>
  );
}
