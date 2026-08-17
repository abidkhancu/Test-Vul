"use client";

import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { api, setTokens, clearTokens, isAuthenticated, ApiError } from "@/lib/api-client";
import type { Role } from "@/types/api";

interface CurrentUser {
  id: string;
  username: string;
  role: Role;
}

interface LoginResponse {
  access_token: string;
  refresh_token: string;
  user: CurrentUser;
}

interface AuthContextValue {
  user: CurrentUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    let cancelled = false;

    async function bootstrap() {
      if (!isAuthenticated()) {
        setLoading(false);
        return;
      }
      try {
        const me = await api.get<CurrentUser>("/api/v1/auth/me");
        if (!cancelled) setUser(me);
      } catch {
        // api-client already redirects to /login on unrecoverable 401;
        // for any other failure, just leave the user unauthenticated.
        clearTokens();
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    bootstrap();

    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(
    async (username: string, password: string) => {
      try {
        const res = await api.postAuth<LoginResponse>("/api/v1/auth/login", { username, password });
        setTokens(res.access_token, res.refresh_token);
        setUser(res.user);
        router.push("/dashboard");
      } catch (err) {
        if (err instanceof ApiError) throw err;
        throw new ApiError(0, "Unable to reach the server");
      }
    },
    [router]
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/api/v1/auth/logout");
    } catch {
      // best-effort — proceed with local logout regardless of whether
      // the server-side refresh-token revocation call succeeded
    }
    clearTokens();
    setUser(null);
    router.push("/login");
  }, [router]);

  return <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
