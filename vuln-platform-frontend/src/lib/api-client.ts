// Central API client. Every request goes through `request()` below so
// auth headers, 401-triggered refresh, and error shaping happen in
// exactly one place rather than being re-implemented per call site.

const TOKEN_KEY = "vuln_platform_access_token";
const REFRESH_KEY = "vuln_platform_refresh_token";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(REFRESH_KEY);
}

export function setTokens(access: string, refresh: string) {
  window.localStorage.setItem(TOKEN_KEY, access);
  window.localStorage.setItem(REFRESH_KEY, refresh);
}

export function clearTokens() {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(REFRESH_KEY);
}

// Refresh is de-duplicated: if several requests 401 at once (e.g. a
// dashboard firing five queries in parallel right as the access token
// expires), they should all wait on one refresh call, not each fire
// their own and race to store tokens.
let refreshPromise: Promise<boolean> | null = null;

async function refreshAccessToken(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    const refreshToken = getRefreshToken();
    if (!refreshToken) return false;

    try {
      const res = await fetch("/api/v1/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!res.ok) {
        clearTokens();
        return false;
      }
      const data = await res.json();
      setTokens(data.access_token, data.refresh_token);
      return true;
    } catch {
      clearTokens();
      return false;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  isFormData?: boolean;
  // Skips auth header + 401 refresh handling — only for /auth/login
  // and /auth/refresh themselves.
  skipAuth?: boolean;
}

async function request<T>(path: string, opts: RequestOptions = {}, isRetry = false): Promise<T> {
  const headers: Record<string, string> = {};
  let body: BodyInit | undefined;

  if (opts.isFormData) {
    body = opts.body as FormData;
  } else if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }

  if (!opts.skipAuth) {
    const token = getAccessToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(path, { method: opts.method ?? "GET", headers, body });

  if (res.status === 401 && !opts.skipAuth && !isRetry) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      return request<T>(path, opts, true);
    }
    clearTokens();
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new ApiError(401, "Session expired");
  }

  if (!res.ok) {
    let message = res.statusText;
    try {
      const data = await res.json();
      message = data.error ?? message;
    } catch {
      // response body wasn't JSON — fall back to statusText above
    }
    throw new ApiError(res.status, message);
  }

  if (res.status === 204) return undefined as T;

  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return res.json() as Promise<T>;
  }
  // Binary downloads (report generation) — caller handles the blob.
  return res as unknown as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, bodyData?: unknown) => request<T>(path, { method: "POST", body: bodyData }),
  patch: <T>(path: string, bodyData?: unknown) => request<T>(path, { method: "PATCH", body: bodyData }),
  postForm: <T>(path: string, formData: FormData) => request<T>(path, { method: "POST", body: formData, isFormData: true }),
  postAuth: <T>(path: string, bodyData: unknown) => request<T>(path, { method: "POST", body: bodyData, skipAuth: true }),
  // Binary downloads (report generation/download) share the same
  // pipeline as every other request — auth header attached, 401
  // triggers the same de-duplicated refresh-and-retry — rather than
  // callers reaching into localStorage and hand-rolling fetch() the
  // way the reports page originally did. request() already returns
  // the raw Response for non-JSON content types (see the branch at
  // the bottom of request()); these just add the .blob() step and a
  // clear name so call sites don't need to know that implementation
  // detail.
  getBlob: async (path: string): Promise<Blob> => {
    const res = await request<Response>(path);
    return res.blob();
  },
  postBlob: async (path: string): Promise<Blob> => {
    const res = await request<Response>(path, { method: "POST" });
    return res.blob();
  },
};

export function isAuthenticated(): boolean {
  return getAccessToken() !== null;
}
