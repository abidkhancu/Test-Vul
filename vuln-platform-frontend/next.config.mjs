/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Required for the Dockerfile's multi-stage build, which copies
  // only .next/standalone + .next/static into the runtime image
  // rather than shipping node_modules wholesale.
  output: "standalone",
  // The Go backend is a separate service (see ../README.md). In
  // production, put this behind the same ingress/reverse proxy as
  // the API (or set NEXT_PUBLIC_API_URL to the API's public URL) —
  // this rewrite is a local-dev convenience so the browser can call
  // relative /api/v1/* paths without CORS configuration on the Go
  // side.
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: `${process.env.API_PROXY_TARGET || "http://localhost:8080"}/api/v1/:path*`,
      },
    ];
  },
};

export default nextConfig;
