import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow any LAN device to access the dev server
  allowedDevOrigins: ["10.0.0.*", "10.0.*", "192.168.*.*", "172.16.*.*", "172.31.*.*"],
};

export default nextConfig;
