/** @type {import('next').NextConfig} */
const nextConfig = {
  // Allow Puppeteer to find Chrome bundled with the package
  experimental: {
    serverComponentsExternalPackages: ["puppeteer"],
  },
};

module.exports = nextConfig;
