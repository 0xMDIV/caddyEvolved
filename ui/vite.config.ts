import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built assets are embedded into the Go binary via internal/webui (embed.FS).
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "../internal/webui/dist",
    emptyOutDir: true,
    assetsDir: "assets",
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "https://127.0.0.1:8484", secure: false, changeOrigin: true },
    },
  },
});
