// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

export default defineConfig({
  base: "./",
  plugins: [solid()],
  build: {
    target: "esnext",
    outDir: "dist",
  },
  server: {
    port: 3000,
  },
});
