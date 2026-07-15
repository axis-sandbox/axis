// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export async function verifyDist(distDir) {
  const resolvedDistDir = path.resolve(distDir);
  const html = await readFile(path.join(resolvedDistDir, "index.html"), "utf8");

  if (/<base\b/i.test(html)) {
    throw new Error("dist/index.html must not override its relative base URL");
  }

  const references = [];
  for (const element of html.matchAll(/<(script|link)\b[^>]*>/gi)) {
    const attribute = element[1].toLowerCase() === "script" ? "src" : "href";
    const assigned = new RegExp(`\\b${attribute}\\s*=`, "i").test(element[0]);
    const quoted = new RegExp(`\\b${attribute}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, "i").exec(
      element[0],
    );
    if (assigned && quoted === null) {
      throw new Error(`dist/index.html ${attribute} attributes must be quoted`);
    }
    if (quoted !== null) references.push(quoted[1] ?? quoted[2]);
  }

  if (!references.some((reference) => reference.split(/[?#]/, 1)[0].endsWith(".js"))) {
    throw new Error("dist/index.html does not reference a JavaScript asset");
  }

  for (const reference of references) {
    if (!reference.startsWith("./")) {
      throw new Error(`dist/index.html asset URL must be relative: ${reference}`);
    }
    const assetPath = path.resolve(resolvedDistDir, reference.split(/[?#]/, 1)[0]);
    if (!assetPath.startsWith(`${resolvedDistDir}${path.sep}`)) {
      throw new Error(`dist/index.html asset URL escapes dist: ${reference}`);
    }
    await access(assetPath);
  }

  return references.length;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const count = await verifyDist(path.join(projectDir, "dist"));
  console.log(`Verified ${count} relative frontend asset references`);
}
