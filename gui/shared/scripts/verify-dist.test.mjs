// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { afterEach } from "node:test";
import { verifyDist } from "./verify-dist.mjs";

const fixtureRoots = new Set();

afterEach(async () => {
  const roots = [...fixtureRoots];
  fixtureRoots.clear();
  await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture(html, { withScript = true, withStyle = true } = {}) {
  const dist = await mkdtemp(path.join(tmpdir(), "axis-gui-dist-"));
  fixtureRoots.add(dist);
  await mkdir(path.join(dist, "assets"));
  await writeFile(path.join(dist, "index.html"), html);
  if (withScript) await writeFile(path.join(dist, "assets/app.js"), "");
  if (withStyle) await writeFile(path.join(dist, "assets/app.css"), "");
  return dist;
}

test("accepts existing relative script and stylesheet assets", async () => {
  const dist = await fixture(
    '<script src="./assets/app.js?rev=1"></script><link href="./assets/app.css" rel="stylesheet">',
  );
  assert.equal(await verifyDist(dist), 2);
});

test("rejects an HTML base element", async () => {
  await assert.rejects(
    verifyDist(await fixture('<base href="./"><script src="./assets/app.js"></script>')),
    /must not override/,
  );
});

test("rejects documents without a JavaScript asset", async () => {
  await assert.rejects(
    verifyDist(await fixture('<link href="./assets/app.css" rel="stylesheet">')),
    /does not reference a JavaScript/,
  );
});

test("rejects root-relative, remote, and parent asset URLs", async () => {
  for (const reference of ["/assets/app.js", "https://example.com/app.js", "./../app.js"]) {
    await assert.rejects(
      verifyDist(await fixture(`<script src="${reference}"></script>`)),
      /must be relative|escapes dist/,
    );
  }
});

test("rejects unquoted asset attributes", async () => {
  await assert.rejects(
    verifyDist(await fixture("<script src=/assets/app.js></script>")),
    /attributes must be quoted/,
  );
});

test("rejects references to missing assets", async () => {
  await assert.rejects(
    verifyDist(await fixture('<script src="./assets/app.js"></script>', { withScript: false })),
    /ENOENT/,
  );
});
