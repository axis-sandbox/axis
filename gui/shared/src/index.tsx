// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

import { render } from "solid-js/web";
import App from "./App";

const root = document.getElementById("root");
if (root) {
  render(() => <App />, root);
}
