import { onMount, onCleanup, createEffect } from "solid-js";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";
import { connectPty, type PtyConnection } from "../api/client";
import "@xterm/xterm/css/xterm.css";

interface TerminalProps {
  sandboxId: string | null;
}

export function Terminal(props: TerminalProps) {
  let containerRef!: HTMLDivElement;
  let term: XTerm | null = null;
  let fitAddon: FitAddon | null = null;
  let ptyConn: PtyConnection | null = null;

  onMount(() => {
    term = new XTerm({
      theme: {
        background: "#0d1117",
        foreground: "#e6edf3",
        cursor: "#58a6ff",
        selectionBackground: "#264f78",
      },
      fontFamily: '"Cascadia Code", "SF Mono", "Fira Code", monospace',
      fontSize: 13,
      cursorBlink: true,
    });

    fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(containerRef);

    // Try WebGL renderer for performance.
    try {
      term.loadAddon(new WebglAddon());
    } catch {
      // WebGL not available, fallback to canvas.
    }

    fitAddon.fit();

    // Handle window resize.
    const resizeObserver = new ResizeObserver(() => {
      fitAddon?.fit();
      if (ptyConn && term) {
        ptyConn.resize(term.cols, term.rows);
      }
    });
    resizeObserver.observe(containerRef);

    onCleanup(() => {
      resizeObserver.disconnect();
      ptyConn?.close();
      term?.dispose();
    });
  });

  // Connect/reconnect when sandboxId changes.
  createEffect(() => {
    const sandboxId = props.sandboxId;

    // Disconnect previous.
    if (ptyConn) {
      ptyConn.close();
      ptyConn = null;
    }

    if (!sandboxId || !term) {
      if (term) {
        term.clear();
        term.write("\r\n  No sandbox selected. Launch an agent to connect.\r\n");
      }
      return;
    }

    term.clear();
    term.write(`\r\n  Connecting to sandbox ${sandboxId}...\r\n`);

    ptyConn = connectPty(sandboxId);

    ptyConn.ws.onopen = () => {
      term!.clear();
      term!.write("\x1b[32mConnected to sandbox.\x1b[0m\r\n");
      term!.write("Waiting for agent to start...\r\n\r\n");
    };

    // Wire up the result callback to show prompt.
    onResultCallback = showPrompt;

    ptyConn.ws.onmessage = (msg) => {
      if (msg.data instanceof ArrayBuffer) {
        const view = new Uint8Array(msg.data);
        if (view[0] === 0x00) {
          // Data frame — may be raw text or stream-json lines.
          const text = new TextDecoder().decode(view.slice(1));
          renderOutput(term!, text);
        }
      } else if (typeof msg.data === "string") {
        renderOutput(term!, msg.data);
      }
    };

    ptyConn.ws.onclose = () => {
      term!.write("\r\n\r\n  [Connection closed]\r\n");
    };

    // Input is not yet supported (stdin is null in one-shot mode).
    // Interactive multi-turn requires ConPTY which is a future enhancement.
  });

  return (
    <div class="terminal-container" ref={containerRef} />
  );
}

/** Render output to the terminal, handling both raw text and Claude stream-json.
 *  Returns true if a "result" message was received (agent finished responding). */
let onResultCallback: (() => void) | null = null;

function renderOutput(term: XTerm, text: string) {
  // Try to parse each line as JSON (Claude stream-json format).
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      const msg = JSON.parse(trimmed);
      if (msg.type === "assistant" && msg.message?.content) {
        // Claude assistant message — render the text content.
        for (const block of msg.message.content) {
          if (block.type === "text") {
            term.write(block.text.replace(/\n/g, "\r\n"));
            term.write("\r\n");
          } else if (block.type === "tool_use") {
            term.write(`\x1b[36m[Tool: ${block.name}]\x1b[0m\r\n`);
          }
        }
      } else if (msg.type === "result") {
        // Final result — agent finished this turn.
        if (msg.result) {
          term.write(msg.result.replace(/\n/g, "\r\n"));
          term.write("\r\n");
        }
        term.write("\r\n\x1b[33m[Session complete — interactive mode coming soon]\x1b[0m\r\n");
      } else if (msg.type === "content_block_delta" && msg.delta?.text) {
        // Streaming text delta.
        term.write(msg.delta.text);
      } else if (msg.type === "error") {
        term.write(`\x1b[31m[Error: ${msg.error?.message || JSON.stringify(msg)}]\x1b[0m\r\n`);
      } else {
        // Unknown JSON type — show raw.
        term.write(trimmed + "\r\n");
      }
    } catch {
      // Not JSON — render as raw text.
      term.write(line);
      if (!text.endsWith("\n")) {
        // Don't add extra newlines for partial output.
      } else {
        term.write("\r\n");
      }
    }
  }
}
