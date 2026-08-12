"use client";

import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { getToken } from "./apiClient";

interface Props {
  instanceId: string;
}

export default function TerminalView({ instanceId }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const termRef = useRef<Terminal | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    let disposed = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectAttempts = 0;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      theme: {
        background: "#060907",
        foreground: "#8fe6ab",
        cursor: "#39ff6a",
        selectionBackground: "#1c6b40",
      },
    });
    termRef.current = term;
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(containerRef.current);

    requestAnimationFrame(() => {
      fitAddon.fit();
    });

    const connect = () => {
      if (disposed) return;

      const token = getToken();
      const wsUrl =
        "ws://localhost:8000/instances/" + instanceId + "/terminal?token=" + encodeURIComponent(token || "");
      const socket = new WebSocket(wsUrl);
      socketRef.current = socket;

      socket.onopen = () => {
        reconnectAttempts = 0;
        term.writeln("\r\nConectado. Sessão de shell ativa.\r\n");
      };

      socket.onmessage = (event) => {
        term.write(event.data);
      };

      socket.onerror = () => {
        // onclose trata a reconexão; aqui só evitamos barulho no console.
      };

      socket.onclose = () => {
        if (disposed) return;
        reconnectAttempts += 1;
        const delaySeconds = Math.min(reconnectAttempts, 5);
        term.writeln(
          "\r\n[conexão perdida — reconectando em " + delaySeconds + "s...]"
        );
        reconnectTimer = setTimeout(connect, delaySeconds * 1000);
      };
    };

    term.writeln("Conectando ao container...\r\n");
    connect();

    term.onData((data) => {
      const socket = socketRef.current;
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(data);
      }
    });

    const handleResize = () => requestAnimationFrame(() => fitAddon.fit());
    window.addEventListener("resize", handleResize);

    return () => {
      disposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      window.removeEventListener("resize", handleResize);
      socketRef.current?.close();
      term.dispose();
    };
  }, [instanceId]);

  return (
    <div className="terminal-wrapper">
      <div className="terminal-header">Terminal — instância {instanceId}</div>
      <div
        className="terminal-container"
        ref={containerRef}
        onClick={() => termRef.current?.focus()}
      />
    </div>
  );
}
