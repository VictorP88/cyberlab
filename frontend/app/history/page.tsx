"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import GatorMascot from "../GatorMascot";
import { apiFetch, getToken } from "../apiClient";

interface HistoryItem {
  instance_id: string;
  scenario_name: string;
  vulnerability_type: string;
  difficulty: string;
  hints: string[];
  status: string;
  setup_success: boolean | null;
  flag_placed: boolean | null;
  solved: boolean;
  solved_at: string | null;
  has_root_stage: boolean;
  root_solved: boolean;
  root_solved_at: string | null;
  target_host_port: number | null;
  created_at: string;
  destroyed_at: string | null;
}

function formatDuration(startIso: string, endIso: string): string {
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime();
  if (ms < 0) return "—";
  const totalSeconds = Math.round(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes === 0) return seconds + "s";
  return minutes + "min " + seconds + "s";
}

export default function HistoryPage() {
  const router = useRouter();
  const [authChecked, setAuthChecked] = useState(false);
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    if (!getToken()) {
      router.push("/login");
      return;
    }
    setAuthChecked(true);
  }, [router]);

  useEffect(() => {
    if (!authChecked) return;
    (async () => {
      try {
        const res = await apiFetch("/instances/history?limit=50&mine_only=true");
        if (res.ok) {
          setItems(await res.json());
        }
      } finally {
        setLoading(false);
      }
    })();
  }, [authChecked]);

  if (!authChecked) return null;

  const isFullyComplete = (i: HistoryItem) => i.solved && (!i.has_root_stage || i.root_solved);
  const completeItems = items.filter(isFullyComplete);
  const solvedCount = completeItems.length;

  const avgDuration = (() => {
    const durationsMs = completeItems
      .map((i) => {
        const endIso = i.has_root_stage ? i.root_solved_at : i.solved_at;
        if (!endIso) return null;
        return new Date(endIso).getTime() - new Date(i.created_at).getTime();
      })
      .filter((ms): ms is number => ms !== null && ms >= 0);
    if (durationsMs.length === 0) return null;
    const avgMs = durationsMs.reduce((a, b) => a + b, 0) / durationsMs.length;
    const minutes = Math.floor(avgMs / 60000);
    const seconds = Math.round((avgMs % 60000) / 1000);
    return minutes === 0 ? seconds + "s" : minutes + "min " + seconds + "s";
  })();

  return (
    <main>
      <div className="brand-row" style={{ justifyContent: "space-between" }}>
        <div className="brand-row" style={{ marginBottom: 0 }}>
          <GatorMascot size={64} />
          <h1 className="brand-title">CYBERLAB</h1>
        </div>
        <Link href="/">
          <button style={{ background: "var(--bg-raised)", color: "var(--text)", marginTop: 0 }}>
            Voltar
          </button>
        </Link>
      </div>
      <p className="subtitle">
        Meu histórico — {solvedCount} de {items.length} cenário(s) resolvido(s)
        {avgDuration && <> · tempo médio: {avgDuration}</>}
      </p>

      {loading && <p>Carregando...</p>}

      {!loading && items.length === 0 && (
        <div className="card">
          <p>Nenhum cenário ainda. Volta pra página principal e gera o primeiro.</p>
        </div>
      )}

      {items.map((item) => {
        const isExpanded = expandedId === item.instance_id;
        const fullyComplete = isFullyComplete(item);
        return (
          <div
            key={item.instance_id}
            className="card"
            style={{ cursor: "pointer" }}
            onClick={() => setExpandedId(isExpanded ? null : item.instance_id)}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "0.5rem" }}>
              <strong style={{ fontSize: "1.1rem" }}>{item.scenario_name}</strong>
              <span className={"status status-" + (fullyComplete ? "done" : item.status)}>
                {fullyComplete ? "resolvido" : item.status}
              </span>
            </div>
            <p style={{ color: "var(--text-dim)", fontSize: "0.9rem" }}>
              {item.vulnerability_type} · {item.difficulty} · gerado em{" "}
              {new Date(item.created_at).toLocaleString("pt-BR")}
            </p>
            {item.solved && item.solved_at && (
              <p style={{ color: "var(--primary)", fontSize: "0.9rem" }}>
                🏆 Fase 1 (usuário) em {new Date(item.solved_at).toLocaleString("pt-BR")} · levou{" "}
                {formatDuration(item.created_at, item.solved_at)}
              </p>
            )}
            {item.has_root_stage && (
              <p style={{ color: item.root_solved ? "var(--primary)" : "var(--text-dim)", fontSize: "0.9rem" }}>
                {item.root_solved && item.root_solved_at
                  ? "🏆 Fase 2 (root) em " + new Date(item.root_solved_at).toLocaleString("pt-BR")
                  : "🔒 Fase 2 (root) ainda não resolvida"}
              </p>
            )}

            {isExpanded && (
              <div
                style={{
                  marginTop: "0.8rem",
                  paddingTop: "0.8rem",
                  borderTop: "2px solid var(--outline)",
                }}
              >
                {item.hints?.length > 0 && (
                  <div className="hints">
                    <strong>Dicas que apareceram:</strong>
                    <ul>
                      {item.hints.map((h, i) => (
                        <li key={i}>{h}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <p style={{ color: "var(--text-dim)", fontSize: "0.85rem", marginTop: "0.6rem" }}>
                  ID da instância: <code>{item.instance_id}</code>
                </p>
              </div>
            )}

            <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginTop: "0.5rem" }}>
              {isExpanded ? "▲ clique pra recolher" : "▼ clique pra ver detalhes"}
            </p>
          </div>
        );
      })}
    </main>
  );
}
