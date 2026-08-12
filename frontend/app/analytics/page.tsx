"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import GatorMascot from "../GatorMascot";
import { apiFetch, getToken } from "../apiClient";

interface AnalyticsGroup {
  vulnerability_type: string;
  variant: string;
  difficulty: string;
  total_generated: number;
  setup_success_rate: number | null;
  user_flag_solve_rate: number | null;
  has_root_stage: boolean;
  root_flag_solve_rate: number | null;
  abandoned_count: number;
  avg_time_to_user_flag_seconds: number | null;
  avg_time_to_root_flag_seconds: number | null;
  avg_time_root_phase_only_seconds: number | null;
  avg_wrong_attempts_user: number | null;
  avg_wrong_attempts_root: number | null;
}

function formatSeconds(seconds: number | null): string {
  if (seconds === null) return "—";
  const minutes = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return minutes === 0 ? secs + "s" : minutes + "min " + secs + "s";
}

function formatPct(rate: number | null): string {
  if (rate === null) return "—";
  return Math.round(rate * 100) + "%";
}

function Bar({ rate, color }: { rate: number | null; color: string }) {
  const pct = rate === null ? 0 : Math.round(rate * 100);
  return (
    <div style={{ background: "var(--bg-raised)", border: "2px solid var(--outline)", height: "14px", width: "100%" }}>
      <div style={{ background: color, height: "100%", width: pct + "%" }} />
    </div>
  );
}

export default function AnalyticsPage() {
  const router = useRouter();
  const [authChecked, setAuthChecked] = useState(false);
  const [groups, setGroups] = useState<AnalyticsGroup[]>([]);
  const [loading, setLoading] = useState(true);

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
        const res = await apiFetch("/instances/analytics");
        if (res.ok) {
          setGroups(await res.json());
        }
      } finally {
        setLoading(false);
      }
    })();
  }, [authChecked]);

  if (!authChecked) return null;

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
        Analytics — taxa de conclusão, tempo médio e onde as pessoas travam, por tipo de cenário.
      </p>

      {loading && <p>Carregando...</p>}

      {!loading && groups.length === 0 && (
        <div className="card">
          <p>Ainda não há dados suficientes. Gera e resolve alguns cenários primeiro.</p>
        </div>
      )}

      {groups.map((g) => (
        <div key={g.vulnerability_type + g.variant + g.difficulty} className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "0.5rem" }}>
            <strong style={{ fontSize: "1.1rem" }}>
              {g.vulnerability_type} · {g.variant} · {g.difficulty}
            </strong>
            <span className="status status-done">{g.total_generated} gerado(s)</span>
          </div>

          <div style={{ marginTop: "0.8rem" }}>
            <p style={{ fontSize: "0.85rem", color: "var(--text-dim)", marginBottom: "0.2rem" }}>
              Confiabilidade do setup (infra): {formatPct(g.setup_success_rate)}
            </p>
            <Bar rate={g.setup_success_rate} color="var(--info)" />
          </div>

          <div style={{ marginTop: "0.8rem" }}>
            <p style={{ fontSize: "0.85rem", color: "var(--text-dim)", marginBottom: "0.2rem" }}>
              Resolveram fase 1: {formatPct(g.user_flag_solve_rate)} · tempo médio:{" "}
              {formatSeconds(g.avg_time_to_user_flag_seconds)} · tentativas erradas médias:{" "}
              {g.avg_wrong_attempts_user ?? "—"}
            </p>
            <Bar rate={g.user_flag_solve_rate} color="var(--primary)" />
          </div>

          {g.has_root_stage && (
            <div style={{ marginTop: "0.8rem" }}>
              <p style={{ fontSize: "0.85rem", color: "var(--text-dim)", marginBottom: "0.2rem" }}>
                Resolveram fase 2 (root): {formatPct(g.root_flag_solve_rate)} · tempo médio (fase 2 só):{" "}
                {formatSeconds(g.avg_time_root_phase_only_seconds)} · tentativas erradas médias:{" "}
                {g.avg_wrong_attempts_root ?? "—"}
              </p>
              <Bar rate={g.root_flag_solve_rate} color="var(--accent)" />
            </div>
          )}

          <p style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "0.6rem" }}>
            Abandonados (encerrados sem resolver): {g.abandoned_count}
          </p>
        </div>
      ))}
    </main>
  );
}
