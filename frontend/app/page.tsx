"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import dynamic from "next/dynamic";
import Link from "next/link";
import GatorMascot from "./GatorMascot";
import { apiFetch, clearToken, getToken } from "./apiClient";

const TerminalView = dynamic(() => import("./TerminalView"), { ssr: false });

// Agrupado por tipo de vulnerabilidade — escala bem conforme mais tipos
// e mais variantes forem entrando (cada grupo vira um <optgroup>).
const PROMPT_SUGGESTIONS: { category: string; variants: { label: string; text: string }[] }[] = [
  {
    category: "SQL Injection",
    variants: [
      {
        label: "Login (completo, 2 fases)",
        text: "máquina Linux com SQLi na tela de login, flag em /root/flag.txt",
      },
      {
        label: "Login — iniciante (erro SQL visível)",
        text: "SQLi na tela de login, algo fácil pra quem tá aprendendo",
      },
      {
        label: "Login — avançado (blind, sem retorno)",
        text: "SQLi avançado na tela de login, cego, sem retorno direto de dados",
      },
      {
        label: "Busca de produtos (simples, 1 fase)",
        text: "sistema de busca de produtos vulnerável a SQL Injection, algo simples e rápido",
      },
    ],
  },
  {
    category: "Command Injection",
    variants: [
      {
        label: "Diagnóstico de rede",
        text: "ferramenta de diagnóstico de rede vulnerável a injeção de comandos",
      },
      {
        label: "Diagnóstico de rede — avançado (cego, OOB)",
        text: "ferramenta de diagnóstico de rede vulnerável a comandos, avançado, execução cega",
      },
      {
        label: "Visualizador de logs (via URL)",
        text: "visualizador de logs vulnerável a injeção de comandos via parâmetro na URL",
      },
    ],
  },
];

interface ScenarioSpec {
  name: string;
  base_image: string;
  vulnerability_type: string;
  difficulty: string;
  setup_commands: string[];
  flag_location: string;
  hints: string[];
}

interface SpawnAccepted {
  job_id: string;
  instance_id: string;
  container_name: string;
  attacker_container_name: string;
  target_host_port: number | null;
  spec: ScenarioSpec;
  status: string;
}

interface JobStatus {
  status: "pending" | "running" | "done" | "error";
  instance_id: string;
  container_name: string;
  attacker_container_name?: string;
  target_host_port?: number | null;
  spec: ScenarioSpec;
  setup_success?: boolean;
  flag_placed?: boolean;
  error?: string;
}

export default function Home() {
  const router = useRouter();
  const [authChecked, setAuthChecked] = useState(false);
  const [description, setDescription] = useState(
    "máquina Linux com SQLi na tela de login, flag em /root/flag.txt"
  );
  const [loading, setLoading] = useState(false);
  const [spawnResult, setSpawnResult] = useState<SpawnAccepted | null>(null);
  const [job, setJob] = useState<JobStatus | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [destroying, setDestroying] = useState(false);
  const [destroyed, setDestroyed] = useState(false);
  const [terminalTabs, setTerminalTabs] = useState<{ id: number; remountKey: number }[]>([
    { id: 0, remountKey: 0 },
  ]);
  const [activeTabId, setActiveTabId] = useState(0);
  const nextTabId = useRef(1);
  const [flagInput, setFlagInput] = useState("");
  const [flagStage, setFlagStage] = useState<"user" | "root" | "done">("user");
  const [flagWrong, setFlagWrong] = useState(false);
  const [justUnlockedRoot, setJustUnlockedRoot] = useState(false);
  const [submittingFlag, setSubmittingFlag] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!getToken()) {
      router.push("/login");
      return;
    }
    setAuthChecked(true);
  }, [router]);

  const handleLogout = () => {
    clearToken();
    router.push("/login");
  };

  const startPolling = (jobId: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const res = await apiFetch("/scenarios/jobs/" + jobId);
        if (!res.ok) return;
        const data: JobStatus = await res.json();
        setJob(data);
        if (data.status === "done" || data.status === "error") {
          if (pollRef.current) clearInterval(pollRef.current);
        }
      } catch {
        // silencioso: próxima iteração tenta de novo
      }
    }, 4000);
  };

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const handleSubmit = async () => {
    setLoading(true);
    setErrorMsg(null);
    setSpawnResult(null);
    setJob(null);
    setDestroyed(false);
    setTerminalTabs([{ id: 0, remountKey: 0 }]);
    setActiveTabId(0);
    nextTabId.current = 1;
    setFlagInput("");
    setFlagStage("user");
    setFlagWrong(false);
    setJustUnlockedRoot(false);

    try {
      const res = await apiFetch("/scenarios/generate-and-spawn", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description }),
      });

      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || ("Erro " + res.status));
      }

      const data: SpawnAccepted = await res.json();
      setSpawnResult(data);
      setJob({
        status: "pending",
        instance_id: data.instance_id,
        container_name: data.container_name,
        attacker_container_name: data.attacker_container_name,
        target_host_port: data.target_host_port,
        spec: data.spec,
      });
      startPolling(data.job_id);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Erro desconhecido");
    } finally {
      setLoading(false);
    }
  };

  const handleDestroy = async () => {
    if (!job) return;
    setDestroying(true);
    try {
      await apiFetch("/instances", { method: "DELETE" });
      setDestroyed(true);
    } catch {
      setErrorMsg("Falha ao encerrar o cenário. Verifique o backend.");
    } finally {
      setDestroying(false);
    }
  };

  const handleSubmitFlag = async () => {
    if (!job || !flagInput.trim()) return;
    setSubmittingFlag(true);
    setFlagWrong(false);
    setJustUnlockedRoot(false);
    try {
      const res = await apiFetch("/instances/" + job.instance_id + "/submit-flag", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flag: flagInput.trim() }),
      });
      const data = await res.json();
      if (!data.correct) {
        setFlagWrong(true);
        return;
      }
      setFlagInput("");
      if (data.fully_complete) {
        setFlagStage("done");
      } else if (data.stage === "user" && data.has_root_stage) {
        setFlagStage("root");
        setJustUnlockedRoot(true);
      }
    } catch {
      setFlagWrong(true);
    } finally {
      setSubmittingFlag(false);
    }
  };

  const addTerminalTab = () => {
    const id = nextTabId.current++;
    setTerminalTabs((prev) => [...prev, { id, remountKey: 0 }]);
    setActiveTabId(id);
  };

  const closeTerminalTab = (id: number) => {
    setTerminalTabs((prev) => {
      if (prev.length <= 1) return prev; // sempre deixa pelo menos uma aba
      const filtered = prev.filter((t) => t.id !== id);
      if (activeTabId === id) {
        setActiveTabId(filtered[0].id);
      }
      return filtered;
    });
  };

  const refreshActiveTab = () => {
    setTerminalTabs((prev) =>
      prev.map((t) => (t.id === activeTabId ? { ...t, remountKey: t.remountKey + 1 } : t))
    );
  };

  if (!authChecked) {
    return null;
  }

  const statusClass = job ? "status status-" + job.status : "";

  return (
    <main>
      <div className="brand-row" style={{ justifyContent: "space-between" }}>
        <div className="brand-row" style={{ marginBottom: 0 }}>
          <GatorMascot size={64} />
          <h1 className="brand-title">CYBERLAB</h1>
        </div>
        <div style={{ display: "flex", gap: "0.6rem" }}>
          <Link href="/history">
            <button style={{ background: "var(--bg-raised)", color: "var(--text)", marginTop: 0 }}>
              Meu histórico
            </button>
          </Link>
          <Link href="/analytics">
            <button style={{ background: "var(--bg-raised)", color: "var(--text)", marginTop: 0 }}>
              Analytics
            </button>
          </Link>
          <button onClick={handleLogout} style={{ background: "var(--bg-raised)", color: "var(--text)", marginTop: 0 }}>
            Sair
          </button>
        </div>
      </div>
      <p className="subtitle">Descreva um cenário e a LLM monta o ambiente vulnerável.</p>

      <textarea
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        placeholder="Ex: máquina Linux com SQLi na tela de login, flag em /root/flag.txt"
      />

      <div style={{ marginTop: "0.6rem" }}>
        <label style={{ display: "block", marginBottom: "0.3rem", fontSize: "0.8rem", color: "var(--text-dim)" }}>
          Ou escolhe um exemplo pronto:
        </label>
        <select
          onChange={(e) => {
            if (e.target.value) setDescription(e.target.value);
            e.target.selectedIndex = 0;
          }}
          defaultValue=""
          style={{
            width: "100%",
            padding: "0.6rem",
            border: "3px solid var(--outline)",
            background: "var(--bg-raised)",
            color: "var(--text)",
            fontFamily: "var(--font-mono-pixel), monospace",
            fontSize: "1.05rem",
          }}
        >
          <option value="" disabled>
            -- escolher exemplo --
          </option>
          {PROMPT_SUGGESTIONS.map((group) => (
            <optgroup key={group.category} label={group.category}>
              {group.variants.map((v) => (
                <option key={v.label} value={v.text}>
                  {v.label}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
      </div>

      <br />
      <button onClick={handleSubmit} disabled={loading || !description.trim()}>
        {loading ? "Gerando..." : "Gerar e spawnar cenário"}
      </button>

      {errorMsg && (
        <div className="card" style={{ borderColor: "var(--accent)" }}>
          <strong style={{ color: "var(--accent)" }}>Erro:</strong> {errorMsg}
        </div>
      )}

      {job && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "0.5rem" }}>
            <strong style={{ fontSize: "1.2rem" }}>{job.spec.name}</strong>
            <span className={statusClass}>{job.status}</span>
          </div>
          <p style={{ color: "var(--text-dim)", fontSize: "0.95rem" }}>
            {job.spec.vulnerability_type} · {job.spec.difficulty} · <code>{job.spec.base_image}</code>
          </p>

          {job.status === "done" && (
            <p>
              Setup: {job.setup_success ? "✅ concluído" : "⚠️ com falhas"} · Flag:{" "}
              {job.flag_placed ? "✅ posicionada" : "❌ não encontrada"}
            </p>
          )}

          {job.target_host_port && (
            <p>
              Alvo:{" "}
              <a
                href={"http://localhost:" + job.target_host_port}
                target="_blank"
                rel="noopener noreferrer"
              >
                http://localhost:{job.target_host_port}
              </a>{" "}
              <span style={{ color: "var(--text-dim)", fontSize: "0.85rem" }}>
                (pode levar um tempo até o serviço responder, enquanto o setup roda)
              </span>
            </p>
          )}

          {job.status === "error" && (
            <p style={{ color: "var(--accent)" }}>Erro: {job.error}</p>
          )}

          {job.spec.hints?.length > 0 && (
            <div className="hints">
              <strong>Dicas:</strong>
              <ul>
                {job.spec.hints.map((h, i) => (
                  <li key={i}>{h}</li>
                ))}
              </ul>
            </div>
          )}

          {job.status === "done" && flagStage !== "done" && (
            <div style={{ marginTop: "1rem" }}>
              {justUnlockedRoot && (
                <p style={{ color: "var(--primary)" }}>
                  🔓 Fase 1 completa! Agora escala privilégio (SSH + sudo) pra pegar a segunda flag.
                </p>
              )}
              <label style={{ display: "block", marginBottom: "0.4rem", fontSize: "0.9rem" }}>
                {flagStage === "root" ? "Flag da fase 2 (root):" : "Achou a flag? Cola ela aqui:"}
              </label>
              <input
                type="text"
                value={flagInput}
                onChange={(e) => setFlagInput(e.target.value)}
                placeholder="CYBERLAB{...}"
                style={{
                  width: "100%",
                  padding: "0.6rem",
                  border: "3px solid var(--outline)",
                  background: "var(--bg-raised)",
                  color: "var(--text)",
                  fontFamily: "var(--font-mono-pixel), monospace",
                  fontSize: "1.1rem",
                  marginBottom: "0.5rem",
                }}
              />
              <button onClick={handleSubmitFlag} disabled={submittingFlag || !flagInput.trim()}>
                {submittingFlag ? "Conferindo..." : "Submeter flag"}
              </button>
              {flagWrong && (
                <p style={{ color: "var(--accent)" }}>❌ Flag incorreta. Tenta de novo.</p>
              )}
            </div>
          )}

          {flagStage === "done" && (
            <p style={{ color: "var(--primary)", marginTop: "1rem", fontSize: "1.1rem" }}>
              🏆 Cenário totalmente resolvido e salvo no seu histórico.
            </p>
          )}

          {!destroyed && (job.status === "running" || job.status === "done") && (
            <button
              onClick={handleDestroy}
              disabled={destroying}
              style={{ background: "var(--accent)", marginTop: "1rem" }}
            >
              {destroying ? "Encerrando..." : "Encerrar cenário (limpa todos os pendentes)"}
            </button>
          )}

          {destroyed && (
            <p style={{ color: "var(--primary)", marginTop: "1rem" }}>
              ✅ Cenário encerrado — containers e rede removidos.
            </p>
          )}
        </div>
      )}

      {job && !destroyed && (job.status === "running" || job.status === "done") && (
        <>
          <div
            style={{
              display: "flex",
              gap: "0.4rem",
              marginTop: "1rem",
              flexWrap: "wrap",
              alignItems: "center",
            }}
          >
            {terminalTabs.map((tab, idx) => (
              <button
                key={tab.id}
                onClick={() => setActiveTabId(tab.id)}
                style={{
                  marginTop: 0,
                  background: tab.id === activeTabId ? "var(--primary)" : "var(--bg-raised)",
                  color: tab.id === activeTabId ? "var(--outline)" : "var(--text)",
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                }}
              >
                Terminal {idx + 1}
                {terminalTabs.length > 1 && (
                  <span
                    onClick={(e) => {
                      e.stopPropagation();
                      closeTerminalTab(tab.id);
                    }}
                    style={{ fontWeight: "bold" }}
                  >
                    ×
                  </span>
                )}
              </button>
            ))}
            <button onClick={addTerminalTab} style={{ marginTop: 0, background: "var(--primary)" }}>
              + Novo terminal
            </button>
            <button onClick={refreshActiveTab} style={{ marginTop: 0, background: "var(--info)" }}>
              Refresh terminal
            </button>
          </div>

          {terminalTabs.map((tab) => (
            <div key={tab.id} style={{ display: tab.id === activeTabId ? "block" : "none" }}>
              <TerminalView key={tab.id + "-" + tab.remountKey} instanceId={job.instance_id} />
            </div>
          ))}
        </>
      )}
    </main>
  );
}
