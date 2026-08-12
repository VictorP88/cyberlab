"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import GatorMascot from "../GatorMascot";
import { API_BASE, setToken } from "../apiClient";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch(API_BASE + "/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Usuário ou senha inválidos");
      }
      const data = await res.json();
      setToken(data.access_token);
      router.push("/");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Erro desconhecido");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main style={{ maxWidth: "420px" }}>
      <div className="brand-row" style={{ justifyContent: "center", marginTop: "3rem" }}>
        <GatorMascot size={64} />
        <h1 className="brand-title">CYBERLAB</h1>
      </div>
      <p className="subtitle" style={{ textAlign: "center" }}>
        Entre pra gerar e explorar cenários.
      </p>

      <form onSubmit={handleSubmit} className="card">
        <label style={{ display: "block", marginBottom: "0.4rem", fontSize: "0.9rem" }}>
          Usuário
        </label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
          style={{
            width: "100%",
            padding: "0.7rem",
            border: "3px solid var(--outline)",
            background: "var(--bg-raised)",
            color: "var(--text)",
            fontFamily: "var(--font-mono-pixel), monospace",
            fontSize: "1.1rem",
            marginBottom: "1rem",
          }}
        />

        <label style={{ display: "block", marginBottom: "0.4rem", fontSize: "0.9rem" }}>
          Senha
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{
            width: "100%",
            padding: "0.7rem",
            border: "3px solid var(--outline)",
            background: "var(--bg-raised)",
            color: "var(--text)",
            fontFamily: "var(--font-mono-pixel), monospace",
            fontSize: "1.1rem",
            marginBottom: "1rem",
          }}
        />

        {errorMsg && (
          <p style={{ color: "var(--accent)", marginBottom: "0.5rem" }}>{errorMsg}</p>
        )}

        <button type="submit" disabled={loading || !username || !password} style={{ width: "100%" }}>
          {loading ? "Entrando..." : "Entrar"}
        </button>
      </form>
    </main>
  );
}
