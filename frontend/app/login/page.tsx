"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { login, verifyMfa, type PepResult } from "../../lib/api";
import { collectFingerprint } from "../../lib/fingerprint";
import SessionSecurityStrip from "../../components/SessionSecurityStrip";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("student01");
  const [password, setPassword] = useState("password123");
  const [failed, setFailed] = useState(0);
  const [result, setResult] = useState<PepResult | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [stage, setStage] = useState<"login" | "mfa">("login");

  async function handleLogin() {
    setError("");
    const fp = collectFingerprint();
    const res = await login(username, password, fp, failed);
    if (!res.ok && res.error) {
      setFailed((f) => f + 1);
      setError(res.error);
      return;
    }
    setResult(res);
    setSessionId(res.session_id ?? null);
    routeOnDecision(res);
  }

  async function handleMfa() {
    setError("");
    if (!sessionId) return;
    const res = await verifyMfa(sessionId, code);
    setResult(res);
    if (res.ok) {
      router.push("/dashboard?sid=" + sessionId);
    } else {
      setError(res.error ?? res.explanation?.brief ?? "Verification failed.");
      if (res.decision === "DENY") setStage("login");
    }
  }

  function routeOnDecision(res: PepResult) {
    if (res.decision === "ALLOW" || res.decision === "RESTRICTED") {
      router.push("/dashboard?sid=" + res.session_id);
    } else if (res.decision === "MFA") {
      setStage("mfa");
    } else if (res.decision === "DENY") {
      setError(res.explanation.brief);
    }
  }

  return (
    <>
      <SessionSecurityStrip result={result} />
      <div className="shell">
        <div className="card" style={{ maxWidth: 420, margin: "40px auto" }}>
          <h1>Campus portal</h1>
          <p className="lede">Sign in to APU systems</p>

          {stage === "login" ? (
            <>
              <label>Username</label>
              <input value={username} onChange={(e) => setUsername(e.target.value)} />
              <label>Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
              <button className="btn" onClick={handleLogin}>Sign in</button>
            </>
          ) : (
            <>
              <p className="lede">Enter the 6-digit code from your authenticator app.</p>
              <label>One-time code</label>
              <input
                value={code}
                inputMode="numeric"
                maxLength={6}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                placeholder="000000"
              />
              <button className="btn" onClick={handleMfa}>Verify and continue</button>
              <button className="btn btn--ghost" onClick={() => { setStage("login"); setResult(null); }}>
                Back
              </button>
            </>
          )}
          {error && <p className="err">{error}</p>}
        </div>
      </div>
    </>
  );
}
