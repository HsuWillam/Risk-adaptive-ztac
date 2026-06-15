"use client";

import { Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import SessionSecurityStrip from "../../components/SessionSecurityStrip";
import { useSessionSecurity } from "../../lib/useSessionSecurity";

function Transcript() {
  const sid = useSearchParams().get("sid");
  // Sensitive action -> continuous re-evaluation with A = 1.0
  const { result, loading } = useSessionSecurity(sid, "view_transcript");

  const blocked = result && (result.decision === "RESTRICTED" || result.decision === "DENY");

  return (
    <>
      <SessionSecurityStrip result={result} />
      <div className="shell">
        <nav className="nav">
          <Link href={`/dashboard?sid=${sid}`}>Dashboard</Link>
          <Link href={`/transcript?sid=${sid}`}>Transcript</Link>
          <Link href="/login">Sign out</Link>
        </nav>
        <div className="card">
          <h1>Academic transcript</h1>
          <p className="lede">A sensitive record. This view is re-evaluated on every visit.</p>

          {loading && <p className="lede">Checking session…</p>}

          {blocked ? (
            <div style={{ padding: "20px", border: "1px solid var(--line)", borderRadius: 10, background: "#faf7f3" }}>
              <strong>Transcript hidden</strong>
              <p className="lede" style={{ margin: "6px 0 0" }}>{result?.explanation.full}</p>
            </div>
          ) : (
            <table>
              <thead><tr><th>Module</th><th>Grade</th><th>Credits</th></tr></thead>
              <tbody>
                <tr><td>Network Security</td><td>A</td><td>4</td></tr>
                <tr><td>Distributed Systems</td><td>A-</td><td>4</td></tr>
                <tr><td>Cryptography</td><td>B+</td><td>3</td></tr>
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}

export default function TranscriptPage() {
  return (
    <Suspense fallback={null}>
      <Transcript />
    </Suspense>
  );
}
