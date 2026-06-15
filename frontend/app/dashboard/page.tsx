"use client";

import { Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import SessionSecurityStrip from "../../components/SessionSecurityStrip";
import { useSessionSecurity } from "../../lib/useSessionSecurity";

function Dashboard() {
  const sid = useSearchParams().get("sid");
  const { result } = useSessionSecurity(sid, "open_dashboard");

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
          <h1>Welcome back</h1>
          <p className="lede">Your campus overview. Open the security strip above to see how this session is being assessed.</p>
          <table>
            <thead><tr><th>Item</th><th>Status</th></tr></thead>
            <tbody>
              <tr><td>Enrolled modules</td><td>5</td></tr>
              <tr><td>Pending submissions</td><td>2</td></tr>
              <tr><td>Attendance this week</td><td>92%</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

export default function DashboardPage() {
  return (
    <Suspense fallback={null}>
      <Dashboard />
    </Suspense>
  );
}
