/** Typed client for the Flask ZTAC API. */
import type { Fingerprint } from "./fingerprint";

const BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:5000";

export type Decision = "ALLOW" | "MFA" | "RESTRICTED" | "DENY";

export interface Explanation {
  brief: string;
  full: string;
}

export interface PepResult {
  ok: boolean;
  decision: Decision;
  risk_score: number;
  sub_scores: { C: number; B: number };
  factors: Record<string, number>;
  explanation: Explanation;
  session_id?: string;
  error?: string;
  attempts_remaining?: number;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return (await res.json()) as T;
}

export function login(username: string, password: string, fingerprint: Fingerprint, failedAttempts = 0) {
  return post<PepResult>("/api/auth/login", { username, password, fingerprint, failed_attempts: failedAttempts });
}

export function verifyMfa(sessionId: string, code: string) {
  return post<PepResult>("/api/auth/mfa", { session_id: sessionId, code });
}

export function evaluate(sessionId: string, action: string, fingerprint: Fingerprint) {
  return post<PepResult>("/api/session/evaluate", { session_id: sessionId, action, fingerprint });
}

export async function auditHistory(sessionId: string) {
  const res = await fetch(`${BASE}/api/audit/history?session_id=${encodeURIComponent(sessionId)}`);
  return res.json();
}
