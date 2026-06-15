"use client";

/**
 * Session security strip.
 *
 * The one element this app is remembered by: a docked security-telemetry bar
 * that surfaces every PEP decision. It carries (1) a decision pill, (2) a
 * four-band risk meter with a live marker at the current R, and (3) a layered
 * explanation — one line by default, expandable to the full reason.
 *
 * Layered explanation directly answers the IR survey result that 93.3% of
 * respondents want an explanation when a security action is enforced (Q18),
 * split between "brief is enough" (53.3%) and "full needed" (40%).
 */
import { useState } from "react";
import type { PepResult, Decision } from "../lib/api";

const DECISION_META: Record<Decision, { label: string; color: string }> = {
  ALLOW: { label: "Allowed", color: "var(--allow)" },
  MFA: { label: "Verify", color: "var(--mfa)" },
  RESTRICTED: { label: "Restricted", color: "var(--restricted)" },
  DENY: { label: "Blocked", color: "var(--deny)" },
};

// Band boundaries mirror the PEP thresholds (config.T_MFA / T_RESTRICTED / T_DENY).
const BANDS = [
  { key: "ALLOW", from: 0.0, to: 0.3, color: "var(--allow)" },
  { key: "MFA", from: 0.3, to: 0.55, color: "var(--mfa)" },
  { key: "RESTRICTED", from: 0.55, to: 0.8, color: "var(--restricted)" },
  { key: "DENY", from: 0.8, to: 1.0, color: "var(--deny)" },
];

export default function SessionSecurityStrip({ result }: { result: PepResult | null }) {
  const [open, setOpen] = useState(false);
  if (!result) return null;

  const meta = DECISION_META[result.decision];
  const r = result.risk_score;

  return (
    <div className="ssec" data-decision={result.decision}>
      <div className="ssec__row">
        <span className="ssec__eyebrow">Session security</span>

        <span className="ssec__pill" style={{ ["--pill" as any]: meta.color }}>
          <span className="ssec__dot" />
          {meta.label}
        </span>

        <div className="ssec__meter" role="img" aria-label={`Risk score ${r}`}>
          {BANDS.map((b) => (
            <div
              key={b.key}
              className="ssec__band"
              style={{ flex: b.to - b.from, background: b.color, opacity: result.decision === b.key ? 1 : 0.22 }}
            />
          ))}
          <div className="ssec__marker" style={{ left: `${Math.min(r, 1) * 100}%` }} />
        </div>

        <span className="ssec__score">
          R&nbsp;<b>{r.toFixed(2)}</b>
          <span className="ssec__sub">C {result.sub_scores.C.toFixed(2)} · B {result.sub_scores.B.toFixed(2)}</span>
        </span>

        <button className="ssec__toggle" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
          {result.explanation.brief}
          <span className={`ssec__chev ${open ? "is-open" : ""}`}>›</span>
        </button>
      </div>

      {open && (
        <div className="ssec__detail">
          <p>{result.explanation.full}</p>
          <div className="ssec__factors">
            {Object.entries(result.factors)
              .filter(([, v]) => v > 0)
              .map(([k, v]) => (
                <span key={k} className="ssec__factor">
                  {k} <b>{v}</b>
                </span>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}
