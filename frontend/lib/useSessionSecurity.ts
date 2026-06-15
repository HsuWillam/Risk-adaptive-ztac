"use client";

import { useCallback, useEffect, useState } from "react";
import { evaluate, type PepResult } from "../lib/api";
import { fingerprintOnInteraction } from "../lib/fingerprint";

/**
 * Continuous re-evaluation: re-runs the PEP for a given action whenever a
 * protected page mounts or an action is taken, and exposes the latest result
 * for the Session security strip. This is the Zero Trust "always verify"
 * loop, not a one-time login check.
 */
export function useSessionSecurity(sessionId: string | null, action: string) {
  const [result, setResult] = useState<PepResult | null>(null);
  const [loading, setLoading] = useState(false);

  const reevaluate = useCallback(
    async (overrideAction?: string) => {
      if (!sessionId) return null;
      setLoading(true);
      const fp = await fingerprintOnInteraction();
      const res = await evaluate(sessionId, overrideAction ?? action, fp);
      setResult(res);
      setLoading(false);
      return res;
    },
    [sessionId, action]
  );

  useEffect(() => {
    void reevaluate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  return { result, loading, reevaluate };
}
