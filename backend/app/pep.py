"""
Policy Enforcement Point.

Maps the composite risk score R to one of four decisions using the strict
inequalities in config, and produces a layered plain-language explanation
(brief headline + full detail) — addressing the IR survey finding that 93.3%
of respondents want an explanation when a security action is enforced (Q18).
"""
import config

FACTOR_LABELS = {
    "D": "an unrecognised device",
    "I": "an unusual IP/location",
    "T": "an unusual login time",
    "F": "repeated failed logins",
    "A": "a sensitive action",
    "CS": "concurrent sessions",
    "SW": "rapid device switching",
    "P": "multiple networks in a short window",
    "G": "impossible-travel movement",
}


def decide(r: float) -> str:
    if r < config.T_MFA:
        return "ALLOW"
    if r < config.T_RESTRICTED:
        return "MFA"
    if r < config.T_DENY:
        return "RESTRICTED"
    return "DENY"


def top_factors(factors: dict, k: int = 2):
    """Return the factor keys contributing most to the score (weight * value)."""
    weights = {**config.CONTEXTUAL_WEIGHTS, **config.BEHAVIOURAL_WEIGHTS}
    contrib = {key: weights.get(key, 0) * val for key, val in factors.items() if val > 0}
    return [k_ for k_, _ in sorted(contrib.items(), key=lambda x: x[1], reverse=True)[:k]]


def explain(decision: str, scored: dict) -> dict:
    """Layered explanation: 'brief' (one line) + 'full' (detail)."""
    drivers = top_factors(scored["factors"])
    driver_text = " and ".join(FACTOR_LABELS.get(d, d) for d in drivers) or "your current context"

    headlines = {
        "ALLOW": "Access granted. Nothing unusual about this session.",
        "MFA": f"Quick check needed because of {driver_text}.",
        "RESTRICTED": f"Read-only for now because of {driver_text}.",
        "DENY": f"Access blocked because of {driver_text}.",
    }
    full = {
        "ALLOW": "Your session matches your normal device, location and timing, so access continues without interruption.",
        "MFA": (f"We noticed {driver_text}, which raised this session's risk to the medium range "
                f"(score {scored['R']}). Enter a one-time code to confirm it's you, then you'll continue normally."),
        "RESTRICTED": (f"We noticed {driver_text}, which raised this session's risk to the high range "
                       f"(score {scored['R']}). You can still view information, but submitting or changing "
                       f"data is paused until the session is re-verified or reviewed."),
        "DENY": (f"This session's risk reached the critical range (score {scored['R']}) due to {driver_text}. "
                 f"Access has been stopped and an administrator has been notified. Use account recovery if this was you."),
    }
    return {"brief": headlines[decision], "full": full[decision]}


def enforce(scored: dict) -> dict:
    """Combine decision + explanation into the PEP response object."""
    decision = decide(scored["R"])
    explanation = explain(decision, scored)
    return {
        "decision": decision,
        "risk_score": scored["R"],
        "sub_scores": {"C": scored["C"], "B": scored["B"]},
        "factors": scored["factors"],
        "explanation": explanation,
    }
