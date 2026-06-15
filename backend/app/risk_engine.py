"""
Risk scoring engine.

Each of the nine factors is scored on {0.0, 0.5, 1.0}. The two sub-scores are
weighted sums of their factor groups; the composite is R = WC*C + WB*B.
All weights/thresholds come from config so sensitivity analysis stays config-only.
"""
import json
import math
from datetime import datetime

import config


# --------------------------------------------------------------------------
# Factor scorers  (each returns 0.0 / 0.5 / 1.0)
# --------------------------------------------------------------------------
def score_device(similarity: float) -> float:
    """D: how well the current fingerprint matches the user's known devices."""
    if similarity >= config.FP_SIMILARITY_THRESHOLD:
        return 0.0                      # known device
    if similarity >= 0.50:
        return 0.5                      # slightly unusual / drifted
    return 1.0                          # completely new device


def score_ip_location(changed: bool, highly_unusual: bool) -> float:
    if highly_unusual:
        return 1.0
    return 0.5 if changed else 0.0


def score_time(hour: int, user_night_owl: bool = False) -> float:
    """T: scored against a per-user baseline rather than a global rule."""
    unusual = 0 <= hour < 6
    if not unusual:
        return 0.0
    return 0.5 if user_night_owl else 1.0


def score_failed_login(attempts: int) -> float:
    if attempts == 0:
        return 0.0
    return 0.5 if attempts <= 2 else 1.0


def score_action(action: str) -> float:
    """A: view-only=0.0, normal=0.5, sensitive (write/transcript/grades)=1.0."""
    sensitive = {"view_transcript", "submit_grade", "change_password", "download_record"}
    normal = {"open_dashboard", "edit_profile"}
    if action in sensitive:
        return 1.0
    if action in normal:
        return 0.5
    return 0.0


def score_concurrent_sessions(n_active: int, distinct_locations: int) -> float:
    if distinct_locations >= 2:
        return 1.0
    if n_active >= 2:
        return 0.5
    return 0.0


def score_device_switching(switches_in_window: int) -> float:
    if switches_in_window == 0:
        return 0.0
    return 0.5 if switches_in_window == 1 else 1.0


def score_ip_prefix(new_prefixes_in_window: int) -> float:
    """
    Per-user-baseline P factor with short-time clustering (IR note on Q19):
    baseline +1 prefix in a short window -> 0.5; +2 or more -> 1.0.
    """
    if new_prefixes_in_window >= 2:
        return 1.0
    return 0.5 if new_prefixes_in_window == 1 else 0.0


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    h = (math.sin(dlat / 2) ** 2
         + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2))
         * math.sin(dlon / 2) ** 2)
    return r * 2 * math.asin(math.sqrt(h))


def score_geo_velocity(prev, curr, seconds: float) -> float:
    """G: implied velocity vs configured thresholds. prev/curr = (lat, lon)."""
    if prev is None or curr is None or seconds <= 0:
        return 0.0
    dist = haversine_km(prev[0], prev[1], curr[0], curr[1])
    if dist <= config.GEO_UNCERTAINTY_KM:
        return 0.0
    kmh = dist / (seconds / 3600.0)
    if kmh >= config.GEO_IMPOSSIBLE_KMH:
        return 1.0
    if kmh >= config.GEO_FAST_KMH:
        return 0.5
    return 0.0


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------
def contextual_subscore(factors: dict) -> float:
    w = config.CONTEXTUAL_WEIGHTS
    return sum(w[k] * factors[k] for k in w)


def behavioural_subscore(factors: dict) -> float:
    w = config.BEHAVIOURAL_WEIGHTS
    return sum(w[k] * factors[k] for k in w)


def composite_risk(factors: dict) -> dict:
    """factors keys: D,I,T,F,A,CS,SW,P,G. Returns C, B, R and echoes factors."""
    c = contextual_subscore(factors)
    b = behavioural_subscore(factors)
    r = config.WC * c + config.WB * b
    return {"factors": factors, "C": round(c, 4), "B": round(b, 4), "R": round(r, 4)}


def fingerprint_similarity(stored_hashes: dict, current_hashes: dict) -> float:
    """Attribute-wise match ratio over the configured FP_ATTRIBUTES."""
    attrs = config.FP_ATTRIBUTES
    if not stored_hashes:
        return 0.0
    matches = sum(
        1 for k in attrs if stored_hashes.get(k) and stored_hashes.get(k) == current_hashes.get(k)
    )
    return matches / len(attrs)
