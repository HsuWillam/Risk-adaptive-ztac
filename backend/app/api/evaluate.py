"""
Continuous re-evaluation endpoint. The frontend calls this on every sensitive
navigation/action so risk is recomputed per-request (Zero Trust: never trust,
always verify) rather than only at login.
"""
import json
from datetime import datetime

from flask import Blueprint, request, jsonify

import config
from app import hash_attr
from app.models import db, Session, AuditLog
from app import risk_engine as re
from app import pep
from app import geo
from app.api.auth import _hash_fingerprint, _ip_prefix, _write_audit, _curr_latlon, _location_factor

evaluate_bp = Blueprint("evaluate", __name__)


@evaluate_bp.route("/evaluate", methods=["POST"])
def evaluate():
    data = request.get_json(force=True)
    sid = data.get("session_id")
    action = data.get("action", "open_dashboard")
    fp = data.get("fingerprint", {})

    sess = Session.query.get(sid)
    if not sess or not sess.active:
        return jsonify({"ok": False, "error": "Session not found or expired."}), 404

    cur_hashes = _hash_fingerprint(fp)
    # Compare against the fingerprint BOUND AT LOGIN (avoids false device-novelty).
    sim = re.fingerprint_similarity(json.loads(sess.fingerprint_hash), cur_hashes)

    ip = geo.client_ip(request)
    prefix = _ip_prefix(ip)
    seen_prefixes = json.loads(sess.ip_prefixes or "[]")
    new_in_window = 0 if prefix in seen_prefixes else 1
    if prefix not in seen_prefixes:
        seen_prefixes.append(prefix)
        sess.ip_prefixes = json.dumps(seen_prefixes)

    # Real geo-velocity / location change vs this session's last known position.
    curr_loc = _curr_latlon(ip)
    prev_loc = (sess.last_lat, sess.last_lon) if sess.last_lat is not None else None
    geo_seconds = (datetime.utcnow() - sess.last_seen).total_seconds() if sess.last_seen else 0
    changed, highly_unusual = _location_factor(prev_loc, curr_loc)

    hour = datetime.utcnow().hour
    factors = {
        "D": re.score_device(sim),
        "I": re.score_ip_location(changed=changed, highly_unusual=highly_unusual),
        "T": re.score_time(hour),
        "F": re.score_failed_login(0),
        "A": re.score_action(action),
        "CS": re.score_concurrent_sessions(
            n_active=Session.query.filter_by(user_id=sess.user_id, active=True).count(),
            distinct_locations=0),
        "SW": re.score_device_switching(1 if sim < config.FP_SIMILARITY_THRESHOLD else 0),
        "P": re.score_ip_prefix(new_in_window),
        "G": re.score_geo_velocity(prev_loc, curr_loc, geo_seconds),
    }
    enforced = pep.enforce(re.composite_risk(factors))

    # If MFA already passed this session, don't bounce a medium score back to MFA.
    if sess.mfa_passed and enforced["decision"] == "MFA":
        enforced["decision"] = "ALLOW"
        enforced["explanation"] = {"brief": "Access granted (already verified).",
                                   "full": "This session was already verified, so the medium-risk signal does not re-trigger a code."}

    sess.last_ip = ip
    if curr_loc:
        sess.last_lat, sess.last_lon = curr_loc[0], curr_loc[1]
    sess.last_seen = datetime.utcnow()
    db.session.commit()

    _write_audit(sess.user_id, sid, enforced)
    return jsonify({"ok": True, **enforced})
