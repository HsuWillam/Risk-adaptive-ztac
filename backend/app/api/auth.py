"""Auth endpoints: /login performs initial risk evaluation; /mfa verifies TOTP."""
import json
import uuid
from datetime import datetime

import pyotp
from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash

import config
from app import hash_attr
from app.models import db, User, Device, Session, AuditLog
from app import risk_engine as re
from app import pep
from app import geo

auth_bp = Blueprint("auth", __name__)


def _hash_fingerprint(fp: dict) -> dict:
    return {k: hash_attr(fp.get(k, "")) for k in config.FP_ATTRIBUTES}


def _ip_prefix(ip: str) -> str:
    parts = (ip or "0.0.0.0").split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip


def _curr_latlon(ip: str):
    """Resolve the request IP to (lat, lon), or None if unresolvable."""
    lat, lon = geo.geolocate(ip)
    return (lat, lon) if lat is not None and lon is not None else None


def _prev_location_for_user(user_id, exclude_sid=None):
    """Most recent prior session of this user that carries coordinates."""
    q = Session.query.filter(Session.user_id == user_id,
                             Session.last_lat.isnot(None))
    if exclude_sid:
        q = q.filter(Session.id != exclude_sid)
    s = q.order_by(Session.last_seen.desc()).first()
    if s is None:
        return None, None
    return (s.last_lat, s.last_lon), s.last_seen


def _location_factor(prev_latlon, curr_latlon):
    """
    Translate geographic distance into the (changed, highly_unusual) booleans the
    existing score_ip_location() expects:
        distance <= I_NEAR_KM      -> changed=False (normal)
        <= I_REGIONAL_KM           -> changed=True  (some change)
        beyond I_REGIONAL_KM       -> highly_unusual=True
    Falls back to "no signal" when either location is missing.
    """
    if not prev_latlon or not curr_latlon:
        return False, False
    dist = re.haversine_km(prev_latlon[0], prev_latlon[1],
                           curr_latlon[0], curr_latlon[1])
    dist = max(0.0, dist - config.GEO_UNCERTAINTY_KM)
    if dist <= config.I_NEAR_KM:
        return False, False
    if dist <= config.I_REGIONAL_KM:
        return True, False
    return True, True


def _write_audit(user_id, session_id, enforced):
    f = enforced["factors"]
    log = AuditLog(
        user_id=user_id, session_id=session_id,
        d=f["D"], i=f["I"], t=f["T"], f=f["F"], a=f["A"],
        cs=f["CS"], sw=f["SW"], p=f["P"], g=f["G"],
        c_score=enforced["sub_scores"]["C"], b_score=enforced["sub_scores"]["B"],
        r_score=enforced["risk_score"], decision=enforced["decision"],
        explanation=enforced["explanation"]["full"],
    )
    db.session.add(log)
    db.session.commit()


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    fp = data.get("fingerprint", {})
    failed_attempts = int(data.get("failed_attempts", 0))

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"ok": False, "error": "Invalid username or password."}), 401

    cur_hashes = _hash_fingerprint(fp)
    # Device familiarity: best similarity over the user's known devices.
    devices = Device.query.filter_by(user_id=user.id).all()
    best_sim = max(
        (re.fingerprint_similarity(json.loads(d.fingerprint_hash), cur_hashes) for d in devices),
        default=0.0,
    )

    ip = geo.client_ip(request)
    hour = datetime.utcnow().hour

    # Resolve location; compute geo-velocity vs the user's most recent prior
    # session and the location-change factor from real geographic distance.
    curr_loc = _curr_latlon(ip)
    prev_loc, prev_seen = _prev_location_for_user(user.id)
    geo_seconds = (datetime.utcnow() - prev_seen).total_seconds() if prev_seen else 0
    changed, highly_unusual = _location_factor(prev_loc, curr_loc)

    factors = {
        "D": re.score_device(best_sim),
        "I": re.score_ip_location(changed=changed, highly_unusual=highly_unusual),
        "T": re.score_time(hour),
        "F": re.score_failed_login(failed_attempts),
        "A": re.score_action("login"),
        "CS": re.score_concurrent_sessions(
            n_active=Session.query.filter_by(user_id=user.id, active=True).count(),
            distinct_locations=0),
        "SW": re.score_device_switching(0),
        "P": re.score_ip_prefix(0),
        "G": re.score_geo_velocity(prev_loc, curr_loc, geo_seconds),
    }
    enforced = pep.enforce(re.composite_risk(factors))

    # Create session (fingerprint bound at login so MFA re-eval doesn't re-flag novelty).
    sid = uuid.uuid4().hex
    sess = Session(
        id=sid, user_id=user.id, fingerprint_hash=json.dumps(cur_hashes),
        last_ip=ip, ip_prefixes=json.dumps([_ip_prefix(ip)]),
        last_lat=(curr_loc[0] if curr_loc else None),
        last_lon=(curr_loc[1] if curr_loc else None),
        mfa_passed=(enforced["decision"] == "ALLOW"),
    )
    db.session.add(sess)
    # First-time device: remember it.
    if best_sim < config.FP_SIMILARITY_THRESHOLD:
        db.session.add(Device(user_id=user.id, fingerprint_hash=json.dumps(cur_hashes)))
    db.session.commit()

    _write_audit(user.id, sid, enforced)
    return jsonify({"ok": True, "session_id": sid, **enforced})


@auth_bp.route("/mfa", methods=["POST"])
def mfa():
    data = request.get_json(force=True)
    sid = data.get("session_id")
    code = data.get("code", "")

    sess = Session.query.get(sid)
    if not sess or not sess.active:
        return jsonify({"ok": False, "error": "Session not found or expired."}), 404
    user = User.query.get(sess.user_id)

    # Increment attempts BEFORE the exhaustion check (per spec).
    sess.mfa_attempts += 1
    valid = pyotp.TOTP(user.totp_secret).verify(code)

    if valid:
        sess.mfa_passed = True
        db.session.commit()
        scored = re.composite_risk({k: 0.0 for k in
                  ["D", "I", "T", "F", "A", "CS", "SW", "P", "G"]})
        enforced = pep.enforce(scored)
        enforced["decision"] = "ALLOW"
        enforced["explanation"] = {"brief": "Verified. You're all set.",
                                   "full": "Your identity was confirmed via one-time code; access continues normally."}
        _write_audit(user.id, sid, enforced)
        return jsonify({"ok": True, **enforced})

    if sess.mfa_attempts >= config.TOTP_MAX_ATTEMPTS:
        sess.active = False
        sess.mfa_passed = False
        db.session.commit()
        scored = re.composite_risk({"D": 1.0, "I": 0.0, "T": 0.0, "F": 1.0, "A": 0.0,
                                    "CS": 0.0, "SW": 0.0, "P": 0.0, "G": 0.0})
        enforced = pep.enforce(scored)
        enforced["decision"] = "DENY"
        enforced["explanation"] = {
            "brief": "Access blocked after too many failed codes.",
            "full": "The one-time code was entered incorrectly too many times, so this session has been stopped. "
                    "Use account recovery or contact IT if this was you."}
        _write_audit(user.id, sid, enforced)
        return jsonify({"ok": False, **enforced}), 403

    db.session.commit()
    remaining = config.TOTP_MAX_ATTEMPTS - sess.mfa_attempts
    return jsonify({"ok": False, "error": f"Incorrect code. {remaining} attempt(s) left.",
                    "attempts_remaining": remaining}), 401
