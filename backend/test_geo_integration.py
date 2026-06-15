"""Backend integration test for the Next.js-API GeoLite2 wiring (mocked geo)."""
import json
from app import create_app, geo
from app.models import db, AuditLog

# canned geolocation by IP
COORDS = {"1.1.1.1": (3.139, 101.687),      # KL
          "2.2.2.2": (35.676, 139.650),     # Tokyo
          "1.1.1.2": (3.20, 101.70)}        # KL-near
geo.geolocate = lambda ip: COORDS.get(ip, (None, None))

FP_A = {"userAgent": "ua-A", "language": "en", "platform": "Win32",
        "screenResolution": "1920x1080", "colorDepth": "24", "timezone": "Asia/KL",
        "canvasHash": "aaa", "webglVendor": "Intel"}
FP_B = {"userAgent": "ua-B", "language": "ja", "platform": "Linux",
        "screenResolution": "1366x768", "colorDepth": "32", "timezone": "Asia/Tokyo",
        "canvasHash": "zzz", "webglVendor": "AMD"}

app = create_app()
passed = failed = 0
def check(label, cond):
    global passed, failed
    print(f"  [{'OK ' if cond else 'XX '}] {label}")
    passed += cond; failed += (not cond)

def login(c, ip, fp):
    return c.post("/api/auth/login", json={"username": "student01", "password": "password123",
                  "fingerprint": fp}, headers={"X-Forwarded-For": ip}).get_json()

with app.app_context():
    db.drop_all(); db.create_all()
    from app import _seed_demo_user; _seed_demo_user()
    c = app.test_client()

    # Login A from KL, known-ish device A -> baseline session
    r1 = login(c, "1.1.1.1", FP_A)
    check(f"login A (KL) decision={r1['decision']}", r1["decision"] in ("ALLOW", "MFA"))

    # Login B from Tokyo, NEW device B, seconds later -> sharing pattern
    r2 = login(c, "2.2.2.2", FP_B)
    with app.app_context():
        alog = AuditLog.query.order_by(AuditLog.id.desc()).first()
    check(f"impossible travel: G = 1.0 (got {alog.g})", alog.g == 1.0)
    check(f"far location: I = 1.0 (got {alog.i})", alog.i == 1.0)
    check(f"new device: D = 1.0 (got {alog.d})", alog.d == 1.0)
    check(f"sharing pattern escalates: {r2['decision']} (R={r2['risk_score']})",
          r2["decision"] != "ALLOW")
    print(f"      reason: {r2['explanation']['brief']}")

    # Continuous evaluate: same session, jump to Tokyo on a sensitive action
    sid = r1["session_id"]
    ev = c.post("/api/session/evaluate", json={"session_id": sid, "action": "view_transcript",
                "fingerprint": FP_A}, headers={"X-Forwarded-For": "2.2.2.2"}).get_json()
    with app.app_context():
        alog2 = AuditLog.query.order_by(AuditLog.id.desc()).first()
    check(f"re-eval geo-velocity fires mid-session: G = 1.0 (got {alog2.g})", alog2.g == 1.0)
    check(f"re-eval far location: I = 1.0 (got {alog2.i})", alog2.i == 1.0)

    # Control via direct scoring (no stateful session): staying near KL = no anomaly,
    # and an 8-hour KL->Tokyo trip reads as fast-but-possible air travel (0.5).
    from app import risk_engine as r2
    from app.api.auth import _location_factor
    KL, NEAR, TOK = (3.139, 101.687), (3.20, 101.70), (35.676, 139.650)
    check(f"near KL over 1h -> G = 0.0 (got {r2.score_geo_velocity(KL, NEAR, 3600)})",
          r2.score_geo_velocity(KL, NEAR, 3600) == 0.0)
    check(f"KL->Tokyo over 8h -> G = 0.5 air travel (got {r2.score_geo_velocity(KL, TOK, 8*3600)})",
          r2.score_geo_velocity(KL, TOK, 8*3600) == 0.5)
    ch, hi = _location_factor(KL, NEAR)
    check(f"near KL -> I factor 0.0 (changed={ch}, highly={hi})",
          r2.score_ip_location(ch, hi) == 0.0)
    ch2, hi2 = _location_factor(KL, TOK)
    check(f"KL->Tokyo -> I factor 1.0 (changed={ch2}, highly={hi2})",
          r2.score_ip_location(ch2, hi2) == 1.0)

print(f"\n{passed} passed, {failed} failed")
import sys; sys.exit(1 if failed else 0)
