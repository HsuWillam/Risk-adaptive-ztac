"""
Central configuration — every tunable parameter for the risk engine lives here,
so the FYP sensitivity analysis can sweep weights/thresholds without touching logic.

NOTE: weight/threshold values below mirror the IR specification. If your existing
ztac_scaffold uses different attribute names, reconcile FP_ATTRIBUTES + the factor
keys with your version.
"""

# --- Composite weighting: R = WC * C + WB * B -------------------------------
WC = 0.60   # contextual sub-score weight
WB = 0.40   # behavioural sub-score weight

# --- Contextual factor weights (must sum to 1.0) ----------------------------
# D=device, I=ip/location, T=time, F=failed-login, A=action-sensitivity
CONTEXTUAL_WEIGHTS = {
    "D": 0.30,
    "F": 0.25,
    "I": 0.20,
    "T": 0.15,
    "A": 0.10,
}

# --- Behavioural factor weights (must sum to 1.0) ---------------------------
# CS=concurrent-sessions, SW=device-switching, P=ip-prefix, G=geo-velocity
BEHAVIOURAL_WEIGHTS = {
    "CS": 0.30,
    "SW": 0.25,
    "G": 0.25,
    "P": 0.20,
}

# --- PEP decision thresholds (strict inequalities) --------------------------
# ALLOW       : R < T_MFA
# MFA         : T_MFA      <= R < T_RESTRICTED
# RESTRICTED  : T_RESTRICTED <= R < T_DENY
# DENY        : R >= T_DENY
T_MFA = 0.30
T_RESTRICTED = 0.55
T_DENY = 0.80

# --- Device fingerprint -----------------------------------------------------
# The eight browser attributes collected client-side (must match fingerprint.ts).
FP_ATTRIBUTES = [
    "userAgent",
    "language",
    "platform",
    "screenResolution",
    "colorDepth",
    "timezone",
    "canvasHash",
    "webglVendor",
]
# A returning device is treated as "known" when attribute similarity >= this.
FP_SIMILARITY_THRESHOLD = 0.85

# --- TOTP / MFA -------------------------------------------------------------
TOTP_MAX_ATTEMPTS = 3          # attempts is incremented BEFORE the >= check
TOTP_ISSUER = "APU-ZTAC"

# --- Geo-velocity -----------------------------------------------------------
GEO_IMPOSSIBLE_KMH = 900.0     # above commercial cruise speed -> G = 1.0
GEO_FAST_KMH = 400.0           # plausible air travel -> G = 0.5
GEO_UNCERTAINTY_KM = 50.0      # geolocation imprecision margin

# --- Geo-velocity uncertainty already defined above; IP/location (I) bands ---
I_NEAR_KM = 50.0        # within this of the known location -> I = 0.0 (normal)
I_REGIONAL_KM = 500.0   # within this -> I = 0.5 (some change); beyond -> I = 1.0

# --- GeoLite2 / online geolocation ------------------------------------------
import os

GEOIP_DB_PATH = os.environ.get(
    "GEOIP_DB_PATH",
    os.path.join(os.path.dirname(__file__), "instance", "GeoLite2-City.mmdb"),
)
GEOIP_DEV_FALLBACK_LATLON = (3.0556, 101.7000)   # APU, KL — private/localhost IPs
# Online (Render) without a .mmdb: resolve real coords via a free HTTP API.
GEOIP_HTTP_FALLBACK = os.environ.get("GEOIP_HTTP_FALLBACK", "1") == "1"
GEOIP_HTTP_URL = "http://ip-api.com/json/{ip}?fields=status,lat,lon,city,countryCode"
GEOIP_HTTP_TIMEOUT = 2.5

# --- Misc / deployment -------------------------------------------------------
# Render injects DATABASE_URL; it hands out "postgres://" which SQLAlchemy needs
# as "postgresql://". Falls back to local SQLite when unset.
_db_url = os.environ.get("DATABASE_URL")
if _db_url and _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)
SQLALCHEMY_DATABASE_URI = _db_url or "sqlite:///ztac.db"
SQLALCHEMY_TRACK_MODIFICATIONS = False

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-in-production")

# CORS: comma-separated origins via env; "*" (default) allows any origin. The
# frontend authenticates with a session_id in the body (no cookies), so wildcard
# is safe here. Lock this to your frontend URL in production.
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",")]

# Fixed demo TOTP secret so MFA survives redeploys/restarts (ephemeral SQLite).
DEMO_TOTP_SECRET = os.environ.get("DEMO_TOTP_SECRET")
