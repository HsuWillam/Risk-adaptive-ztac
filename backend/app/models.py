"""Database models. audit_logs is the central evaluation artifact for FYP Part 2."""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), default="student")   # student / lecturer / admin
    totp_secret = db.Column(db.String(64), nullable=False)


class Device(db.Model):
    """Per-user fingerprint library (similarity matching, not binary known/unknown)."""
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # Hashed attribute map (one-way) for privacy-by-design (PDPA/GDPR aligned).
    fingerprint_hash = db.Column(db.Text, nullable=False)  # JSON of hashed attrs
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)


class Session(db.Model):
    """Server-side session state carried across requests for continuous re-eval."""
    __tablename__ = "sessions"
    id = db.Column(db.String(64), primary_key=True)         # session token
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    fingerprint_hash = db.Column(db.Text, nullable=False)   # bound at login
    last_ip = db.Column(db.String(64))
    last_lat = db.Column(db.Float)
    last_lon = db.Column(db.Float)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    ip_prefixes = db.Column(db.Text, default="[]")          # JSON list of /24 prefixes
    mfa_attempts = db.Column(db.Integer, default=0)
    mfa_passed = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)


class AuditLog(db.Model):
    """One row per evaluated request: nine factors, sub-scores, R, decision, reason."""
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer)
    session_id = db.Column(db.String(64))
    # contextual factor scores
    d = db.Column(db.Float)
    i = db.Column(db.Float)
    t = db.Column(db.Float)
    f = db.Column(db.Float)
    a = db.Column(db.Float)
    # behavioural factor scores
    cs = db.Column(db.Float)
    sw = db.Column(db.Float)
    p = db.Column(db.Float)
    g = db.Column(db.Float)
    # sub-scores + composite
    c_score = db.Column(db.Float)
    b_score = db.Column(db.Float)
    r_score = db.Column(db.Float)
    decision = db.Column(db.String(16))
    explanation = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "factors": {
                "D": self.d, "I": self.i, "T": self.t, "F": self.f, "A": self.a,
                "CS": self.cs, "SW": self.sw, "P": self.p, "G": self.g,
            },
            "C": self.c_score,
            "B": self.b_score,
            "R": self.r_score,
            "decision": self.decision,
            "explanation": self.explanation,
        }
