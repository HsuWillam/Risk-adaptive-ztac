"""Flask application factory: JSON REST API consumed by the Next.js frontend."""
import json
import hashlib

import pyotp
from flask import Flask
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash

import config
from app.models import db, User


def hash_attr(value: str) -> str:
    """One-way hash of a fingerprint attribute (privacy-by-design)."""
    return hashlib.sha256(str(value).encode()).hexdigest()[:32]


def create_app():
    app = Flask(__name__)
    app.config.from_object(config)

    # Behind Render's reverse proxy: trust one X-Forwarded-* layer so scheme/host
    # are correct. The real client IP is taken from the leftmost XFF in geo.client_ip.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # The frontend authenticates with a session_id in the request body (no
    # cookies), so credentials are not needed and a wildcard origin is safe.
    CORS(app, origins=config.CORS_ORIGINS)
    db.init_app(app)

    from app.api.auth import auth_bp
    from app.api.evaluate import evaluate_bp
    from app.api.audit import audit_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(evaluate_bp, url_prefix="/api/session")
    app.register_blueprint(audit_bp, url_prefix="/api/audit")

    with app.app_context():
        db.create_all()
        _seed_demo_user()

    return app


def _seed_demo_user():
    if User.query.filter_by(username="student01").first():
        return
    secret = config.DEMO_TOTP_SECRET or pyotp.random_base32()
    user = User(
        username="student01",
        password_hash=generate_password_hash("password123"),
        role="student",
        totp_secret=secret,
    )
    db.session.add(user)
    db.session.commit()
    # Print the provisioning URI so you can add it to an authenticator app.
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name="student01", issuer_name=config.TOTP_ISSUER
    )
    print(f"[seed] demo user 'student01' / 'password123'")
    print(f"[seed] TOTP secret: {secret}")
    print(f"[seed] TOTP otpauth URI: {uri}")
