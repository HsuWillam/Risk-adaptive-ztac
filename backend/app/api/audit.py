"""User-facing audit trail (Q8: lets users verify/dispel suspicion of access)."""
from flask import Blueprint, request, jsonify

from app.models import Session, AuditLog

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("/history", methods=["GET"])
def history():
    sid = request.args.get("session_id")
    sess = Session.query.get(sid)
    if not sess:
        return jsonify({"ok": False, "error": "Session not found."}), 404
    logs = (AuditLog.query
            .filter_by(user_id=sess.user_id)
            .order_by(AuditLog.timestamp.desc())
            .limit(50).all())
    return jsonify({"ok": True, "entries": [l.to_dict() for l in logs]})
