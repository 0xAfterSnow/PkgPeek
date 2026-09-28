"""
PkgPeek — npm supply chain security scanner.

Routes are grouped as: public pages, public API, the community reporting flow,
the paid tool listing flow, and the admin API. All state-changing requests are
CSRF-checked and authenticated where appropriate.
"""

import hmac
import json
import os
import secrets
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

import byteship
import detections
import logos
import reports
import toolstore
import validate
from database import durability_report, get_connection, init_db, utcnow
from scanner import PackageScanner

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))
# Large enough for a 512 KB logo, which is also the per-logo cap.
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set PEEPEEK_SECURE_COOKIES=1 behind TLS (Render/Railway/Fly terminate it).
if os.environ.get("PKPEEK_SECURE_COOKIES", "").lower() in ("1", "true", "yes"):
    app.config["SESSION_COOKIE_SECURE"] = True

def redact_uri(uri: str) -> str:
    """Strip any credentials from a connection string before it is logged.

    Storage URIs routinely embed a password (``redis://user:secret@host``), and
    log files get shipped, grepped and pasted. Never log one verbatim.
    """
    if not uri:
        return uri
    try:
        parsed = urlparse(uri)
    except ValueError:
        return "<unparseable>"
    if not parsed.password and not parsed.username:
        return uri
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://***@{host}"


def _build_limiter():
    """Build the rate limiter, degrading rather than refusing to boot.

    LIMITER_STORAGE_URI is optional, and a misconfigured value (say
    redis://... without the redis package installed) used to raise at import
    time and take the whole app down. A warning plus a fall back to in-process
    storage is strictly better: the service starts, and the weaker limit is
    visible in the logs.
    """
    storage_uri = os.environ.get("LIMITER_STORAGE_URI", "").strip() or "memory://"
    try:
        return Limiter(
            get_remote_address,
            app=app,
            default_limits=["500 per day", "100 per hour"],
            storage_uri=storage_uri,
        )
    except Exception as exc:
        app.logger.warning(
            "LIMITER_STORAGE_URI=%s is unusable (%s: %s). Falling back to in-process "
            "storage. Limits will reset on restart and are per-worker. Install the "
            "matching package, e.g. `pip install redis`, or set memory:// to silence "
            "this.",
            redact_uri(storage_uri),
            type(exc).__name__,
            exc,
        )
        return Limiter(
            get_remote_address,
            app=app,
            default_limits=["500 per day", "100 per hour"],
            storage_uri="memory://",
        )


limiter = _build_limiter()

scanner = PackageScanner()


# ── Auth ───────────────────────────────────────────────────────────────────
def check_auth(username, password):
    expected_user = os.environ.get("ADMIN_USERNAME")
    expected_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    if not expected_user or not expected_hash:
        return False
    return hmac.compare_digest(username or "", expected_user) and check_password_hash(
        expected_hash, password
    )


def authenticate():
    return Response(
        "Could not verify your access level for that URL.\n"
        "You have to login with proper credentials",
        401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'},
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


# ── CSRF ───────────────────────────────────────────────────────────────────
def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


@app.before_request
def csrf_protect():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    expected = session.get("_csrf")
    if not expected or not sent or not hmac.compare_digest(sent, expected):
        return jsonify({"error": "Invalid or missing CSRF token"}), 403
    return None


@app.context_processor
def inject_globals():
    return {"csrf_token": csrf_token, "year": datetime.now().year}


# ── Pages ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", payment=toolstore.payment_config())


@app.route("/report")
def report_page():
    return render_template("report.html", prefill=request.args.get("package", ""))


@app.route("/contribute")
def contribute_page():
    return render_template("contribute.html", community=detections.community())


@app.route("/submit-tool")
def submit_tool_page():
    return render_template("submit_tool.html", payment=toolstore.payment_config())


@app.route("/listing/<token>")
def listing_status(token):
    submission = toolstore.get_submission_by_token(token)
    if not submission:
        return render_template("listing_status.html", submission=None, payment=toolstore.payment_config()), 404
    return render_template(
        "listing_status.html", submission=submission, payment=toolstore.payment_config()
    )


@app.route("/admin")
@requires_auth
def admin():
    toolstore.sweep_expired()
    report = durability_report()
    if report["message"]:
        # Loud, because losing a paid listing or a customer's email is not
        # recoverable by re-running anything.
        app.logger.warning("DURABILITY: %s", report["message"])
    return render_template(
        "admin.html",
        payment=toolstore.payment_config(),
        durability=report,
        storage=byteship.config(),
    )


@app.route("/admin/storage", methods=["GET"])
@requires_auth
def admin_storage():
    return jsonify(durability_report())


@app.route("/robots.txt")
@app.route("/sitemap.xml")
@app.route("/sw.js")
@app.route("/manifest.json")
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])


# ── Uploads ────────────────────────────────────────────────────────────────
@app.route("/logos/<path:filename>")
def serve_logo(filename):
    """Serve an uploaded or curated logo under a locked-down content policy.

    ``filename`` is relative to /logos/, but resolve_logo() takes the full
    public path, so put the prefix back on.
    """
    resolved = toolstore.resolve_logo(f"/logos/{filename}")
    if not resolved:
        return jsonify({"error": "Not found"}), 404
    path, content_type = resolved
    response = send_file(path, mimetype=content_type, conditional=True)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    response.headers["Content-Disposition"] = "inline"
    # Both sources are content-addressed (uploads random, curated hashed), so a
    # URL never changes meaning and can be cached hard.
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


# ── Scanner API ────────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@limiter.limit("10 per minute")
def scan():
    data = request.get_json(silent=True)
    if not data or "packageJson" not in data:
        return jsonify({"error": "Missing packageJson field"}), 400
    try:
        pkg_json = json.loads(data["packageJson"])
    except (json.JSONDecodeError, TypeError) as exc:
        return jsonify({"error": f"Invalid JSON: {exc}"}), 400
    if not isinstance(pkg_json, dict):
        return jsonify({"error": "packageJson must be a JSON object"}), 400
    return jsonify(scanner.scan(pkg_json))


@app.route("/api/stats", methods=["GET"])
def stats():
    return jsonify(scanner.get_stats())


@app.route("/api/community", methods=["GET"])
def community():
    return jsonify(detections.community())


# ── Tools directory ────────────────────────────────────────────────────────
@app.route("/api/tools", methods=["GET"])
def get_tools():
    return jsonify(toolstore.list_public_tools())


@app.route("/api/tools", methods=["POST"])
@requires_auth
def add_tool():
    """Add a curated tool. Paid listings go through /api/tool-submissions.

    Accepts either JSON or multipart so the admin form can send a logo file.
    """
    if request.files:
        data = {k: request.form.get(k) for k in ("name", "type", "cls", "url", "desc")}
        upload = request.files.get("logo")
        logo_bytes = upload.read() if upload and upload.filename else None
    else:
        data = request.get_json(silent=True) or {}
        logo_bytes = None

    try:
        name = validate.clean_text(data.get("name"), validate.MAX_NAME, "Name")
        desc = validate.clean_text(data.get("desc"), validate.MAX_DESCRIPTION, "Description")
        url = validate.clean_url(data.get("url"), "URL")
        type_ = validate.clean_text(data.get("type"), 60, "Type")
        cls = validate.clean_choice(
            data.get("cls"), {"tt-vscode", "tt-cli", "tt-ci", "tt-service"}, "Colour class"
        )
        # Magic-byte validation, same rules as advertiser uploads.
        stored = toolstore.save_logo(logo_bytes) if logo_bytes else None
    except validate.ValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    except byteship.ByteshipError as exc:
        # The logo was offered and could not be stored. Say so rather than
        # creating a record that renders as a broken image.
        return jsonify({"error": f"Logo upload failed: {exc}"}), 502

    logo_url, logo_ref = toolstore._saved(stored)
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO tools (type, cls, name, desc, url, logo, logo_ref, logo_tile, "
            "source, sponsored, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (type_, cls, name, desc, url, logo_url, logo_ref, "light", "curated", 0, utcnow()),
        )
        conn.commit()
    except Exception:
        if stored:
            toolstore.delete_logo(stored)
        raise
    finally:
        conn.close()
    return jsonify({"success": True, "logo": logo_url})


@app.route("/api/tools/<int:tool_id>", methods=["DELETE"])
@requires_auth
def delete_tool(tool_id):
    conn = get_connection()
    try:
        conn.execute("DELETE FROM tools WHERE id = %s", (tool_id,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"success": True})


# ── Community reports ──────────────────────────────────────────────────────
@app.route("/api/report", methods=["POST"])
@limiter.limit("5 per hour")
def submit_report():
    # Honeypot: a real person never sees this field, so a filled one means a bot.
    if (request.get_json(silent=True) or {}).get("website"):
        return jsonify({"success": True, "queued": True})
    try:
        report = reports.create_report(request.get_json(silent=True) or {})
    except validate.ValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(
        {
            "success": True,
            "id": report["id"],
            "github_issue_url": report.get("github_issue_url")
            or reports.prefilled_issue_url(report),
            "github_integration": reports.github_configured(),
        }
    )


@app.route("/api/reports", methods=["GET"])
@requires_auth
def list_reports():
    return jsonify(
        reports.list_reports(status=request.args.get("status"), kind=request.args.get("kind"))
    )


@app.route("/api/reports/<int:report_id>/status", methods=["POST"])
@requires_auth
def review_report(report_id):
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(reports.set_status(report_id, data.get("status")))
    except validate.ValidationError as exc:
        return jsonify({"error": str(exc)}), 400


# ── Paid tool listings ─────────────────────────────────────────────────────
@app.route("/api/tool-submissions", methods=["POST"])
@limiter.limit("5 per hour")
def create_tool_submission():
    payment = toolstore.payment_config()
    if not payment["configured"]:
        # Better a clear refusal than a submission that can never be paid for.
        return (
            jsonify(
                {
                    "error": "Tool listings are not open right now: the payment link "
                    "is not configured on this instance."
                }
            ),
            503,
        )
    if request.form.get("website"):
        return jsonify({"success": True, "token": None})

    logo_bytes = None
    if "logo" in request.files:
        upload = request.files["logo"]
        logo_bytes = upload.read() if upload and upload.filename else None

    payload = {k: request.form.get(k) for k in
               ("toolName", "websiteUrl", "description", "category", "contactEmail",
                "githubUrl", "pricingModel", "documentationUrl", "twitterUrl")}
    try:
        submission = toolstore.create_submission(payload, logo_bytes)
    except validate.ValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    except byteship.ByteshipError as exc:
        return jsonify({"error": f"Logo upload failed: {exc}"}), 502
    return jsonify({"success": True, "token": submission["public_token"]})


@app.route("/api/listing/<token>/declare-paid", methods=["POST"])
@limiter.limit("10 per hour")
def declare_paid(token):
    submission = toolstore.get_submission_by_token(token)
    if not submission:
        return jsonify({"error": "Not found"}), 404
    try:
        toolstore.declare_payment_complete(submission["id"])
    except validate.SubmissionError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"success": True})


# ── Admin API ──────────────────────────────────────────────────────────────
@app.route("/api/admin/submissions", methods=["GET"])
@requires_auth
def admin_submissions():
    toolstore.sweep_expired()
    return jsonify(
        {
            "submissions": toolstore.list_submissions(status=request.args.get("status")),
            "counts": toolstore.submission_counts(),
            "payment": toolstore.payment_config(),
            "storage": byteship.config(),
        }
    )


@app.route("/api/admin/submissions/<int:submission_id>/<action>", methods=["POST"])
@requires_auth
def admin_submission_action(submission_id, action):
    data = request.get_json(silent=True) or {}
    try:
        if action == "approve":
            return jsonify(toolstore.review(submission_id, "approve"))
        if action == "reject":
            return jsonify(toolstore.review(submission_id, "reject", data.get("reason")))
        if action == "mark-paid":
            return jsonify(
                toolstore.review(submission_id, "mark_paid", payment_reference=data.get("reference"))
            )
        if action == "refund":
            return jsonify(toolstore.review(submission_id, "refund"))
        if action == "publish":
            return jsonify(toolstore.publish(submission_id))
        if action == "unpublish":
            return jsonify(toolstore.unpublish(submission_id))
    except validate.ValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"error": "Unknown action"}), 404


if __name__ == "__main__":
    init_db()
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, port=int(os.environ.get("PORT", 5000)))
