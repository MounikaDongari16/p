"""
LivenessLens: Automated Deepfake Detection & Biometric Identity Verifier
Flask Backend — app.py  (Full Edition)

Author  : LivenessLens Team
Services: Rekognition · S3 · SNS · SES · DynamoDB · Lambda
"""

import os
import json
import uuid
import logging
import hashlib
import hmac
from datetime import datetime, timezone
from functools import wraps
from typing import Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from flask import (
    Flask, request, jsonify, render_template,
    session, redirect, url_for, flash
)
from flask_cors import CORS
from dotenv import load_dotenv

# ─────────────────────────────────────────────
#  ENVIRONMENT & CONFIG
# ─────────────────────────────────────────────
load_dotenv()

AWS_REGION       = os.environ.get("AWS_REGION",       "ap-south-1")
S3_BUCKET_NAME   = os.environ.get("S3_BUCKET_NAME",   "livenesslens-audit-logs")
SNS_TOPIC_ARN    = os.environ.get("SNS_TOPIC_ARN",    "arn:aws:sns:ap-south-1:188122309045:LivenessAlerts")
DYNAMODB_TABLE   = os.environ.get("DYNAMODB_TABLE",   "livenesslens-users")
LAMBDA_FUNC_NAME = os.environ.get("LAMBDA_FUNC_NAME", "livenesslens-processor")
SECRET_KEY       = os.environ.get("SECRET_KEY",       "change-me-in-production-very-secret")

# ─────────────────────────────────────────────
#  FLASK INIT
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = SECRET_KEY
CORS(app)

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("LivenessLens")


# ══════════════════════════════════════════════
#  AWS CLIENT FACTORIES
# ══════════════════════════════════════════════

def get_rekognition_client():
    return boto3.client("rekognition", region_name=AWS_REGION)

def get_s3_client():
    return boto3.client("s3", region_name=AWS_REGION)

def get_sns_client():
    return boto3.client("sns", region_name=AWS_REGION)

def get_dynamodb_resource():
    """Return a boto3 DynamoDB resource for user storage."""
    return boto3.resource("dynamodb", region_name=AWS_REGION)

def get_lambda_client():
    """Return a boto3 Lambda client for invoking serverless functions."""
    return boto3.client("lambda", region_name=AWS_REGION)


# ══════════════════════════════════════════════
#  AUTH HELPERS
# ══════════════════════════════════════════════

def hash_password(password: str) -> str:
    """
    Returns a SHA-256 hex digest of the password.
    In production, prefer bcrypt or argon2 for stronger hashing.
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    """Timing-safe comparison to prevent timing-based attacks."""
    return hmac.compare_digest(hash_password(plain), hashed)


def login_required(f):
    """
    Route decorator — redirects unauthenticated requests to /login.
    Apply above any protected route:  @login_required
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_email" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════
#  DYNAMODB HELPERS  (User CRUD)
# ══════════════════════════════════════════════

from typing import Optional

def db_get_user(email: str) -> Optional[dict]:
    """
    Looks up a user by email (DynamoDB partition key).
    Returns the item dict or None if not found / error.
    """
    try:
        table    = get_dynamodb_resource().Table(DYNAMODB_TABLE)
        response = table.get_item(Key={"email": email})
        return response.get("Item")
    except (BotoCoreError, ClientError) as exc:
        logger.error("DynamoDB get_user error: %s", exc)
        return None


def db_create_user(email: str, name: str, password: str) -> bool:
    """
    Inserts a new user record into DynamoDB.
    Uses a ConditionExpression to prevent overwriting existing accounts.
    Returns True on success, False on duplicate / error.
    """
    try:
        table = get_dynamodb_resource().Table(DYNAMODB_TABLE)
        table.put_item(
            Item={
                "email"      : email,
                "name"       : name,
                "password"   : hash_password(password),
                "created_at" : datetime.now(timezone.utc).isoformat(),
                "role"       : "user",
            },
            ConditionExpression="attribute_not_exists(email)",
        )
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.warning("Registration attempt for existing email: %s", email)
        else:
            logger.error("DynamoDB create_user error: %s", exc)
        return False
    except BotoCoreError as exc:
        logger.error("DynamoDB create_user error: %s", exc)
        return False



# ══════════════════════════════════════════════
#  S3 HELPER  (Audit Logs)
# ══════════════════════════════════════════════

def save_audit_log_to_s3(
    session_id : str,
    confidence : float,
    status     : str,
    user_email : str = "",
) -> bool:
    """
    Persists a JSON audit record to S3.
    Key format: audit-logs/<session_id>.json
    """
    record = {
        "session_id" : session_id,
        "user_email" : user_email,
        "confidence" : confidence,
        "result"     : status,
        "timestamp"  : datetime.now(timezone.utc).isoformat(),
    }
    try:
        s3 = get_s3_client()
        s3.put_object(
            Bucket      = S3_BUCKET_NAME,
            Key         = f"audit-logs/{session_id}.json",
            Body        = json.dumps(record, indent=2),
            ContentType = "application/json",
        )
        logger.info("Audit log saved → s3://%s/audit-logs/%s.json",
                    S3_BUCKET_NAME, session_id)
        return True
    except (BotoCoreError, ClientError) as exc:
        logger.error("S3 audit log error: %s", exc)
        return False


# ══════════════════════════════════════════════
#  SNS HELPER  (Spoof Alerts)
# ══════════════════════════════════════════════

def send_sns_alert(session_id: str, confidence: float, user_email: str = "") -> bool:
    """
    Publishes a spoof-detection alert to the configured SNS topic.
    Triggered automatically when confidence < 80.
    """
    message = (
        f"⚠️  Possible Spoof Detected\n\n"
        f"User        : {user_email}\n"
        f"Session ID  : {session_id}\n"
        f"Confidence  : {confidence:.2f}%\n"
        f"Timestamp   : {datetime.now(timezone.utc).isoformat()}\n\n"
        f"Please review this session immediately."
    )
    try:
        sns  = get_sns_client()
        resp = sns.publish(
            TopicArn = SNS_TOPIC_ARN,
            Message  = message,
            Subject  = "⚠️ LivenessLens — Spoof Alert",
        )
        logger.warning("SNS alert sent (MessageId: %s)", resp.get("MessageId"))
        return True
    except (BotoCoreError, ClientError) as exc:
        logger.error("SNS alert error: %s", exc)
        return False


# ══════════════════════════════════════════════
#  LAMBDA HELPER
# ══════════════════════════════════════════════

from typing import Optional

def invoke_lambda(payload: dict) -> Optional[dict]:
    """
    Synchronously invokes the LivenessLens Lambda processor.

    The Lambda function can handle:
      - Advanced fraud scoring
      - Logging to external SIEM systems
      - Triggering downstream workflows / Step Functions
      - Sending data to Kinesis streams

    Args:
        payload : Python dict sent as the Lambda event

    Returns:
        Parsed response dict from Lambda, or None on error
    """
    try:
        lam      = get_lambda_client()
        response = lam.invoke(
            FunctionName   = LAMBDA_FUNC_NAME,
            InvocationType = "RequestResponse",
            Payload        = json.dumps(payload).encode("utf-8"),
        )
        result = json.loads(response["Payload"].read())
        logger.info("Lambda '%s' invoked successfully", LAMBDA_FUNC_NAME)
        return result
    except (BotoCoreError, ClientError) as exc:
        logger.error("Lambda invocation error: %s", exc)
        return None
# ══════════════════════════════════════════════
#  PAGE ROUTES
# ══════════════════════════════════════════════

@app.route("/", methods=["GET"])
def index():
    """
    Landing page — entry point of the app.
    Shows Login and Register call-to-action buttons.
    Automatically redirects authenticated users to /dashboard.
    """
    if "user_email" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """
    Main dashboard — shows the liveness scanner and session controls.
    Protected route: requires an active login session.
    Passes the user object (name, email) to the template.
    """
    user = db_get_user(session["user_email"])
    return render_template("dashboard.html", user=user)


# ══════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    GET  → Render the registration form.
    POST → Validate input → Create DynamoDB user → Send SES welcome email → Redirect to login.
    """
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("register.html")

    # Collect form fields
    name     = request.form.get("name",     "").strip()
    email    = request.form.get("email",    "").strip().lower()
    password = request.form.get("password", "").strip()
    confirm  = request.form.get("confirm",  "").strip()

    # Input validation
    errors = []
    if not name:                       errors.append("Full name is required.")
    if not email or "@" not in email:  errors.append("A valid email address is required.")
    if len(password) < 8:              errors.append("Password must be at least 8 characters.")
    if password != confirm:            errors.append("Passwords do not match.")

    if errors:
        return render_template("register.html", errors=errors, name=name, email=email)

    # Write user to DynamoDB
    created = db_create_user(email, name, password)
    if not created:
        return render_template("register.html",
                               errors=["An account with this email already exists."],
                               name=name, email=email)

    logger.info("New user registered: %s", email)

    flash("✅ Account created successfully. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET  → Render the login form.
    POST → Validate credentials against DynamoDB → Start Flask session → Redirect to dashboard.
    """
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("login.html")

    email    = request.form.get("email",    "").strip().lower()
    password = request.form.get("password", "").strip()

    if not email or not password:
        return render_template("login.html",
                               error="Email and password are required.",
                               email=email)

    # Look up user in DynamoDB
    user = db_get_user(email)

    # Verify password (timing-safe)
    if not user or not verify_password(password, user["password"]):
        logger.warning("Failed login attempt: %s", email)
        return render_template("login.html",
                               error="Invalid email or password.",
                               email=email)

    # Store user info in Flask session (server-side)
    session["user_email"] = email
    session["user_name"]  = user.get("name", "User")
    logger.info("User logged in: %s", email)

    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    Clears the server-side Flask session and redirects to the landing page.
    Uses POST to prevent CSRF logout via GET links.
    """
    email = session.get("user_email", "unknown")
    session.clear()
    logger.info("User logged out: %s", email)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ══════════════════════════════════════════════
#  API: HEALTH CHECK
# ══════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health_check():
    """Lightweight health-check endpoint for AWS ELB/ALB target groups."""
    return jsonify({
        "status"  : "healthy",
        "service" : "LivenessLens",
        "region"  : AWS_REGION,
        "time"    : datetime.now(timezone.utc).isoformat(),
    }), 200


# ══════════════════════════════════════════════
#  API: CREATE LIVENESS SESSION
# ══════════════════════════════════════════════

@app.route("/create-session", methods=["POST"])
@login_required
def create_session():
    """
    Creates a Rekognition Face Liveness session.
    Frontend uses the returned session_id to launch the webcam challenge.

    Response: { "success": true, "session_id": "<UUID>" }
    """
    logger.info("POST /create-session — user: %s", session.get("user_email"))

    try:
        rekognition = get_rekognition_client()
        response    = rekognition.create_face_liveness_session(
            ClientRequestToken = str(uuid.uuid4()),
            Settings           = {"AuditImagesLimit": 4},
        )
        session_id = response["SessionId"]
        logger.info("Liveness session created: %s", session_id)
        return jsonify({"success": True, "session_id": session_id}), 200

    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        msg  = exc.response["Error"]["Message"]
        logger.error("Rekognition ClientError [%s]: %s", code, msg)
        return jsonify({"success": False, "error": f"Rekognition error: {msg}", "code": code}), 500

    except BotoCoreError as exc:
        logger.error("BotoCoreError create_session: %s", exc)
        return jsonify({"success": False, "error": "AWS connectivity error."}), 500

    except Exception as exc:
        logger.exception("Unexpected error in create_session: %s", exc)
        return jsonify({"success": False, "error": "Unexpected server error."}), 500


# ══════════════════════════════════════════════
#  API: GET LIVENESS RESULT
# ══════════════════════════════════════════════

@app.route("/get-result", methods=["POST"])
@login_required
def get_result():
    """
    Retrieves and evaluates the liveness session result.

    Steps:
      1  Validate session_id
      2  Call Rekognition GetFaceLivenessSessionResults
      3  Determine LIVE / SPOOF / FAILED verdict
      4  Save JSON audit log → S3
      5  If spoof → send SNS alert + SES email + invoke Lambda
      6  Return structured JSON response

    Request:  { "session_id": "<UUID>" }
    Response: { "success": true, "confidence": 95.3, "status": "LIVE", ... }
    """
    logger.info("POST /get-result — user: %s", session.get("user_email"))
    user_email = session.get("user_email", "")

    body = request.get_json(silent=True)
    if not body or not body.get("session_id", "").strip():
        return jsonify({"success": False, "error": "Missing required field: session_id"}), 400

    session_id = body["session_id"].strip()

    try:
        rekognition    = get_rekognition_client()
        response       = rekognition.get_face_liveness_session_results(SessionId=session_id)
        confidence     = float(response.get("Confidence", 0.0))
        session_status = response.get("Status", "UNKNOWN")

        # Determine verdict
        if session_status == "SUCCEEDED":
            status = "LIVE" if confidence >= 80 else "SPOOF"
        elif session_status == "FAILED":
            status, confidence = "FAILED", 0.0
        else:
            status = session_status

        logger.info("Session %s → %s (%.2f%%)", session_id, status, confidence)

        # Persist audit log to S3
        log_saved = save_audit_log_to_s3(session_id, confidence, status, user_email)

        # Spoof actions: SNS + SES email + Lambda
        alert_sent     = False
        email_sent     = False
        lambda_invoked = False

        if confidence < 80:
            alert_sent = send_sns_alert(session_id, confidence, user_email)
            email_sent = False

            # Invoke Lambda for extended post-processing
            lambda_result  = invoke_lambda({
                "event_type" : "SPOOF_DETECTED",
                "session_id" : session_id,
                "user_email" : user_email,
                "confidence" : confidence,
                "timestamp"  : datetime.now(timezone.utc).isoformat(),
            })
            lambda_invoked = lambda_result is not None

        return jsonify({
            "success"        : True,
            "session_id"     : session_id,
            "confidence"     : round(confidence, 2),
            "status"         : status,
            "raw_status"     : session_status,
            "alert_sent"     : alert_sent,
            "email_sent"     : email_sent,
            "log_saved"      : log_saved,
            "lambda_invoked" : lambda_invoked,
        }), 200

    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        msg  = exc.response["Error"]["Message"]
        logger.error("Rekognition ClientError [%s]: %s", code, msg)
        if code == "SessionNotFoundException":
            return jsonify({
                "success": False,
                "error"  : f"Session '{session_id}' not found or expired.",
                "code"   : code,
            }), 404
        return jsonify({"success": False, "error": f"Rekognition error: {msg}", "code": code}), 500

    except BotoCoreError as exc:
        logger.error("BotoCoreError get_result: %s", exc)
        return jsonify({"success": False, "error": "AWS connectivity error."}), 500

    except Exception as exc:
        logger.exception("Unexpected error in get_result: %s", exc)
        return jsonify({"success": False, "error": "Unexpected server error."}), 500


# ══════════════════════════════════════════════
#  API: INVOKE LAMBDA (manual trigger)
# ══════════════════════════════════════════════

@app.route("/invoke-lambda", methods=["POST"])
@login_required
def trigger_lambda():
    """
    Manually invoke the Lambda processor with a custom payload.
    Useful for admin workflows or triggered post-processing.

    Request:  { "payload": { ... } }
    Response: { "success": true, "result": { ... } }
    """
    body = request.get_json(silent=True)
    if not body or "payload" not in body:
        return jsonify({"success": False, "error": "Missing 'payload' field."}), 400

    logger.info("POST /invoke-lambda — user: %s", session.get("user_email"))
    result = invoke_lambda({
        **body["payload"],
        "invoked_by" : session.get("user_email"),
        "timestamp"  : datetime.now(timezone.utc).isoformat(),
    })

    if result is None:
        return jsonify({"success": False, "error": "Lambda invocation failed."}), 500

    return jsonify({"success": True, "result": result}), 200


# ══════════════════════════════════════════════
#  API: LIST AUDIT LOGS
# ══════════════════════════════════════════════

@app.route("/audit-logs", methods=["GET"])
@login_required
def list_audit_logs():
    """
    Returns a list of recent audit log file names from S3.
    Query param: limit (int, default 20, max 100)
    """
    limit = min(int(request.args.get("limit", 20)), 100)
    try:
        s3  = get_s3_client()
        res = s3.list_objects_v2(
            Bucket  = S3_BUCKET_NAME,
            Prefix  = "audit-logs/",
            MaxKeys = limit,
        )
        logs = [
            {
                "key"          : obj["Key"],
                "size_bytes"   : obj["Size"],
                "last_modified": obj["LastModified"].isoformat(),
            }
            for obj in res.get("Contents", [])
        ]
        return jsonify({"success": True, "logs": logs, "count": len(logs)}), 200

    except (BotoCoreError, ClientError) as exc:
        logger.error("S3 list_audit_logs error: %s", exc)
        return jsonify({"success": False, "error": "Failed to retrieve audit logs."}), 500


# ══════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════

if __name__ == "__main__":
    port       = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info("🚀 LivenessLens starting on port %d (debug=%s)", port, debug_mode)
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
