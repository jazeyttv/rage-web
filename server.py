"""
rage web server  —  Python 3, Flask + SQLite
Run: python server.py
"""

import os, secrets, sqlite3, string, random
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path

import bcrypt
import jwt
from flask import Flask, request, jsonify, send_from_directory, g

# ── Config ────────────────────────────────────────────────────────────────────

BASE   = Path(__file__).parent
DB_PATH = BASE / "rage.db"
PUBLIC  = BASE / "public"

PORT       = int(os.environ.get("PORT", 3000))
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))

app = Flask(__name__, static_folder=str(PUBLIC), static_url_path="")

# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(DB_PATH), detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT UNIQUE NOT NULL,
                email      TEXT UNIQUE NOT NULL,
                password   TEXT NOT NULL,
                role       TEXT NOT NULL DEFAULT 'user',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS license_keys (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                key_code      TEXT UNIQUE NOT NULL,
                product       TEXT NOT NULL DEFAULT 'rage.lua',
                user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
                expires_at    TEXT,
                hwid          TEXT,
                hwid_bound_at TEXT,
                last_seen     TEXT,
                active        INTEGER NOT NULL DEFAULT 1,
                note          TEXT,
                created_at    TEXT DEFAULT (datetime('now')),
                created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL
            );
        """)
        db.commit()

# ── Auth helpers ──────────────────────────────────────────────────────────────

def make_token(user):
    return jwt.encode(
        {"id": user["id"], "username": user["username"], "role": user["role"],
         "exp": datetime.now(timezone.utc) + timedelta(days=7)},
        JWT_SECRET, algorithm="HS256"
    )

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify(error="Unauthorized"), 401
        try:
            g.current_user = jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify(error="Token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="Invalid token"), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_user.get("role") != "admin":
            return jsonify(error="Admin only"), 403
        return f(*args, **kwargs)
    return decorated

def row_to_dict(row):
    return dict(row) if row else None

def rows_to_list(rows):
    return [dict(r) for r in rows]

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def gen_key():
    def seg(): return "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"RAGE-{seg()}-{seg()}-{seg()}"

# ── rage.lua verify endpoint ──────────────────────────────────────────────────

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key_code = (data.get("key") or "").strip()
    hwid     = (data.get("hwid") or "").strip()

    if not key_code or not hwid:
        return jsonify(ok=False, msg="Missing key or hwid")

    db  = get_db()
    row = db.execute("SELECT * FROM license_keys WHERE key_code=?", (key_code,)).fetchone()
    if not row:
        return jsonify(ok=False, msg="Unknown key")
    if not row["active"]:
        return jsonify(ok=False, msg="Key revoked")
    if row["expires_at"] and row["expires_at"] < now():
        return jsonify(ok=False, msg="Key expired")

    if not row["hwid"]:
        db.execute("UPDATE license_keys SET hwid=?,hwid_bound_at=?,last_seen=? WHERE id=?",
                   (hwid, now(), now(), row["id"]))
        db.commit()
        return jsonify(ok=True, msg="Key activated")

    if row["hwid"] != hwid:
        return jsonify(ok=False, msg="HWID mismatch")

    db.execute("UPDATE license_keys SET last_seen=? WHERE id=?", (now(), row["id"]))
    db.commit()
    return jsonify(ok=True, msg="OK")

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify(error="All fields required"), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400

    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    role  = "admin" if count == 0 else "user"

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        db.execute("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
                   (username, email, pw_hash, role))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username or email already taken"), 409

    user = row_to_dict(db.execute("SELECT id,username,email,role FROM users WHERE username=?",
                                   (username,)).fetchone())
    return jsonify(token=make_token(user), user=user)

@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify(error="All fields required"), 400

    db  = get_db()
    row = db.execute("SELECT * FROM users WHERE username=? OR email=?",
                     (username, username)).fetchone()
    if not row or not bcrypt.checkpw(password.encode(), row["password"].encode()):
        return jsonify(error="Invalid credentials"), 401

    user = {"id": row["id"], "username": row["username"],
            "email": row["email"], "role": row["role"]}
    return jsonify(token=make_token(user), user=user)

# ── User routes ───────────────────────────────────────────────────────────────

@app.route("/api/user/me")
@token_required
def user_me():
    db  = get_db()
    row = db.execute("SELECT id,username,email,role,created_at FROM users WHERE id=?",
                     (g.current_user["id"],)).fetchone()
    return jsonify(row_to_dict(row))

@app.route("/api/user/keys")
@token_required
def user_keys():
    db   = get_db()
    rows = db.execute(
        "SELECT id,key_code,product,expires_at,active,hwid IS NOT NULL as hwid_bound,created_at "
        "FROM license_keys WHERE user_id=? ORDER BY created_at DESC",
        (g.current_user["id"],)
    ).fetchall()
    return jsonify(rows_to_list(rows))

# ── Admin routes ──────────────────────────────────────────────────────────────

@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    db = get_db()
    users    = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    keys     = db.execute("SELECT COUNT(*) FROM license_keys").fetchone()[0]
    active   = db.execute("SELECT COUNT(*) FROM license_keys WHERE active=1").fetchone()[0]
    expiring = db.execute(
        "SELECT COUNT(*) FROM license_keys WHERE active=1 AND expires_at IS NOT NULL "
        "AND expires_at < datetime('now','+7 days')"
    ).fetchone()[0]
    return jsonify(users=users, keys=keys, active=active, expiring=expiring)

@app.route("/api/admin/users")
@admin_required
def admin_users():
    db   = get_db()
    rows = db.execute(
        "SELECT u.id,u.username,u.email,u.role,u.created_at, COUNT(k.id) as key_count "
        "FROM users u LEFT JOIN license_keys k ON k.user_id=u.id "
        "GROUP BY u.id ORDER BY u.created_at DESC"
    ).fetchall()
    return jsonify(rows_to_list(rows))

@app.route("/api/admin/users/<int:uid>/role", methods=["PATCH"])
@admin_required
def admin_user_role(uid):
    data = request.get_json(silent=True) or {}
    role = data.get("role")
    if role not in ("user", "admin"):
        return jsonify(error="Invalid role"), 400
    db = get_db()
    db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    db.commit()
    row = db.execute("SELECT id,username,role FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify(row_to_dict(row))

@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@admin_required
def admin_delete_user(uid):
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    return jsonify(ok=True)

@app.route("/api/admin/keys")
@admin_required
def admin_keys():
    db   = get_db()
    rows = db.execute(
        "SELECT k.id,k.key_code,k.product,k.expires_at,k.active,k.hwid,k.hwid_bound_at,"
        "k.last_seen,k.note,k.created_at,u.username as assigned_to,u.id as user_id,"
        "a.username as created_by_name "
        "FROM license_keys k "
        "LEFT JOIN users u ON u.id=k.user_id "
        "LEFT JOIN users a ON a.id=k.created_by "
        "ORDER BY k.created_at DESC"
    ).fetchall()
    return jsonify(rows_to_list(rows))

@app.route("/api/admin/keys/generate", methods=["POST"])
@admin_required
def admin_generate():
    data       = request.get_json(silent=True) or {}
    product    = (data.get("product") or "").strip()
    expires_at = data.get("expires_at") or None
    user_id    = data.get("user_id") or None
    note       = data.get("note") or None
    count      = min(max(int(data.get("count") or 1), 1), 50)

    if not product:
        return jsonify(error="product is required"), 400

    db  = get_db()
    out = []
    for _ in range(count):
        code = gen_key()
        try:
            db.execute(
                "INSERT INTO license_keys (key_code,product,user_id,expires_at,note,created_by) "
                "VALUES (?,?,?,?,?,?)",
                (code, product, user_id, expires_at, note, g.current_user["id"])
            )
            db.commit()
            row = db.execute("SELECT * FROM license_keys WHERE key_code=?", (code,)).fetchone()
            out.append(row_to_dict(row))
        except sqlite3.IntegrityError:
            pass  # duplicate key_code, skip
    return jsonify(out)

@app.route("/api/admin/keys/<int:kid>/assign", methods=["PATCH"])
@admin_required
def admin_assign(kid):
    data    = request.get_json(silent=True) or {}
    user_id = data.get("user_id") or None
    db = get_db()
    db.execute("UPDATE license_keys SET user_id=? WHERE id=?", (user_id, kid))
    db.commit()
    row = db.execute("SELECT * FROM license_keys WHERE id=?", (kid,)).fetchone()
    return jsonify(row_to_dict(row))

@app.route("/api/admin/keys/<int:kid>/active", methods=["PATCH"])
@admin_required
def admin_toggle_active(kid):
    data   = request.get_json(silent=True) or {}
    active = 1 if data.get("active") else 0
    db = get_db()
    db.execute("UPDATE license_keys SET active=? WHERE id=?", (active, kid))
    db.commit()
    row = db.execute("SELECT * FROM license_keys WHERE id=?", (kid,)).fetchone()
    return jsonify(row_to_dict(row))

@app.route("/api/admin/keys/<int:kid>/reset-hwid", methods=["PATCH"])
@admin_required
def admin_reset_hwid(kid):
    db = get_db()
    db.execute("UPDATE license_keys SET hwid=NULL,hwid_bound_at=NULL WHERE id=?", (kid,))
    db.commit()
    row = db.execute("SELECT * FROM license_keys WHERE id=?", (kid,)).fetchone()
    return jsonify(row_to_dict(row))

@app.route("/api/admin/keys/<int:kid>/expiry", methods=["PATCH"])
@admin_required
def admin_expiry(kid):
    data       = request.get_json(silent=True) or {}
    expires_at = data.get("expires_at") or None
    db = get_db()
    db.execute("UPDATE license_keys SET expires_at=? WHERE id=?", (expires_at, kid))
    db.commit()
    row = db.execute("SELECT * FROM license_keys WHERE id=?", (kid,)).fetchone()
    return jsonify(row_to_dict(row))

@app.route("/api/admin/keys/<int:kid>", methods=["DELETE"])
@admin_required
def admin_delete_key(kid):
    db = get_db()
    db.execute("DELETE FROM license_keys WHERE id=?", (kid,))
    db.commit()
    return jsonify(ok=True)

# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(str(PUBLIC), "index.html")

@app.route("/login")
def page_login():
    return send_from_directory(str(PUBLIC), "login.html")

@app.route("/register")
def page_register():
    return send_from_directory(str(PUBLIC), "register.html")

@app.route("/dashboard")
def page_dashboard():
    return send_from_directory(str(PUBLIC), "dashboard.html")

@app.route("/admin")
def page_admin():
    return send_from_directory(str(PUBLIC), "admin.html")

# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print(f"\n  rage server running at  http://localhost:{PORT}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
