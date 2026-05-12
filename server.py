"""
rage web server  —  Python 3, Flask
Backends: SQLite (local) or PostgreSQL (Render via DATABASE_URL)
"""

import os, secrets, string, random
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path

import bcrypt
import jwt
from flask import Flask, request, jsonify, send_from_directory, g

# ── Config ─────────────────────────────────────────────────────────────────────
BASE       = Path(__file__).parent
PUBLIC     = BASE / "public"
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_PG     = bool(DATABASE_URL)
PORT       = int(os.environ.get("PORT", 3000))
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))

app = Flask(__name__, static_folder=str(PUBLIC), static_url_path="")

# ── Database abstraction ────────────────────────────────────────────────────────

if USE_PG:
    import psycopg2, psycopg2.extras
    P = "%s"  # placeholder

    def _conn():
        return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

    def get_db():
        if "db" not in g:
            g.db = _conn()
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        db = g.pop("db", None)
        if db:
            try: db.close()
            except: pass

    def qall(sql, params=()):
        db = get_db()
        cur = db.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def qone(sql, params=()):
        db = get_db()
        cur = db.cursor()
        cur.execute(sql, params)
        r = cur.fetchone()
        return dict(r) if r else None

    def qexec(sql, params=()):
        db = get_db()
        cur = db.cursor()
        cur.execute(sql, params)
        db.commit()
        return cur

    def now_sql(): return "NOW()"
    def dt_now(): return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    SCHEMA = f"""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            username   TEXT UNIQUE NOT NULL,
            email      TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS license_keys (
            id            SERIAL PRIMARY KEY,
            key_code      TEXT UNIQUE NOT NULL,
            product       TEXT NOT NULL DEFAULT 'rage.lua',
            user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
            expires_at    TIMESTAMPTZ,
            hwid          TEXT,
            hwid_bound_at TIMESTAMPTZ,
            last_seen     TIMESTAMPTZ,
            active        INTEGER NOT NULL DEFAULT 1,
            note          TEXT,
            created_at    TIMESTAMPTZ DEFAULT NOW(),
            created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL
        );
    """

else:
    import sqlite3
    P = "?"

    def get_db():
        if "db" not in g:
            db = sqlite3.connect(str(BASE / "rage.db"), detect_types=sqlite3.PARSE_DECLTYPES)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA foreign_keys=ON")
            g.db = db
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        db = g.pop("db", None)
        if db: db.close()

    def qall(sql, params=()):
        return [dict(r) for r in get_db().execute(sql, params).fetchall()]

    def qone(sql, params=()):
        r = get_db().execute(sql, params).fetchone()
        return dict(r) if r else None

    def qexec(sql, params=()):
        db = get_db()
        cur = db.execute(sql, params)
        db.commit()
        return cur

    def dt_now(): return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    SCHEMA = """
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
    """

def init_db():
    with app.app_context():
        if USE_PG:
            db = get_db()
            cur = db.cursor()
            for stmt in [s.strip() for s in SCHEMA.split(";") if s.strip()]:
                cur.execute(stmt)
            db.commit()
        else:
            get_db().executescript(SCHEMA)

# ── Auth helpers ────────────────────────────────────────────────────────────────

TEAM_ROLES = {"admin", "hwid_team", "blacklist_team", "user"}

def make_token(user):
    return jwt.encode(
        {"id": user["id"], "username": user["username"], "role": user["role"],
         "exp": datetime.now(timezone.utc) + timedelta(days=7)},
        JWT_SECRET, algorithm="HS256"
    )

def token_required(f):
    @wraps(f)
    def dec(*a, **kw):
        h = request.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return jsonify(error="Unauthorized"), 401
        try:
            g.cu = jwt.decode(h[7:], JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify(error="Token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="Invalid token"), 401
        return f(*a, **kw)
    return dec

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @token_required
        def dec(*a, **kw):
            if g.cu.get("role") not in roles:
                return jsonify(error="Access denied"), 403
            return f(*a, **kw)
        return dec
    return decorator

admin_required    = role_required("admin")
hwid_required     = role_required("admin", "hwid_team")
blacklist_required = role_required("admin", "blacklist_team")

def gen_key():
    def seg(): return "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"RAGE-{seg()}-{seg()}-{seg()}"

# ── /verify (rage.lua) ──────────────────────────────────────────────────────────

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key_code = (data.get("key") or "").strip()
    hwid     = (data.get("hwid") or "").strip()
    if not key_code or not hwid:
        return jsonify(ok=False, msg="Missing key or hwid")

    row = qone(f"SELECT * FROM license_keys WHERE key_code={P}", (key_code,))
    if not row:   return jsonify(ok=False, msg="Unknown key")
    if not row["active"]: return jsonify(ok=False, msg="Key revoked")

    exp = row.get("expires_at")
    if exp:
        exp_str = str(exp)[:19]
        if exp_str < dt_now():
            return jsonify(ok=False, msg="Key expired")

    if not row["hwid"]:
        qexec(f"UPDATE license_keys SET hwid={P},hwid_bound_at={P},last_seen={P} WHERE id={P}",
              (hwid, dt_now(), dt_now(), row["id"]))
        return jsonify(ok=True, msg="Key activated")

    if row["hwid"] != hwid:
        return jsonify(ok=False, msg="HWID mismatch")

    qexec(f"UPDATE license_keys SET last_seen={P} WHERE id={P}", (dt_now(), row["id"]))
    return jsonify(ok=True, msg="OK")

# ── Auth ────────────────────────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    d = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip()
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    if not username or not email or not password:
        return jsonify(error="All fields required"), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400

    count = qone("SELECT COUNT(*) as c FROM users")["c"]
    role  = "admin" if int(count) == 0 else "user"
    pw    = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        if USE_PG:
            row = qone(f"INSERT INTO users (username,email,password,role) VALUES ({P},{P},{P},{P}) RETURNING id,username,email,role",
                       (username, email, pw, role))
        else:
            qexec(f"INSERT INTO users (username,email,password,role) VALUES ({P},{P},{P},{P})",
                  (username, email, pw, role))
            row = qone(f"SELECT id,username,email,role FROM users WHERE username={P}", (username,))
    except Exception as e:
        if "unique" in str(e).lower() or "UNIQUE" in str(e):
            return jsonify(error="Username or email already taken"), 409
        return jsonify(error="Server error"), 500

    return jsonify(token=make_token(row), user=row)

@app.route("/api/auth/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    if not username or not password:
        return jsonify(error="All fields required"), 400

    row = qone(f"SELECT * FROM users WHERE username={P} OR email={P}", (username, username))
    if not row or not bcrypt.checkpw(password.encode(), row["password"].encode()):
        return jsonify(error="Invalid credentials"), 401

    user = {k: row[k] for k in ("id", "username", "email", "role")}
    return jsonify(token=make_token(user), user=user)

# ── User ────────────────────────────────────────────────────────────────────────

@app.route("/api/user/me")
@token_required
def user_me():
    return jsonify(qone(f"SELECT id,username,email,role,created_at FROM users WHERE id={P}", (g.cu["id"],)))

@app.route("/api/user/keys")
@token_required
def user_keys():
    return jsonify(qall(
        f"SELECT id,key_code,product,expires_at,active,hwid IS NOT NULL as hwid_bound,created_at "
        f"FROM license_keys WHERE user_id={P} ORDER BY created_at DESC", (g.cu["id"],)
    ))

# ── Admin ───────────────────────────────────────────────────────────────────────

@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    users  = qone("SELECT COUNT(*) as c FROM users")["c"]
    keys   = qone("SELECT COUNT(*) as c FROM license_keys")["c"]
    active = qone("SELECT COUNT(*) as c FROM license_keys WHERE active=1")["c"]
    if USE_PG:
        exp = qone("SELECT COUNT(*) as c FROM license_keys WHERE active=1 AND expires_at IS NOT NULL AND expires_at < NOW()+INTERVAL '7 days'")["c"]
    else:
        exp = qone("SELECT COUNT(*) as c FROM license_keys WHERE active=1 AND expires_at IS NOT NULL AND expires_at < datetime('now','+7 days')")["c"]
    return jsonify(users=int(users), keys=int(keys), active=int(active), expiring=int(exp))

@app.route("/api/admin/users")
@admin_required
def admin_users():
    return jsonify(qall(
        "SELECT u.id,u.username,u.email,u.role,u.created_at,COUNT(k.id) as key_count "
        "FROM users u LEFT JOIN license_keys k ON k.user_id=u.id "
        "GROUP BY u.id,u.username,u.email,u.role,u.created_at ORDER BY u.created_at DESC"
    ))

@app.route("/api/admin/users/<int:uid>/role", methods=["PATCH"])
@admin_required
def admin_user_role(uid):
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in TEAM_ROLES:
        return jsonify(error="Invalid role"), 400
    qexec(f"UPDATE users SET role={P} WHERE id={P}", (role, uid))
    return jsonify(qone(f"SELECT id,username,role FROM users WHERE id={P}", (uid,)))

@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@admin_required
def admin_delete_user(uid):
    qexec(f"DELETE FROM users WHERE id={P}", (uid,))
    return jsonify(ok=True)

@app.route("/api/admin/keys")
@admin_required
def admin_keys():
    return jsonify(qall(
        "SELECT k.id,k.key_code,k.product,k.expires_at,k.active,k.hwid,k.hwid_bound_at,"
        "k.last_seen,k.note,k.created_at,u.username as assigned_to,u.id as user_id,"
        "a.username as created_by_name "
        "FROM license_keys k "
        "LEFT JOIN users u ON u.id=k.user_id "
        "LEFT JOIN users a ON a.id=k.created_by "
        "ORDER BY k.created_at DESC"
    ))

@app.route("/api/admin/keys/generate", methods=["POST"])
@admin_required
def admin_generate():
    d = request.get_json(silent=True) or {}
    product = (d.get("product") or "").strip()
    if not product: return jsonify(error="product is required"), 400
    expires_at = d.get("expires_at") or None
    user_id    = d.get("user_id") or None
    note       = d.get("note") or None
    count      = min(max(int(d.get("count") or 1), 1), 50)
    out = []
    for _ in range(count):
        code = gen_key()
        try:
            if USE_PG:
                row = qone(
                    f"INSERT INTO license_keys (key_code,product,user_id,expires_at,note,created_by) "
                    f"VALUES ({P},{P},{P},{P},{P},{P}) RETURNING *",
                    (code, product, user_id, expires_at, note, g.cu["id"])
                )
                if row: out.append(row)
            else:
                qexec(f"INSERT OR IGNORE INTO license_keys (key_code,product,user_id,expires_at,note,created_by) "
                      f"VALUES ({P},{P},{P},{P},{P},{P})",
                      (code, product, user_id, expires_at, note, g.cu["id"]))
                row = qone(f"SELECT * FROM license_keys WHERE key_code={P}", (code,))
                if row: out.append(row)
        except Exception: pass
    return jsonify(out)

@app.route("/api/admin/keys/<int:kid>/assign", methods=["PATCH"])
@admin_required
def admin_assign(kid):
    user_id = (request.get_json(silent=True) or {}).get("user_id") or None
    qexec(f"UPDATE license_keys SET user_id={P} WHERE id={P}", (user_id, kid))
    return jsonify(qone(f"SELECT * FROM license_keys WHERE id={P}", (kid,)))

@app.route("/api/admin/keys/<int:kid>/active", methods=["PATCH"])
@admin_required
def admin_toggle_active(kid):
    active = 1 if (request.get_json(silent=True) or {}).get("active") else 0
    qexec(f"UPDATE license_keys SET active={P} WHERE id={P}", (active, kid))
    return jsonify(qone(f"SELECT * FROM license_keys WHERE id={P}", (kid,)))

@app.route("/api/admin/keys/<int:kid>/expiry", methods=["PATCH"])
@admin_required
def admin_expiry(kid):
    exp = (request.get_json(silent=True) or {}).get("expires_at") or None
    qexec(f"UPDATE license_keys SET expires_at={P} WHERE id={P}", (exp, kid))
    return jsonify(qone(f"SELECT * FROM license_keys WHERE id={P}", (kid,)))

@app.route("/api/admin/keys/<int:kid>", methods=["DELETE"])
@admin_required
def admin_delete_key(kid):
    qexec(f"DELETE FROM license_keys WHERE id={P}", (kid,))
    return jsonify(ok=True)

# ── HWID Team ────────────────────────────────────────────────────────────────────

@app.route("/api/hwid/keys")
@hwid_required
def hwid_keys():
    return jsonify(qall(
        "SELECT k.id,k.key_code,k.product,k.hwid,k.hwid_bound_at,k.last_seen,"
        "k.active,k.expires_at,u.username as assigned_to "
        "FROM license_keys k LEFT JOIN users u ON u.id=k.user_id "
        "ORDER BY k.hwid_bound_at DESC"
    ))

@app.route("/api/hwid/keys/<int:kid>/reset-hwid", methods=["PATCH"])
@hwid_required
def hwid_reset(kid):
    qexec(f"UPDATE license_keys SET hwid=NULL,hwid_bound_at=NULL WHERE id={P}", (kid,))
    return jsonify(ok=True)

@app.route("/api/hwid/stats")
@hwid_required
def hwid_stats():
    total = qone("SELECT COUNT(*) as c FROM license_keys")["c"]
    bound = qone("SELECT COUNT(*) as c FROM license_keys WHERE hwid IS NOT NULL")["c"]
    return jsonify(total=int(total), bound=int(bound), unbound=int(total)-int(bound))

# ── Blacklist Team ───────────────────────────────────────────────────────────────

@app.route("/api/blacklist/keys")
@blacklist_required
def blacklist_keys():
    return jsonify(qall(
        "SELECT k.id,k.key_code,k.product,k.active,k.hwid,k.expires_at,"
        "k.created_at,u.username as assigned_to "
        "FROM license_keys k LEFT JOIN users u ON u.id=k.user_id "
        "ORDER BY k.created_at DESC"
    ))

@app.route("/api/blacklist/keys/<int:kid>/revoke", methods=["PATCH"])
@blacklist_required
def blacklist_revoke(kid):
    qexec(f"UPDATE license_keys SET active=0 WHERE id={P}", (kid,))
    return jsonify(ok=True)

@app.route("/api/blacklist/keys/<int:kid>/activate", methods=["PATCH"])
@blacklist_required
def blacklist_activate(kid):
    qexec(f"UPDATE license_keys SET active=1 WHERE id={P}", (kid,))
    return jsonify(ok=True)

@app.route("/api/blacklist/stats")
@blacklist_required
def blacklist_stats():
    total   = qone("SELECT COUNT(*) as c FROM license_keys")["c"]
    revoked = qone("SELECT COUNT(*) as c FROM license_keys WHERE active=0")["c"]
    return jsonify(total=int(total), revoked=int(revoked), active=int(total)-int(revoked))

# ── Pages ────────────────────────────────────────────────────────────────────────

@app.route("/")
def page_index():     return send_from_directory(str(PUBLIC), "index.html")

@app.route("/login")
def page_login():     return send_from_directory(str(PUBLIC), "login.html")

@app.route("/register")
def page_register():  return send_from_directory(str(PUBLIC), "register.html")

@app.route("/dashboard")
def page_dashboard(): return send_from_directory(str(PUBLIC), "dashboard.html")

@app.route("/admin")
def page_admin():     return send_from_directory(str(PUBLIC), "admin.html")

@app.route("/hwid-panel")
def page_hwid():      return send_from_directory(str(PUBLIC), "hwid-panel.html")

@app.route("/blacklist-panel")
def page_blacklist(): return send_from_directory(str(PUBLIC), "blacklist-panel.html")

# ── Run ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    backend = "PostgreSQL" if USE_PG else "SQLite"
    print(f"\n  rage server  —  http://localhost:{PORT}  [{backend}]\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
