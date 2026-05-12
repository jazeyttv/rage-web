"""
rage web server — Flask + MongoDB
"""

import os, secrets, string, random
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path

import bcrypt
import jwt
from flask import Flask, request, jsonify, send_from_directory, g

BASE       = Path(__file__).parent
PUBLIC     = BASE / "public"
MONGO_URI  = os.environ.get("MONGO_URI", "")
PORT       = int(os.environ.get("PORT", 3000))
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))

app = Flask(__name__)

# ── MongoDB lazy connection ────────────────────────────────────────────────────
_client = None
_db     = None

def get_db():
    global _client, _db
    if _db is None:
        from pymongo import MongoClient
        if not MONGO_URI:
            raise RuntimeError("MONGO_URI environment variable is not set")
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        _db = _client.get_default_database()
        # Indexes (safe to call multiple times)
        _db["users"].create_index("username", unique=True)
        _db["users"].create_index("email",    unique=True)
        _db["license_keys"].create_index("key_code", unique=True)
        _db["license_keys"].create_index("user_id")
    return _db

def users(): return get_db()["users"]
def keys():  return get_db()["license_keys"]

# ── Helpers ────────────────────────────────────────────────────────────────────
TEAM_ROLES = {"admin", "hwid_team", "blacklist_team", "user"}

def now():
    return datetime.now(timezone.utc)

def gen_key():
    def seg(): return "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"RAGE-{seg()}-{seg()}-{seg()}"

def ser(doc):
    if doc is None: return None
    from bson import ObjectId
    d = dict(doc)
    d["id"] = str(d.pop("_id", ""))
    for k, v in list(d.items()):
        if isinstance(v, ObjectId):  d[k] = str(v)
        elif isinstance(v, datetime): d[k] = v.strftime("%Y-%m-%d %H:%M:%S")
    return d

def ser_all(docs): return [ser(d) for d in docs]

def oid(s):
    from bson import ObjectId
    try: return ObjectId(str(s))
    except: return None

def make_token(user):
    return jwt.encode(
        {"id": user["id"], "username": user["username"], "role": user["role"],
         "exp": now() + timedelta(days=7)},
        JWT_SECRET, algorithm="HS256"
    )

# ── Auth decorators ────────────────────────────────────────────────────────────
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

admin_required     = role_required("admin")
hwid_required      = role_required("admin", "hwid_team")
blacklist_required = role_required("admin", "blacklist_team")

# ── Static files ───────────────────────────────────────────────────────────────
@app.route("/style.css")
def serve_css():
    return send_from_directory(str(PUBLIC), "style.css")

@app.route("/<path:filename>")
def serve_static(filename):
    # Only serve actual static files (css, js, images etc), not page routes
    filepath = PUBLIC / filename
    if filepath.exists() and filepath.is_file():
        return send_from_directory(str(PUBLIC), filename)
    return send_from_directory(str(PUBLIC), "index.html"), 404

# ── Pages (explicit routes — must come before catch-all) ──────────────────────
@app.route("/")
def page_index():        return send_from_directory(str(PUBLIC), "index.html")

@app.route("/login")
def page_login():        return send_from_directory(str(PUBLIC), "login.html")

@app.route("/register")
def page_register():     return send_from_directory(str(PUBLIC), "register.html")

@app.route("/dashboard")
def page_dashboard():    return send_from_directory(str(PUBLIC), "dashboard.html")

@app.route("/admin")
def page_admin():        return send_from_directory(str(PUBLIC), "admin.html")

@app.route("/hwid-panel")
def page_hwid():         return send_from_directory(str(PUBLIC), "hwid-panel.html")

@app.route("/blacklist-panel")
def page_blacklist():    return send_from_directory(str(PUBLIC), "blacklist-panel.html")

# ── /verify (rage.lua) ─────────────────────────────────────────────────────────
@app.route("/verify", methods=["POST"])
def verify():
    from pymongo import DESCENDING
    data     = request.get_json(silent=True) or {}
    key_code = (data.get("key") or "").strip()
    hwid     = (data.get("hwid") or "").strip()
    if not key_code or not hwid:
        return jsonify(ok=False, msg="Missing key or hwid")

    entry = keys().find_one({"key_code": key_code})
    if not entry:           return jsonify(ok=False, msg="Unknown key")
    if not entry["active"]: return jsonify(ok=False, msg="Key revoked")

    exp = entry.get("expires_at")
    if exp and exp.replace(tzinfo=timezone.utc) < now():
        return jsonify(ok=False, msg="Key expired")

    if not entry.get("hwid"):
        keys().update_one({"_id": entry["_id"]},
                          {"$set": {"hwid": hwid, "hwid_bound_at": now(), "last_seen": now()}})
        return jsonify(ok=True, msg="Key activated")

    if entry["hwid"] != hwid:
        return jsonify(ok=False, msg="HWID mismatch")

    keys().update_one({"_id": entry["_id"]}, {"$set": {"last_seen": now()}})
    return jsonify(ok=True, msg="OK")

# ── Auth API ───────────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    from pymongo.errors import DuplicateKeyError
    d        = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip()
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    if not username or not email or not password:
        return jsonify(error="All fields required"), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400

    role = "admin" if users().count_documents({}) == 0 else "user"
    pw   = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        result = users().insert_one({"username": username, "email": email,
                                     "password": pw, "role": role, "created_at": now()})
    except DuplicateKeyError:
        return jsonify(error="Username or email already taken"), 409

    user = ser(users().find_one({"_id": result.inserted_id}))
    return jsonify(token=make_token(user), user={k: user[k] for k in ("id","username","email","role")})

@app.route("/api/auth/login", methods=["POST"])
def login():
    d        = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    if not username or not password:
        return jsonify(error="All fields required"), 400

    row = users().find_one({"$or": [{"username": username}, {"email": username}]})
    if not row or not bcrypt.checkpw(password.encode(), row["password"].encode()):
        return jsonify(error="Invalid credentials"), 401

    user = ser(row)
    return jsonify(token=make_token(user), user={k: user[k] for k in ("id","username","email","role")})

# ── User API ───────────────────────────────────────────────────────────────────
@app.route("/api/user/me")
@token_required
def user_me():
    u = ser(users().find_one({"_id": oid(g.cu["id"])}))
    return jsonify({k: u[k] for k in ("id","username","email","role","created_at")})

@app.route("/api/user/keys")
@token_required
def user_keys():
    from pymongo import DESCENDING
    out = []
    for k in keys().find({"user_id": g.cu["id"]}).sort("created_at", DESCENDING):
        d = ser(k)
        d["hwid_bound"] = bool(k.get("hwid"))
        out.append(d)
    return jsonify(out)

# ── Admin API ──────────────────────────────────────────────────────────────────
@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    return jsonify(
        users=users().count_documents({}),
        keys=keys().count_documents({}),
        active=keys().count_documents({"active": True}),
        expiring=keys().count_documents({"active": True, "expires_at": {"$ne": None, "$lt": now() + timedelta(days=7)}})
    )

@app.route("/api/admin/users")
@admin_required
def admin_users():
    from pymongo import DESCENDING
    out = []
    for u in users().find().sort("created_at", DESCENDING):
        d = ser(u)
        d["key_count"] = keys().count_documents({"user_id": d["id"]})
        out.append(d)
    return jsonify(out)

@app.route("/api/admin/users/<uid>/role", methods=["PATCH"])
@admin_required
def admin_user_role(uid):
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in TEAM_ROLES: return jsonify(error="Invalid role"), 400
    users().update_one({"_id": oid(uid)}, {"$set": {"role": role}})
    return jsonify(ser(users().find_one({"_id": oid(uid)})))

@app.route("/api/admin/users/<uid>", methods=["DELETE"])
@admin_required
def admin_delete_user(uid):
    keys().update_many({"user_id": uid}, {"$set": {"user_id": None}})
    users().delete_one({"_id": oid(uid)})
    return jsonify(ok=True)

@app.route("/api/admin/keys")
@admin_required
def admin_keys():
    from pymongo import DESCENDING
    out = []
    for k in keys().find().sort("created_at", DESCENDING):
        d = ser(k)
        uid = d.get("user_id")
        if uid and len(str(uid)) == 24:
            u = users().find_one({"_id": oid(uid)})
            d["assigned_to"] = u["username"] if u else None
        else:
            d["assigned_to"] = None
        out.append(d)
    return jsonify(out)

@app.route("/api/admin/keys/generate", methods=["POST"])
@admin_required
def admin_generate():
    from pymongo.errors import DuplicateKeyError
    d       = request.get_json(silent=True) or {}
    product = (d.get("product") or "").strip()
    if not product: return jsonify(error="product is required"), 400
    expires_at = d.get("expires_at")
    if expires_at:
        try: expires_at = datetime.fromisoformat(expires_at.replace("Z","")).replace(tzinfo=timezone.utc)
        except: expires_at = None
    user_id = d.get("user_id") or None
    note    = d.get("note") or None
    count   = min(max(int(d.get("count") or 1), 1), 50)
    out = []
    for _ in range(count):
        code = gen_key()
        try:
            result = keys().insert_one({
                "key_code": code, "product": product, "user_id": user_id,
                "expires_at": expires_at, "hwid": None, "hwid_bound_at": None,
                "last_seen": None, "active": True, "note": note,
                "created_at": now(), "created_by": g.cu["id"]
            })
            out.append(ser(keys().find_one({"_id": result.inserted_id})))
        except DuplicateKeyError:
            pass
    return jsonify(out)

@app.route("/api/admin/keys/<kid>/assign", methods=["PATCH"])
@admin_required
def admin_assign(kid):
    user_id = (request.get_json(silent=True) or {}).get("user_id") or None
    keys().update_one({"_id": oid(kid)}, {"$set": {"user_id": user_id}})
    return jsonify(ser(keys().find_one({"_id": oid(kid)})))

@app.route("/api/admin/keys/<kid>/active", methods=["PATCH"])
@admin_required
def admin_toggle_active(kid):
    active = bool((request.get_json(silent=True) or {}).get("active"))
    keys().update_one({"_id": oid(kid)}, {"$set": {"active": active}})
    return jsonify(ser(keys().find_one({"_id": oid(kid)})))

@app.route("/api/admin/keys/<kid>/expiry", methods=["PATCH"])
@admin_required
def admin_expiry(kid):
    exp = (request.get_json(silent=True) or {}).get("expires_at") or None
    if exp:
        try: exp = datetime.fromisoformat(exp.replace("Z","")).replace(tzinfo=timezone.utc)
        except: exp = None
    keys().update_one({"_id": oid(kid)}, {"$set": {"expires_at": exp}})
    return jsonify(ser(keys().find_one({"_id": oid(kid)})))

@app.route("/api/admin/keys/<kid>", methods=["DELETE"])
@admin_required
def admin_delete_key(kid):
    keys().delete_one({"_id": oid(kid)})
    return jsonify(ok=True)

# ── HWID Team API ──────────────────────────────────────────────────────────────
@app.route("/api/hwid/stats")
@hwid_required
def hwid_stats():
    total = keys().count_documents({})
    bound = keys().count_documents({"hwid": {"$ne": None}})
    return jsonify(total=total, bound=bound, unbound=total - bound)

@app.route("/api/hwid/keys")
@hwid_required
def hwid_keys():
    from pymongo import DESCENDING
    out = []
    for k in keys().find().sort("hwid_bound_at", DESCENDING):
        d = ser(k)
        uid = d.get("user_id")
        if uid and len(str(uid)) == 24:
            u = users().find_one({"_id": oid(uid)})
            d["assigned_to"] = u["username"] if u else None
        else:
            d["assigned_to"] = None
        out.append(d)
    return jsonify(out)

@app.route("/api/hwid/keys/<kid>/reset-hwid", methods=["PATCH"])
@hwid_required
def hwid_reset(kid):
    keys().update_one({"_id": oid(kid)}, {"$set": {"hwid": None, "hwid_bound_at": None}})
    return jsonify(ok=True)

# ── Blacklist Team API ─────────────────────────────────────────────────────────
@app.route("/api/blacklist/stats")
@blacklist_required
def blacklist_stats():
    total   = keys().count_documents({})
    revoked = keys().count_documents({"active": False})
    return jsonify(total=total, revoked=revoked, active=total - revoked)

@app.route("/api/blacklist/keys")
@blacklist_required
def blacklist_keys():
    from pymongo import DESCENDING
    out = []
    for k in keys().find().sort("created_at", DESCENDING):
        d = ser(k)
        uid = d.get("user_id")
        if uid and len(str(uid)) == 24:
            u = users().find_one({"_id": oid(uid)})
            d["assigned_to"] = u["username"] if u else None
        else:
            d["assigned_to"] = None
        out.append(d)
    return jsonify(out)

@app.route("/api/blacklist/keys/<kid>/revoke", methods=["PATCH"])
@blacklist_required
def blacklist_revoke(kid):
    keys().update_one({"_id": oid(kid)}, {"$set": {"active": False}})
    return jsonify(ok=True)

@app.route("/api/blacklist/keys/<kid>/activate", methods=["PATCH"])
@blacklist_required
def blacklist_activate(kid):
    keys().update_one({"_id": oid(kid)}, {"$set": {"active": True}})
    return jsonify(ok=True)

# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n  rage server  —  http://localhost:{PORT}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
