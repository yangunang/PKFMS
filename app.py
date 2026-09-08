import base64
import functools
import os
import secrets
import sqlite3
from datetime import datetime
from io import BytesIO

import pyotp
import segno
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import (Flask, g, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from openpyxl import Workbook
from openpyxl.styles import Font
from werkzeug.security import check_password_hash, generate_password_hash

from i18n import LANGS, TRANSLATIONS

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # sessions reset on restart; fine for a personal tool
DATA_DIR = os.environ.get("DATA_DIR", ".")
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE = os.path.join(DATA_DIR, "credentials.db")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")


def load_config():
    """config.json holds the encryption "key". Generated on first run if absent.
    Losing the master password is recoverable (flask reset-password) as long as
    this file is intact \u2014 so back it up, and protect the data directory."""
    import json
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as fh:
            cfg = json.load(fh)
        if cfg.get("key"):
            return cfg
    else:
        cfg = {}
    cfg["key"] = secrets.token_urlsafe(32)
    with open(CONFIG_PATH, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(CONFIG_PATH, 0o600)
    return cfg


CONFIG = load_config()
DEFAULT_ENVIRONMENTS = ["home", "work", "personal", "finance"]
DEFAULT_CATEGORIES = ["img", "video", "docx"]
DEFAULT_NOTE_CATEGORIES = ["work", "daily expenses", "mood journal"]

def current_lang():
    return session.get("lang", "en")


def tr(key, **vars):
    s = TRANSLATIONS.get(current_lang(), TRANSLATIONS["en"]).get(key) or TRANSLATIONS["en"].get(key, key)
    for k, v in vars.items():
        s = s.replace("{" + k + "}", str(v))
    return s


@app.context_processor
def inject_i18n():
    return {"T": TRANSLATIONS.get(current_lang(), TRANSLATIONS["en"]),
            "LANG": current_lang(), "LANGS": LANGS}


@app.route("/lang/<code>")
def set_lang(code):
    if code in LANGS:
        session["lang"] = code
    return redirect(request.args.get("next") or request.referrer or url_for("index"))


# The data key is derived from CONFIG["key"] (config.json), not the password \u2014
# so a lost password is recoverable with `flask reset-password`.
_TOKENS = set()  # valid session tokens
_FERNET = None  # cached data Fernet


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            env TEXT NOT NULL DEFAULT 'home',
            account BLOB NOT NULL,
            password BLOB NOT NULL,
            info BLOB
        );
        CREATE TABLE IF NOT EXISTS environments (
            name TEXT PRIMARY KEY,
            position INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS file_categories (
            name TEXT PRIMARY KEY,
            position INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS note_categories (
            name TEXT PRIMARY KEY,
            position INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title BLOB NOT NULL,
            body BLOB NOT NULL,
            category TEXT NOT NULL,
            created TEXT NOT NULL DEFAULT (date('now'))
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            env TEXT NOT NULL,
            category TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded TEXT NOT NULL DEFAULT (datetime('now'))
        );"""
    )
    if db.execute("SELECT COUNT(*) FROM environments").fetchone()[0] == 0:
        db.executemany("INSERT INTO environments (name, position) VALUES (?, ?)",
                       [(n, i) for i, n in enumerate(DEFAULT_ENVIRONMENTS)])
    if db.execute("SELECT COUNT(*) FROM file_categories").fetchone()[0] == 0:
        db.executemany("INSERT INTO file_categories (name, position) VALUES (?, ?)",
                       [(n, i) for i, n in enumerate(DEFAULT_CATEGORIES)])
    cols = [r[1] for r in db.execute("PRAGMA table_info(credentials)").fetchall()]
    if "info" not in cols:
        db.execute("ALTER TABLE credentials ADD COLUMN info BLOB")
    if "description" not in cols:
        db.execute("ALTER TABLE credentials ADD COLUMN description BLOB")
    if "short_info" not in cols:
        db.execute("ALTER TABLE credentials ADD COLUMN short_info BLOB")
    fcols = [r[1] for r in db.execute("PRAGMA table_info(files)").fetchall()]
    if "description" not in fcols:
        db.execute("ALTER TABLE files ADD COLUMN description BLOB")
    if "tags" not in fcols:
        db.execute("ALTER TABLE files ADD COLUMN tags TEXT")
    if "cred_id" not in fcols:
        db.execute("ALTER TABLE files ADD COLUMN cred_id INTEGER")
    ncols = [r[1] for r in db.execute("PRAGMA table_info(notes)").fetchall()]
    if "env" not in ncols:
        db.execute("ALTER TABLE notes ADD COLUMN env TEXT")
    if (db.execute("SELECT value FROM settings WHERE key = 'totp_secret'").fetchone()
            and not db.execute("SELECT value FROM settings WHERE key = 'totp_confirmed'").fetchone()):
        db.execute("INSERT INTO settings (key, value) VALUES ('totp_confirmed', '1')")
    if db.execute("SELECT COUNT(*) FROM note_categories").fetchone()[0] == 0:
        db.executemany("INSERT INTO note_categories (name, position) VALUES (?, ?)",
                       [(n, i) for i, n in enumerate(DEFAULT_NOTE_CATEGORIES)])
    db.commit()
    db.close()


def get_environments():
    rows = get_db().execute("SELECT name FROM environments ORDER BY position").fetchall()
    return [r["name"] for r in rows]


def get_categories():
    rows = get_db().execute("SELECT name FROM file_categories ORDER BY position").fetchall()
    return [r["name"] for r in rows]


def get_note_categories():
    rows = get_db().execute("SELECT name FROM note_categories ORDER BY position").fetchall()
    return [r["name"] for r in rows]


def get_setting(key):
    row = get_db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(key, value):
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    db.commit()


def derive_fernet(master_password: str, salt_b64: str) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(salt_b64),
        iterations=480_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)


def data_fernet():
    global _FERNET
    if _FERNET is None:
        salt = get_setting("salt")
        if salt is None:
            return None
        _FERNET = derive_fernet(CONFIG["key"], salt)
    return _FERNET


def current_fernet():
    token = session.get("token")
    return data_fernet() if token and token in _TOKENS else None


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if get_setting("pw_hash") is None:
            return redirect(url_for("setup"))
        if current_fernet() is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped





# ---------- recovery CLI ----------

@app.cli.command("reset-password")
def reset_password():
    """Lost the master password? Sets a new one. Data stays readable because the
    encryption key lives in config.json, not in the password."""
    import getpass
    with app.app_context():
        if get_setting("pw_hash") is None:
            print("No account exists yet \u2014 open the app to run first-time setup.")
            return
        pw = getpass.getpass("New master password (min 8 chars): ")
        if len(pw) < 8:
            print("Too short. Aborted.")
            return
        if getpass.getpass("Repeat it: ") != pw:
            print("Passwords do not match. Aborted.")
            return
        set_setting("pw_hash", generate_password_hash(pw))
        print("Password updated. All encrypted data is intact. Log in with the new password.")


@app.cli.command("reset-2fa")
def reset_2fa():
    """Lost your authenticator? Generates a new TOTP secret (data and password kept)."""
    with app.app_context():
        if get_setting("pw_hash") is None:
            print("No account exists yet \u2014 open the app to run first-time setup.")
            return
        totp_secret = pyotp.random_base32()
        set_setting("totp_secret", totp_secret)
        set_setting("totp_confirmed", "0")
        uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name="credentials", issuer_name="My Credentials")
        print("\nNew 2FA secret generated. Scan this QR code with your authenticator app:\n")
        segno.make(uri, error="m").terminal(compact=True, border=2)
        print(f"\nOr enter the secret manually: {totp_secret}\n")
        print("Open the app: it will ask for a code once to confirm the new secret.")
        print("Your master password and all stored data are unchanged.")


@app.cli.command("factory-reset")
def factory_reset():
    """DANGER: deletes the account AND all encrypted data, returning to first-run setup."""
    confirm = input("Type RESET to delete the account and ALL data: ")
    if confirm.strip() != "RESET":
        print("Aborted.")
        return
    with app.app_context():
        db = get_db()
        for table in ("settings", "credentials", "files", "notes"):
            db.execute(f"DELETE FROM {table}")
        db.commit()
        import shutil
        for name in os.listdir(UPLOAD_DIR):
            path = os.path.join(UPLOAD_DIR, name)
            if os.path.isfile(path):
                os.remove(path)
            else:
                shutil.rmtree(path, ignore_errors=True)
        print("Wiped. Open the app to run first-time setup again.")


# ---------- first-run setup ----------

def totp_confirmed():
    return get_setting("totp_confirmed") == "1"


def render_qr_step(error=None):
    totp_secret = get_setting("totp_secret")
    uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name="credentials", issuer_name="My Credentials"
    )
    qr = segno.make(uri, error="m").svg_data_uri(scale=4, border=2)
    return render_template("setup.html", totp_secret=totp_secret,
                           totp_qr=qr, done=True, error=error)


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if get_setting("pw_hash") is not None:
        # password set but 2FA never verified -> resume at the QR step
        if not totp_confirmed():
            return render_qr_step()
        return redirect(url_for("login"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if len(pw) < 8:
            return render_template("setup.html", error="Password must be at least 8 characters.")
        set_setting("pw_hash", generate_password_hash(pw))
        set_setting("salt", base64.b64encode(secrets.token_bytes(16)).decode())
        set_setting("totp_secret", pyotp.random_base32())
        return render_qr_step()
    return render_template("setup.html")


@app.route("/setup/verify", methods=["POST"])
def setup_verify():
    if get_setting("pw_hash") is None:
        return redirect(url_for("setup"))
    if totp_confirmed():
        return redirect(url_for("login"))
    code = request.form.get("code", "").replace(" ", "")
    if pyotp.TOTP(get_setting("totp_secret")).verify(code, valid_window=1):
        set_setting("totp_confirmed", "1")
        return render_template("setup.html", verified=True)
    return render_qr_step(error=tr("wrongCode"))


# ---------- login / logout ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if get_setting("pw_hash") is None or not totp_confirmed():
        return redirect(url_for("setup"))
    error = None
    step = "password"
    if request.method == "POST":
        step = request.form.get("step", "password")
        if step == "password":
            pw = request.form.get("password", "")
            if check_password_hash(get_setting("pw_hash"), pw):
                session["pending_2fa"] = True
                return render_template("login.html", step="otp")
            error = tr("wrongPw")
        elif step == "otp":
            code = request.form.get("code", "").replace(" ", "")
            if not session.get("pending_2fa"):
                return redirect(url_for("login"))
            if pyotp.TOTP(get_setting("totp_secret")).verify(code, valid_window=1):
                session.pop("pending_2fa")
                token = secrets.token_hex(16)
                session["token"] = token
                _TOKENS.add(token)
                return redirect(url_for("index"))
            error = tr("wrongCode")
            return render_template("login.html", step="otp", error=error)
    return render_template("login.html", step="password", error=error)


@app.route("/logout")
def logout():
    _TOKENS.discard(session.pop("token", None))
    session.clear()
    return redirect(url_for("login"))


# ---------- encrypted CRUD ----------

def decrypt_rows(f):
    out = []
    rows = get_db().execute("SELECT * FROM credentials ORDER BY id").fetchall()
    for r in rows:
        try:
            out.append({
                "id": r["id"], "env": r["env"],
                "account": f.decrypt(r["account"]).decode(),
                "password": f.decrypt(r["password"]).decode(),
                "info": f.decrypt(r["info"]).decode() if r["info"] else "",
                "short_info": f.decrypt(r["short_info"]).decode() if r["short_info"] else "",
                "has_desc": bool(r["description"] and f.decrypt(r["description"]).decode().strip()),
                "has_files": bool(get_db().execute(
                    "SELECT 1 FROM files WHERE cred_id = ? LIMIT 1", (r["id"],)).fetchone()),
            })
        except InvalidToken:
            out.append({"id": r["id"], "env": r["env"], "account": "(cannot decrypt)",
                        "password": "", "info": "", "short_info": ""})
    return out


@app.route("/")
@login_required
def index():
    rows = decrypt_rows(current_fernet())
    files = get_db().execute("SELECT id, filename, env, category, size FROM files ORDER BY id").fetchall()
    files = [dict(f) for f in files]
    return render_template("index.html", rows=rows, environments=get_environments(),
                           files=files, categories=get_categories())


def account_options(f):
    """[{id, label}] of credential rows with a non-empty account, used as file tags."""
    out = []
    for r in get_db().execute("SELECT id, account FROM credentials ORDER BY id").fetchall():
        try:
            label = f.decrypt(r["account"]).decode()
        except InvalidToken:
            continue
        if label.strip():
            out.append({"id": r["id"], "label": label})
    return out


def file_tags(row):
    import json
    try:
        v = json.loads(row["tags"]) if row["tags"] else []
        return [int(x) for x in v]
    except (ValueError, TypeError):
        return []


@app.route("/api/rows", methods=["POST"])
@login_required
def add_row():
    f = current_fernet()
    env = get_environments()[0]
    db = get_db()
    cur = db.execute(
        "INSERT INTO credentials (env, account, password, info, short_info) VALUES (?, ?, ?, ?, ?)",
        (env, f.encrypt(b""), f.encrypt(b""), f.encrypt(b""), f.encrypt(b"")),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "env": env, "account": "", "password": "",
                    "info": "", "short_info": ""})


@app.route("/rows/<int:row_id>/description")
@login_required
def description_page(row_id):
    f = current_fernet()
    r = get_db().execute("SELECT * FROM credentials WHERE id = ?", (row_id,)).fetchone()
    if r is None:
        return redirect(url_for("index"))
    try:
        account = f.decrypt(r["account"]).decode()
        desc = f.decrypt(r["description"]).decode() if r["description"] else ""
    except InvalidToken:
        account, desc = "(cannot decrypt)", ""
    return render_template("description.html", row_id=row_id, account=account,
                           env=r["env"], desc=desc, environments=get_environments())


@app.route("/rows/<int:row_id>/files")
@login_required
def account_files_page(row_id):
    f = current_fernet()
    r = get_db().execute("SELECT * FROM credentials WHERE id = ?", (row_id,)).fetchone()
    if r is None:
        return redirect(url_for("index"))
    try:
        account = f.decrypt(r["account"]).decode()
    except InvalidToken:
        account = "(cannot decrypt)"
    files = [dict(x) for x in get_db().execute(
        "SELECT id, filename, category, size FROM files WHERE cred_id = ? ORDER BY id DESC",
        (row_id,)).fetchall()]
    return render_template("account_files.html", account=account, env=r["env"],
                           row_id=row_id, files=files, environments=get_environments(),
                           categories=get_categories())


@app.route("/api/rows/<int:row_id>", methods=["PATCH"])
@login_required
def update_row(row_id):
    f = current_fernet()
    data = request.get_json(force=True)
    db = get_db()
    for k, v in data.items():
        if k == "env":
            if v not in get_environments():
                return jsonify({"error": "invalid environment"}), 400
            db.execute("UPDATE credentials SET env = ? WHERE id = ?", (v, row_id))
        elif k in ("account", "password", "info", "short_info", "description"):
            db.execute(f"UPDATE credentials SET {k} = ? WHERE id = ?",
                       (f.encrypt(str(v).encode()), row_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/rows/<int:row_id>", methods=["DELETE"])
@login_required
def delete_row(row_id):
    db = get_db()
    db.execute("DELETE FROM credentials WHERE id = ?", (row_id,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/envs", methods=["GET", "POST"])
@login_required
def envs():
    db = get_db()
    if request.method == "POST":
        name = (request.get_json(force=True).get("name") or "").strip().lower()
        if not name:
            return jsonify({"error": "empty name"}), 400
        if name in get_environments():
            return jsonify({"error": tr("exists", name=name)}), 400
        pos = db.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM environments").fetchone()[0]
        db.execute("INSERT INTO environments (name, position) VALUES (?, ?)", (name, pos))
        db.commit()
    return jsonify({"environments": get_environments()})


@app.route("/api/envs/<name>", methods=["DELETE"])
@login_required
def delete_env(name):
    db = get_db()
    n = db.execute("SELECT COUNT(*) FROM credentials WHERE env = ?", (name,)).fetchone()[0]
    if n:
        return jsonify({"error": tr("inUse", name=name, n=n)}), 400
    if db.execute("SELECT COUNT(*) FROM environments").fetchone()[0] <= 1:
        return jsonify({"error": tr("atLeastOne")}), 400
    db.execute("DELETE FROM environments WHERE name = ?", (name,))
    db.commit()
    return jsonify({"environments": get_environments()})


# ---------- files ----------

@app.route("/files")
@login_required
def files_page():
    rows = []
    for x in get_db().execute("SELECT * FROM files ORDER BY id").fetchall():
        d = dict(x)
        d["has_desc"] = bool(x["description"]) or bool(file_tags(x))
        rows.append(d)
    return render_template("files.html", files=rows,
                           environments=get_environments(), categories=get_categories())


@app.route("/api/files", methods=["POST"])
@login_required
def upload_file():
    f = request.files.get("file")
    if f is None or not f.filename:
        return jsonify({"error": "no file"}), 400
    env = request.form.get("env") or get_environments()[0]
    category = request.form.get("category") or get_categories()[0]
    if env not in get_environments() or category not in get_categories():
        return jsonify({"error": "invalid env or category"}), 400
    cred_id = request.form.get("cred_id") or None
    if cred_id is not None:
        try:
            cred_id = int(cred_id)
        except ValueError:
            return jsonify({"error": "invalid account"}), 400
        if get_db().execute("SELECT 1 FROM credentials WHERE id = ?", (cred_id,)).fetchone() is None:
            return jsonify({"error": "invalid account"}), 400
    # Keep the real (Unicode) filename; only strip path separators and control chars.
    name = os.path.basename(f.filename.replace("\\", "/")).strip()
    name = "".join(c for c in name if c.isprintable() and c not in '<>:"|?*') or "file"
    subdir = datetime.now().strftime("%Y/%m")  # organized by year/month
    os.makedirs(os.path.join(UPLOAD_DIR, subdir), exist_ok=True)
    stored = f"{subdir}/{name}"
    stem, ext = os.path.splitext(name)
    n = 1
    while os.path.exists(os.path.join(UPLOAD_DIR, stored)):  # avoid collisions
        stored = f"{subdir}/{stem} ({n}){ext}"
        n += 1
    path = os.path.join(UPLOAD_DIR, stored)
    f.save(path)
    size = os.path.getsize(path)
    db = get_db()
    cur = db.execute(
        "INSERT INTO files (filename, stored_name, env, category, size, cred_id) VALUES (?, ?, ?, ?, ?, ?)",
        (name, stored, env, category, size, cred_id),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "filename": name, "env": env,
                    "category": category, "size": size, "cred_id": cred_id})


@app.route("/files/<int:file_id>/description")
@login_required
def file_description_page(file_id):
    import json
    f = current_fernet()
    r = get_db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if r is None:
        return redirect(url_for("files_page"))
    try:
        desc = f.decrypt(r["description"]).decode() if r["description"] else ""
    except InvalidToken:
        desc = ""
    return render_template("file_description.html", file=dict(r), desc=desc,
                           tags=file_tags(r), accounts=account_options(f),
                           environments=get_environments(), categories=get_categories())


@app.route("/api/files/<int:file_id>", methods=["PATCH"])
@login_required
def update_file(file_id):
    data = request.get_json(force=True)
    db = get_db()
    if "env" in data:
        if data["env"] not in get_environments():
            return jsonify({"error": "invalid environment"}), 400
        db.execute("UPDATE files SET env = ? WHERE id = ?", (data["env"], file_id))
    if "category" in data:
        if data["category"] not in get_categories():
            return jsonify({"error": "invalid category"}), 400
        db.execute("UPDATE files SET category = ? WHERE id = ?", (data["category"], file_id))
    if "description" in data:
        db.execute("UPDATE files SET description = ? WHERE id = ?",
                   (current_fernet().encrypt(str(data["description"]).encode()), file_id))
    if "tags" in data:
        import json
        valid = {r["id"] for r in db.execute("SELECT id FROM credentials").fetchall()}
        try:
            tags = [int(x) for x in data["tags"]]
        except (ValueError, TypeError):
            return jsonify({"error": "invalid tags"}), 400
        if not all(t in valid for t in tags):
            return jsonify({"error": "invalid tags"}), 400
        db.execute("UPDATE files SET tags = ? WHERE id = ?", (json.dumps(tags), file_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/files/<int:file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id):
    db = get_db()
    row = db.execute("SELECT stored_name FROM files WHERE id = ?", (file_id,)).fetchone()
    if row:
        try:
            os.remove(os.path.join(UPLOAD_DIR, row["stored_name"]))
        except FileNotFoundError:
            pass
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        db.commit()
    return jsonify({"ok": True})


@app.route("/files/<int:file_id>/download")
@login_required
def download_file(file_id):
    row = get_db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        return "Not found", 404
    return send_file(os.path.join(UPLOAD_DIR, row["stored_name"]),
                     as_attachment=True, download_name=row["filename"])


@app.route("/api/categories", methods=["GET", "POST"])
@login_required
def categories():
    db = get_db()
    if request.method == "POST":
        name = (request.get_json(force=True).get("name") or "").strip().lower()
        if not name:
            return jsonify({"error": "empty name"}), 400
        if name in get_categories():
            return jsonify({"error": tr("exists", name=name)}), 400
        pos = db.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM file_categories").fetchone()[0]
        db.execute("INSERT INTO file_categories (name, position) VALUES (?, ?)", (name, pos))
        db.commit()
    return jsonify({"categories": get_categories()})


@app.route("/api/categories/<name>", methods=["DELETE"])
@login_required
def delete_category(name):
    db = get_db()
    n = db.execute("SELECT COUNT(*) FROM files WHERE category = ?", (name,)).fetchone()[0]
    if n:
        return jsonify({"error": tr("inUse", name=name, n=n)}), 400
    if db.execute("SELECT COUNT(*) FROM file_categories").fetchone()[0] <= 1:
        return jsonify({"error": tr("atLeastOne")}), 400
    db.execute("DELETE FROM file_categories WHERE name = ?", (name,))
    db.commit()
    return jsonify({"categories": get_categories()})


# ---------- journal ----------

@app.route("/notes")
@login_required
def notes_page():
    f = current_fernet()
    posts = []
    for r in get_db().execute("SELECT * FROM notes ORDER BY id DESC").fetchall():
        try:
            posts.append({"id": r["id"], "category": r["category"], "created": r["created"],
                          "env": r["env"] or get_environments()[0],
                          "title": f.decrypt(r["title"]).decode(),
                          "body": f.decrypt(r["body"]).decode()})
        except InvalidToken:
            posts.append({"id": r["id"], "category": r["category"], "created": r["created"],
                          "env": r["env"] or get_environments()[0],
                          "title": "(cannot decrypt)", "body": ""})
    return render_template("notes.html", posts=posts, categories=get_note_categories(),
                           environments=get_environments())


@app.route("/api/notes", methods=["POST"])
@login_required
def add_note():
    f = current_fernet()
    data = request.get_json(force=True)
    category = data.get("category") or get_note_categories()[0]
    if category not in get_note_categories():
        return jsonify({"error": "invalid category"}), 400
    env = data.get("env") or get_environments()[0]
    if env not in get_environments():
        return jsonify({"error": "invalid environment"}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO notes (title, body, category, env) VALUES (?, ?, ?, ?)",
        (f.encrypt(str(data.get("title", "")).encode()),
         f.encrypt(str(data.get("body", "")).encode()), category, env),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/notes/<int:note_id>", methods=["PATCH"])
@login_required
def update_note(note_id):
    f = current_fernet()
    data = request.get_json(force=True)
    db = get_db()
    if "category" in data:
        if data["category"] not in get_note_categories():
            return jsonify({"error": "invalid category"}), 400
        db.execute("UPDATE notes SET category = ? WHERE id = ?", (data["category"], note_id))
    if "env" in data:
        if data["env"] not in get_environments():
            return jsonify({"error": "invalid environment"}), 400
        db.execute("UPDATE notes SET env = ? WHERE id = ?", (data["env"], note_id))
    for k in ("title", "body"):
        if k in data:
            db.execute(f"UPDATE notes SET {k} = ? WHERE id = ?",
                       (f.encrypt(str(data[k]).encode()), note_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id):
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/note-categories", methods=["GET", "POST"])
@login_required
def note_categories():
    db = get_db()
    if request.method == "POST":
        name = (request.get_json(force=True).get("name") or "").strip().lower()
        if not name:
            return jsonify({"error": "empty name"}), 400
        if name in get_note_categories():
            return jsonify({"error": tr("exists", name=name)}), 400
        pos = db.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM note_categories").fetchone()[0]
        db.execute("INSERT INTO note_categories (name, position) VALUES (?, ?)", (name, pos))
        db.commit()
    return jsonify({"categories": get_note_categories()})


@app.route("/api/note-categories/<name>", methods=["DELETE"])
@login_required
def delete_note_category(name):
    db = get_db()
    n = db.execute("SELECT COUNT(*) FROM notes WHERE category = ?", (name,)).fetchone()[0]
    if n:
        return jsonify({"error": tr("inUse", name=name, n=n)}), 400
    if db.execute("SELECT COUNT(*) FROM note_categories").fetchone()[0] <= 1:
        return jsonify({"error": tr("atLeastOne")}), 400
    db.execute("DELETE FROM note_categories WHERE name = ?", (name,))
    db.commit()
    return jsonify({"categories": get_note_categories()})


@app.route("/export", methods=["POST"])
@login_required
def export_excel():
    # The download is locked with the login auth key: the workbook is placed in
    # an AES-256 encrypted ZIP whose password IS the master password, which the
    # user must re-enter here (it is never stored server-side).
    pw = request.form.get("password", "")
    if not check_password_hash(get_setting("pw_hash"), pw):
        return jsonify({"error": tr("wrongPw")}), 403
    rows = decrypt_rows(current_fernet())
    wb = Workbook()
    ws = wb.active
    ws.title = "Credentials"
    ws.append(["account info", "account short info", "Account", "Password", "Environment"])
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for r in rows:
        ws.append([r["info"], r["short_info"], r["account"], r["password"], r["env"]])
    for col, width in zip("ABCDE", (34, 22, 30, 26, 16)):
        ws.column_dimensions[col].width = width
    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    # Encrypt the workbook itself (standard OOXML/AES) so Excel, LibreOffice and
    # Numbers all just prompt for the password — no external unzip tool needed.
    from msoffcrypto.format.ooxml import OOXMLFile
    enc = BytesIO()
    OOXMLFile(buf).encrypt(pw, enc)
    enc.seek(0)
    return send_file(
        enc,
        as_attachment=True,
        download_name="credentials.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


init_db()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
