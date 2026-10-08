import os
import json
import re
import shutil
import socket
import hashlib
import subprocess
import threading
import time
import sys
import zipfile
import io
import psutil
from collections import defaultdict, deque
from flask import Flask, send_from_directory, send_file, request, jsonify, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECURE_ROOT = os.path.abspath(BASE_DIR)
USERS_ROOT = os.path.join(SECURE_ROOT, "USERS")
DATA_DIR = os.path.join(SECURE_ROOT, "DATA")
USERS_DB = os.path.join(DATA_DIR, "users.json")

os.makedirs(USERS_ROOT, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET_KEY", "CHANGE_ME_" + os.urandom(16).hex())

app.config["MAX_CONTENT_LENGTH"] = 128 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 12
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", 240))
LOGIN_MAX_FAILS = int(os.environ.get("LOGIN_MAX_FAILS", 5))
IP_BAN_SECONDS = int(os.environ.get("IP_BAN_SECONDS", 600))

_rate_buckets = defaultdict(deque)
_banned_ips = {}
_login_fails = defaultdict(list)
_sec_stats = {"blocked": 0, "banned": 0}

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "M7MAD_FF")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "M7MAD_FF235467")

running_procs = {}
server_states = {}
lock = threading.Lock()

SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

MAX_LOG_SIZE = 2 * 1024 * 1024  # ✅ 2MB حد أقصى لحجم السجل


# ═══════════════════════════════════════════════════════════
# Security
# ═══════════════════════════════════════════════════════════

def client_ip() -> str:
    fwd = (request.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
    return fwd or (request.remote_addr or "unknown")


def _prune(dq, window):
    now = time.time()
    while dq and now - dq[0] > window:
        dq.popleft()


@app.before_request
def security_gate():
    ip = client_ip()
    unban_at = _banned_ips.get(ip)
    if unban_at:
        if time.time() < unban_at:
            _sec_stats["blocked"] += 1
            return jsonify({"success": False, "message": "IP temporarily blocked"}), 429
        _banned_ips.pop(ip, None)

    dq = _rate_buckets[ip]
    _prune(dq, 60)
    if len(dq) >= RATE_LIMIT_PER_MIN:
        _banned_ips[ip] = time.time() + IP_BAN_SECONDS
        _sec_stats["banned"] += 1
        _sec_stats["blocked"] += 1
        return jsonify({"success": False, "message": "Rate limit exceeded"}), 429
    dq.append(time.time())

    try:
        s = load_settings()
    except Exception:
        s = {"signup_enabled": True}

    if s.get("maintenance_mode"):
        always_allowed = ("/login", "/api/auth/login", "/logout", "/maintenance", "/api/announcement")
        if request.path.startswith(always_allowed):
            return None
        if is_admin_session():
            return None
        if request.method != "GET" or request.path.startswith(("/api", "/server", "/files", "/add", "/servers")):
            return jsonify({"success": False, "message": "Panel is under maintenance", "maintenance": True}), 503
        return send_from_directory(BASE_DIR, "maintenance.html"), 503
    return None


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return resp


@app.errorhandler(413)
def err_too_large(e):
    return jsonify({"success": False, "message": "Upload too large (max 128MB)"}), 413


# ═══════════════════════════════════════════════════════════
# Login Protection
# ═══════════════════════════════════════════════════════════

def login_locked() -> bool:
    ip = client_ip()
    now = time.time()
    _login_fails[ip] = [t for t in _login_fails[ip] if now - t < 900]
    return len(_login_fails[ip]) >= LOGIN_MAX_FAILS


def record_login_fail():
    _login_fails[client_ip()].append(time.time())


def clear_login_fails():
    _login_fails.pop(client_ip(), None)


# ═══════════════════════════════════════════════════════════
# Settings
# ═══════════════════════════════════════════════════════════

def load_settings():
    defaults = {"signup_enabled": True, "maintenance_mode": False, "announcement": ""}
    if not os.path.exists(SETTINGS_FILE):
        return dict(defaults)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f) or {}
        for k, v in defaults.items():
            if k not in d:
                d[k] = v
        return d
    except Exception:
        return dict(defaults)


def save_settings(s):
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)
    os.replace(tmp, SETTINGS_FILE)


# ═══════════════════════════════════════════════════════════
# Path Safety
# ═══════════════════════════════════════════════════════════

def safe_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"[\\/]+", "", name)
    name = re.sub(r"[^A-Za-z0-9\-_\. ]", "", name)
    return name[:200].strip()


def sanitize_folder_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-_\.]", "", name)
    return name[:200]


def get_user_servers_root(username: str) -> str:
    safe_username = re.sub(r'[^a-zA-Z0-9_.-]', '', username)
    return os.path.join(USERS_ROOT, safe_username, "servers")


def get_server_dir(owner: str, folder: str) -> str:
    safe_owner = re.sub(r'[^a-zA-Z0-9_.-]', '', owner)
    safe_folder = re.sub(r'[^a-zA-Z0-9_.-]', '', folder)
    base = get_user_servers_root(safe_owner)
    return os.path.join(base, safe_folder)


def ensure_user_dirs(username: str):
    try:
        path = get_user_servers_root(username)
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        print(f"Security Alert: {e}")


def parse_server_key(key: str, allow_admin: bool):
    key = (key or "").strip()
    if '..' in key or key.startswith('/') or key.startswith('\\'):
        raise ValueError("Invalid key format")

    if "::" in key:
        if not allow_admin or not is_admin_session():
            raise ValueError("forbidden")
        owner, folder = key.split("::", 1)
        owner, folder = owner.strip(), folder.strip()
        if not re.match(r'^[a-zA-Z0-9_.-]+$', owner) or not re.match(r'^[a-zA-Z0-9_.-]+$', folder):
            raise ValueError("Invalid characters")
        return owner, folder

    if not is_admin_session():
        username = current_username()
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username) or not re.match(r'^[a-zA-Z0-9_.-]+$', key):
            raise ValueError("Invalid characters")
        return username, key
    else:
        return current_username(), key


def can_access_key(key: str) -> bool:
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return False
    if is_admin_session():
        return True
    return owner == current_username()


def safe_join_server_path(key: str, rel_path: str = "") -> str:
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception as e:
        raise ValueError(f"Invalid key: {e}")

    server_root = get_server_dir(owner, folder)
    if not os.path.exists(server_root):
        raise FileNotFoundError(f"Server directory not found")

    if not rel_path:
        return server_root

    rel_path = rel_path.lstrip('/\\')
    if '..' in rel_path or rel_path.startswith('/') or rel_path.startswith('\\'):
        raise ValueError("Invalid path")

    full_path = os.path.join(server_root, rel_path)
    full_path = os.path.realpath(full_path)

    if not full_path.startswith(server_root + os.sep) and full_path != server_root:
        raise ValueError("Security violation")
    return full_path


# ═══════════════════════════════════════════════════════════
# State
# ═══════════════════════════════════════════════════════════

def set_state(key: str, state: str):
    with lock:
        server_states[key] = state


def get_state(key: str) -> str:
    with lock:
        return server_states.get(key, "Offline")


# ✅ محسّن: يقص السجل إذا صار أكبر من 2MB
def log_append(key: str, text: str):
    try:
        server_dir = safe_join_server_path(key, "")
        log_path = os.path.join(server_dir, "server.log")

        # ✅ إذا الملف أكبر من الحد، نقتطع النصف الأول
        if os.path.exists(log_path) and os.path.getsize(log_path) > MAX_LOG_SIZE:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            half = len(content) // 2
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("[SYSTEM] Log truncated (too large)\n" + content[half:])

        with open(log_path, "a", encoding="utf-8", errors="ignore") as f:
            f.write(text)
    except Exception:
        pass


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ═══════════════════════════════════════════════════════════
# Users
# ═══════════════════════════════════════════════════════════

def load_users():
    if not os.path.exists(USERS_DB):
        return {"users": []}
    try:
        with open(USERS_DB, "r", encoding="utf-8") as f:
            return json.load(f) or {"users": []}
    except Exception:
        return {"users": []}


def save_users(db):
    tmp = USERS_DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, USERS_DB)


def find_user(db, username: str):
    u = (username or "").strip().lower()
    for x in db.get("users", []):
        if (x.get("username") or "").strip().lower() == u:
            return x
    return None


def is_admin_session():
    u = session.get("user") or {}
    return bool(u.get("is_admin"))


def current_username():
    u = session.get("user") or {}
    return (u.get("username") or "").strip()


def get_user_limit(username: str) -> int:
    if is_admin_session():
        return 999999
    db = load_users()
    u = find_user(db, username)
    if not u:
        return 1
    return 1000 if u.get("premium", False) else 1


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        if not is_admin_session():
            return jsonify({"success": False, "message": "Admin only"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════
# Server Meta
# ═══════════════════════════════════════════════════════════

def ensure_meta(owner: str, folder: str):
    server_dir = get_server_dir(owner, folder)
    os.makedirs(server_dir, exist_ok=True)
    meta_path = os.path.join(server_dir, "meta.json")
    base = {
        "display_name": folder,
        "startup_file": "",
        "owner": owner,
        "banned": False,
        "runtime": "python",
        "auto_restart": True,
        "env": {}
    }
    if not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(base, f, indent=2)
    else:
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                m = json.load(f) or {}
        except Exception:
            m = {}
        changed = False
        for k, v in base.items():
            if k not in m:
                m[k] = v
                changed = True
        if changed:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(m, f, indent=2)
    return meta_path


def read_meta(owner: str, folder: str):
    meta_path = ensure_meta(owner, folder)
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {"display_name": folder, "startup_file": "", "owner": owner, "banned": False, "runtime": "python"}


def write_meta(owner: str, folder: str, meta):
    meta_path = ensure_meta(owner, folder)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


# ═══════════════════════════════════════════════════════════
# Auto Install (Python + Node.js)
# ═══════════════════════════════════════════════════════════

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def installed_file_path(owner: str, folder: str):
    return os.path.join(get_server_dir(owner, folder), ".installed")


def read_installed(owner: str, folder: str):
    p = installed_file_path(owner, folder)
    data = {"req_sha": "", "pkg_sha": "", "pkgs": set()}
    if not os.path.exists(p):
        return data
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("REQ_SHA="):
                    data["req_sha"] = line.split("=", 1)[1].strip()
                elif line.startswith("PKG_SHA="):
                    data["pkg_sha"] = line.split("=", 1)[1].strip()
                else:
                    data["pkgs"].add(line)
    except Exception:
        pass
    return data


def write_installed(owner: str, folder: str, req_sha=None, pkg_sha=None, add_pkgs=None):
    p = installed_file_path(owner, folder)
    cur = read_installed(owner, folder)
    if req_sha is not None:
        cur["req_sha"] = req_sha
    if pkg_sha is not None:
        cur["pkg_sha"] = pkg_sha
    if add_pkgs:
        cur["pkgs"].update(add_pkgs)
    lines = []
    if cur["req_sha"]:
        lines.append(f"REQ_SHA={cur['req_sha']}")
    if cur["pkg_sha"]:
        lines.append(f"PKG_SHA={cur['pkg_sha']}")
    lines.extend(sorted(cur["pkgs"]))
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def ensure_requirements_installed(owner: str, folder: str, runtime: str = "python"):
    server_dir = get_server_dir(owner, folder)

    # ✅ Node.js
    if runtime == "node":
        pkg_path = os.path.join(server_dir, "package.json")
        if not os.path.exists(pkg_path):
            return False
        pkg_sha = sha256_file(pkg_path)
        cur = read_installed(owner, folder)
        if cur.get("pkg_sha") == pkg_sha and os.path.isdir(os.path.join(server_dir, "node_modules")):
            return False
        log_append(f"{owner}::{folder}", "[SYSTEM] Installing npm dependencies...\n")
        try:
            subprocess.check_call(["npm", "install", "--omit=dev"], cwd=server_dir)
            write_installed(owner, folder, pkg_sha=pkg_sha)
            log_append(f"{owner}::{folder}", "[SYSTEM] npm install done\n")
            return True
        except subprocess.CalledProcessError as e:
            log_append(f"{owner}::{folder}", f"[SYSTEM] npm install failed: {e}\n")
            return False
        except FileNotFoundError:
            log_append(f"{owner}::{folder}", "[SYSTEM] npm not found — install Node.js first\n")
            return False

    # ✅ Python
    req_path = os.path.join(server_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return False

    req_sha = sha256_file(req_path)
    cur = read_installed(owner, folder)
    if cur["req_sha"] == req_sha:
        return False

    log_append(f"{owner}::{folder}", "[SYSTEM] Installing requirements.txt...\n")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=server_dir)
        write_installed(owner, folder, req_sha=req_sha)
        log_append(f"{owner}::{folder}", "[SYSTEM] requirements installed\n")
        return True
    except subprocess.CalledProcessError as e:
        log_append(f"{owner}::{folder}", f"[SYSTEM] requirements install failed: {e}\n")
        return False


# ═══════════════════════════════════════════════════════════
# Start Server
# ═══════════════════════════════════════════════════════════

def start_with_autoinstall(owner: str, folder: str, startup_file: str, runtime: str = "python", env: dict = None):
    server_dir = get_server_dir(owner, folder)
    log_path = os.path.join(server_dir, "server.log")
    log_file = open(log_path, "a", encoding="utf-8", errors="ignore")

    env_vars = os.environ.copy()
    if env:
        env_vars.update({k: str(v) for k, v in env.items()})

    # ✅ Node.js
    if runtime == "node":
        proc = subprocess.Popen(
            ["node", startup_file],
            cwd=server_dir,
            stdout=log_file, stderr=log_file,
            env=env_vars
        )
        return proc, log_file

    # ✅ Shell
    if runtime == "shell":
        proc = subprocess.Popen(
            ["bash", startup_file],
            cwd=server_dir,
            stdout=log_file, stderr=log_file,
            env=env_vars
        )
        return proc, log_file

    # ✅ Python (default) with auto-install wrapper
    wrapper_code = r'''
import runpy, sys, subprocess, traceback, re, os
script = sys.argv[1]
cwd = os.getcwd()

def append_installed(pkg):
    try:
        p = os.path.join(cwd, ".installed")
        existing = set()
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                existing = set([x.strip() for x in f.read().splitlines() if x.strip()])
        if pkg and pkg not in existing:
            with open(p, "a", encoding="utf-8") as f:
                f.write(pkg + "\n")
    except:
        pass

def parse_missing_name(e):
    n = getattr(e, "name", None)
    if n: return n
    s = str(e)
    m = re.search(r"No module named '([^']+)'", s)
    if m: return m.group(1)
    return None

while True:
    try:
        runpy.run_path(script, run_name="__main__")
        break
    except ModuleNotFoundError as e:
        pkg = parse_missing_name(e)
        if not pkg:
            traceback.print_exc()
            break
        print(f"[AUTO-INSTALL] Missing module: {pkg} -> installing...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            append_installed(pkg)
            print(f"[AUTO-INSTALL] Installed: {pkg} -> restarting...")
            continue
        except Exception as ex:
            print(f"[AUTO-INSTALL] Failed: {ex}")
            traceback.print_exc()
            break
    except Exception:
        traceback.print_exc()
        break
'''
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", wrapper_code, startup_file],
        cwd=server_dir,
        stdout=log_file, stderr=log_file,
        env=env_vars
    )
    return proc, log_file


def stop_proc(key: str):
    if key in running_procs:
        proc, logf = running_procs[key]
        try:
            p = psutil.Process(proc.pid)
            for child in p.children(recursive=True):
                try: child.kill()
                except: pass
            p.kill()
        except Exception:
            pass
        try:
            logf.close()
        except Exception:
            pass
        running_procs.pop(key, None)


# ═══════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════

@app.route("/")
@login_required
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/login")
def login_page():
    return send_from_directory(BASE_DIR, "login.html")


@app.route("/create")
def create_page():
    return send_from_directory(BASE_DIR, "create.html")


@app.route("/admin")
@login_required
def admin_page():
    if not is_admin_session():
        return redirect("/")
    return send_from_directory(BASE_DIR, "admin.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


@app.route("/maintenance")
def maintenance_page():
    return send_from_directory(BASE_DIR, "maintenance.html")


@app.route("/api/signup-status")
def signup_status():
    return jsonify({"success": True, "signup_enabled": bool(load_settings().get("signup_enabled", True))})


@app.route("/api/announcement")
def api_announcement():
    s = load_settings()
    return jsonify({"success": True, "announcement": s.get("announcement", ""), "maintenance_mode": bool(s.get("maintenance_mode", False))})


# ═══════════════════════════════════════════════════════════
# Auth
# ═══════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    if login_locked():
        return jsonify({"success": False, "message": "Too many failed attempts"}), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        clear_login_fails()
        session["user"] = {"username": ADMIN_USERNAME, "is_admin": True}
        session.permanent = True
        return jsonify({"success": True, "is_admin": True})

    db = load_users()
    u = find_user(db, username)
    if not u:
        record_login_fail()
        return jsonify({"success": False, "message": "Invalid username or password"}), 401
    if not u.get("active", True):
        return jsonify({"success": False, "message": "Account is banned"}), 403
    if not check_password_hash(u.get("password_hash", ""), password):
        record_login_fail()
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

    clear_login_fails()
    session["user"] = {"username": u.get("username"), "is_admin": False}
    session.permanent = True
    ensure_user_dirs(u.get("username"))
    return jsonify({"success": True, "is_admin": False})


@app.route("/api/auth/create", methods=["POST"])
def api_create():
    if not load_settings().get("signup_enabled", True):
        return jsonify({"success": False, "message": "Signup disabled"}), 403

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    password2 = data.get("password2") or ""

    if not username or len(username) < 3:
        return jsonify({"success": False, "message": "Username too short"}), 400
    if not re.fullmatch(r"[A-Za-z0-9_\.]+", username):
        return jsonify({"success": False, "message": "Invalid username"}), 400
    if username.upper() == ADMIN_USERNAME.upper():
        return jsonify({"success": False, "message": "Reserved username"}), 400
    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Invalid email"}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password too short"}), 400
    if password != password2:
        return jsonify({"success": False, "message": "Passwords don't match"}), 400

    db = load_users()
    if find_user(db, username):
        return jsonify({"success": False, "message": "Username exists"}), 409

    db["users"].append({
        "username": username,
        "email": email,
        "password_hash": generate_password_hash(password),
        "active": True,
        "premium": False
    })
    save_users(db)
    ensure_user_dirs(username)
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════
# Servers
# ═══════════════════════════════════════════════════════════

def list_all_servers_for_admin():
    servers = []
    if not os.path.isdir(USERS_ROOT):
        return servers
    for owner in sorted(os.listdir(USERS_ROOT)):
        root = get_user_servers_root(owner)
        if not os.path.isdir(root):
            continue
        for folder in sorted(os.listdir(root)):
            server_dir = get_server_dir(owner, folder)
            if not os.path.isdir(server_dir):
                continue
            meta = read_meta(owner, folder)
            banned = bool(meta.get("banned", False))
            key = f"{owner}::{folder}"
            st = "Banned" if banned else get_state(key)
            servers.append({
                "title": meta.get("display_name", folder),
                "folder": folder,
                "owner": owner,
                "key": key,
                "subtitle": f"Owner: {owner}",
                "startup_file": meta.get("startup_file", ""),
                "runtime": meta.get("runtime", "python"),
                "status": st
            })
    return servers


def list_servers_for_user(username: str):
    ensure_user_dirs(username)
    root = get_user_servers_root(username)
    servers = []
    if not os.path.isdir(root):
        return servers
    for folder in sorted(os.listdir(root)):
        server_dir = get_server_dir(username, folder)
        if not os.path.isdir(server_dir):
            continue
        meta = read_meta(username, folder)
        banned = bool(meta.get("banned", False))
        key = folder
        st = "Banned" if banned else get_state(key)
        servers.append({
            "title": meta.get("display_name", folder),
            "folder": folder,
            "owner": username,
            "key": key,
            "subtitle": f"Owner: {username}",
            "startup_file": meta.get("startup_file", ""),
            "runtime": meta.get("runtime", "python"),
            "status": st
        })
    return servers


@app.route("/servers")
@login_required
def servers():
    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(current_username())})


@app.route("/add", methods=["POST"])
@login_required
def add_server():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    runtime = (data.get("runtime") or "python").strip()
    folder = sanitize_folder_name(name)
    if not folder:
        return jsonify({"success": False, "message": "Invalid server name"}), 400

    owner = current_username()
    ensure_user_dirs(owner)

    if not is_admin_session():
        limit = get_user_limit(owner)
        user_root = get_user_servers_root(owner)
        existing_count = 0
        if os.path.isdir(user_root):
            existing_count = len([d for d in os.listdir(user_root) if os.path.isdir(os.path.join(user_root, d))])
        if existing_count >= limit:
            return jsonify({"success": False, "message": f"Server limit reached ({limit})"}), 403

    target = get_server_dir(owner, folder)
    if os.path.exists(target):
        return jsonify({"success": False, "message": "Server already exists"}), 409

    os.makedirs(target, exist_ok=True)
    open(os.path.join(target, "server.log"), "w", encoding="utf-8").close()

    meta = {
        "display_name": name or folder,
        "startup_file": "",
        "owner": owner,
        "banned": False,
        "runtime": runtime,
        "auto_restart": True,
        "env": {}
    }
    write_meta(owner, folder, meta)

    key = folder if not is_admin_session() else f"{owner}::{folder}"
    set_state(key, "Offline")

    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(owner)})


@app.route("/server/stats/<path:key>")
@login_required
def server_stats(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"status": "Offline", "cpu": "0%", "mem": "0 MB", "logs": "", "ip": get_ip()}), 404

    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")

    proc_tuple = running_procs.get(key)
    running = False
    cpu, mem = "0%", "0 MB"

    if proc_tuple:
        proc, _logf = proc_tuple
        if psutil.pid_exists(proc.pid):
            try:
                p = psutil.Process(proc.pid)
                if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                    running = True
                    cpu = f"{p.cpu_percent(interval=None)}%"
                    mem = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
            except Exception:
                pass

    log_path = os.path.join(server_dir, "server.log")
    try:
        # ✅ نقرأ آخر 300 سطر فقط لتخفيف الضغط
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                all_lines = f.readlines()
            logs = "".join(all_lines[-300:])
        else:
            logs = ""
    except Exception:
        logs = ""

    state = get_state(key)
    if meta.get("banned", False):
        state = "Banned"
    elif running:
        state = "Running"
        set_state(key, "Running")
    elif state not in ("Installing", "Starting"):
        state = "Offline"
        set_state(key, "Offline")

    return jsonify({
        "status": state,
        "cpu": cpu,
        "mem": mem,
        "logs": logs,
        "ip": get_ip(),
        "runtime": meta.get("runtime", "python")
    })


def background_start(key: str, owner: str, folder: str, startup_file: str, runtime: str, env: dict):
    try:
        set_state(key, "Installing")
        log_append(key, "[SYSTEM] Preparing...\n")

        ensure_requirements_installed(owner, folder, runtime)

        set_state(key, "Starting")
        log_append(key, "[SYSTEM] Starting...\n")

        proc, logf = start_with_autoinstall(owner, folder, startup_file, runtime, env)
        running_procs[key] = (proc, logf)

        time.sleep(1.0)
        if proc.poll() is None:
            set_state(key, "Running")
        else:
            set_state(key, "Offline")
    except Exception as e:
        log_append(key, f"[SYSTEM] Start failed: {e}\n")
        set_state(key, "Offline")


@app.route("/server/action/<path:key>/<act>", methods=["POST"])
@login_required
def server_action(key, act):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")
        return jsonify({"success": False, "message": "Server banned"}), 403

    if act in ("stop", "restart"):
        stop_proc(key)
        set_state(key, "Offline")

    if act == "stop":
        return jsonify({"success": True})

    startup = meta.get("startup_file") or ""
    if not startup:
        return jsonify({"success": False, "message": "No main file set"}), 400

    open(os.path.join(server_dir, "server.log"), "w", encoding="utf-8").close()

    runtime = meta.get("runtime", "python")
    env = meta.get("env", {}) or {}

    t = threading.Thread(target=background_start, args=(key, owner, folder, startup, runtime, env), daemon=True)
    t.start()
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════
# Terminal Command Execution
# ═══════════════════════════════════════════════════════════

@app.route("/server/exec/<path:key>", methods=["POST"])
@login_required
def server_exec(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    data = request.get_json(silent=True) or {}
    cmd = (data.get("cmd") or "").strip()
    if not cmd:
        return jsonify({"success": False, "message": "Empty command"}), 400

    allowed_prefixes = (
        "pip install ", "pip3 install ",
        "npm install ", "npm i ", "npm run ",
        "python ", "python3 ",
        "node ",
        "ls", "pwd", "cat ", "echo ",
        "unzip ", "zip ", "tar ",
        "whoami", "date",
    )

    if not any(cmd.startswith(p) for p in allowed_prefixes):
        return jsonify({
            "success": False,
            "message": f"Command not allowed. Allowed prefixes: {', '.join(allowed_prefixes)}"
        }), 403

    try:
        result = subprocess.run(
            cmd, shell=True, cwd=server_dir,
            capture_output=True, text=True, timeout=90
        )
        return jsonify({
            "success": True,
            "stdout": result.stdout[:8000],
            "stderr": result.stderr[:3000],
            "returncode": result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "Command timeout (90s)"}), 408
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ═══════════════════════════════════════════════════════════
# Environment Variables
# ═══════════════════════════════════════════════════════════

@app.route("/server/env/<path:key>", methods=["GET", "POST"])
@login_required
def server_env(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    meta = read_meta(owner, folder)

    if request.method == "GET":
        return jsonify({"success": True, "env": meta.get("env", {})})

    data = request.get_json(silent=True) or {}
    env = data.get("env") or {}
    if not isinstance(env, dict):
        return jsonify({"success": False, "message": "Invalid env format"}), 400

    safe_env = {}
    for k, v in env.items():
        k = str(k).strip()
        if not re.fullmatch(r'[A-Z_][A-Z0-9_]*', k, re.IGNORECASE):
            continue
        safe_env[k] = str(v)[:1000]

    meta["env"] = safe_env
    write_meta(owner, folder, meta)
    return jsonify({"success": True, "env": safe_env})


# ═══════════════════════════════════════════════════════════
# Runtime Changer
# ═══════════════════════════════════════════════════════════

@app.route("/server/runtime/<path:key>", methods=["POST"])
@login_required
def server_runtime(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    runtime = (data.get("runtime") or "python").strip()
    if runtime not in ("python", "node", "shell"):
        return jsonify({"success": False, "message": "Invalid runtime"}), 400

    owner, folder = parse_server_key(key, allow_admin=True)
    meta = read_meta(owner, folder)
    meta["runtime"] = runtime
    write_meta(owner, folder, meta)
    return jsonify({"success": True, "runtime": runtime})


@app.route("/server/set-startup/<path:key>", methods=["POST"])
@login_required
def set_startup(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    data = request.get_json(silent=True) or {}
    f = (data.get("file") or "").strip()
    meta = read_meta(owner, folder)
    meta["startup_file"] = f
    write_meta(owner, folder, meta)
    return jsonify({"success": True})


# ═══════════════════════════════════════════════════════════
# Files
# ═══════════════════════════════════════════════════════════

@app.route("/files/list/<path:key>")
@login_required
def files_list(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden", "path": ""}), 403

    rel = request.args.get("path", "") or ""
    try:
        base = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path", "path": ""}), 400

    dirs, files = [], []
    if os.path.isdir(base):
        for name in sorted(os.listdir(base), key=lambda x: (not os.path.isdir(os.path.join(base, x)), x.lower())):
            if rel == "" and name in ("meta.json", "server.log"):
                continue
            full = os.path.join(base, name)
            if os.path.isdir(full):
                dirs.append({"name": name})
            elif os.path.isfile(full):
                try:
                    size_kb = os.path.getsize(full) / 1024
                    size = f"{size_kb:.1f} KB"
                except Exception:
                    size = ""
                files.append({"name": name, "size": size})

    return jsonify({"success": True, "path": rel, "dirs": dirs, "files": files})


@app.route("/files/content/<path:key>")
@login_required
def file_content(key):
    if not can_access_key(key):
        return jsonify({"content": ""}), 403
    file_rel = request.args.get("file", "") or ""
    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"content": ""}), 400
    if os.path.isdir(full):
        return jsonify({"content": ""}), 400
    try:
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": ""})


@app.route("/files/save/<path:key>", methods=["POST"])
@login_required
def file_save(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    file_rel = data.get("file", "") or ""
    content = data.get("content", "")

    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400

    os.makedirs(os.path.dirname(full), exist_ok=True)
    try:
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/mkdir/<path:key>", methods=["POST"])
@login_required
def file_mkdir(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        os.makedirs(target, exist_ok=False)
        return jsonify({"success": True})
    except FileExistsError:
        return jsonify({"success": False, "message": "Already exists"}), 409
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/rename/<path:key>", methods=["POST"])
@login_required
def file_rename(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    old = safe_name(data.get("old", ""))
    new = safe_name(data.get("new", ""))
    if not old or not new:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        src = safe_join_server_path(key, os.path.join(rel, old))
        dst = safe_join_server_path(key, os.path.join(rel, new))
        os.rename(src, dst)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/delete/<path:key>", methods=["POST"])
@login_required
def file_delete(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    kind = (data.get("kind") or "file").lower()
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        if kind == "dir":
            shutil.rmtree(target)
        else:
            os.remove(target)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/upload/<path:key>", methods=["POST"])
@login_required
def file_upload(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    rel = request.args.get("path", "") or ""
    try:
        base_dir = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400
    os.makedirs(base_dir, exist_ok=True)

    files = request.files.getlist("files") or []
    if not files:
        one = request.files.get("file")
        if one:
            files = [one]
    if not files:
        return jsonify({"success": False, "message": "No file"}), 400

    relpaths = request.form.getlist("relpaths")
    saved = 0

    for i, f in enumerate(files):
        if not f or not f.filename:
            continue
        filename = os.path.basename(f.filename)
        rp = ""
        if relpaths and i < len(relpaths):
            rp = (relpaths[i] or "").replace("\\", "/").lstrip("/")
        try:
            if rp:
                target_dir = safe_join_server_path(key, os.path.join(rel, os.path.dirname(rp)))
            else:
                target_dir = base_dir
        except Exception:
            continue
        os.makedirs(target_dir, exist_ok=True)
        f.save(os.path.join(target_dir, filename))
        saved += 1

    return jsonify({"success": True, "saved": saved})


@app.route("/files/extract/<path:key>", methods=["POST"])
@login_required
def file_extract(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    if not name or not name.lower().endswith(".zip"):
        return jsonify({"success": False, "message": "Not a zip file"}), 400
    try:
        zip_path = safe_join_server_path(key, os.path.join(rel, name))
        dest_dir = safe_join_server_path(key, rel) if rel else safe_join_server_path(key, "")
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400
    if not os.path.isfile(zip_path):
        return jsonify({"success": False, "message": "Zip not found"}), 404
    try:
        extracted = 0
        dest_real = os.path.realpath(dest_dir)
        with zipfile.ZipFile(zip_path, "r") as z:
            for member in z.namelist():
                target = os.path.realpath(os.path.join(dest_dir, member))
                if not target.startswith(dest_real + os.sep) and target != dest_real:
                    continue
                z.extract(member, dest_dir)
                extracted += 1
        return jsonify({"success": True, "extracted": extracted})
    except zipfile.BadZipFile:
        return jsonify({"success": False, "message": "Corrupt zip"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/server/delete/<path:key>", methods=["POST"])
@login_required
def server_delete(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return jsonify({"success": False, "message": "Invalid key"}), 400
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404
    try:
        stop_proc(key)
        shutil.rmtree(server_dir)
        with lock:
            server_states.pop(key, None)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/server/download/<path:key>")
@login_required
def server_download(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return jsonify({"success": False, "message": "Invalid key"}), 400
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(server_dir):
            for fn in files:
                if fn in ("server.log", ".installed"):
                    continue
                full = os.path.join(root, fn)
                z.write(full, os.path.relpath(full, server_dir))
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{folder}.zip")


# ═══════════════════════════════════════════════════════════
# User Profile
# ═══════════════════════════════════════════════════════════

@app.route("/api/user/profile")
@login_required
def user_profile():
    username = current_username()
    if is_admin_session():
        return jsonify({"success": True, "username": username, "email": "Owner Account", "premium": True, "is_admin": True})
    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404
    return jsonify({"success": True, "username": u.get("username"), "email": u.get("email", ""), "premium": bool(u.get("premium", False)), "is_admin": False})


@app.route("/api/user/change-password", methods=["POST"])
@login_required
def user_change_password():
    global ADMIN_PASSWORD
    data = request.get_json(silent=True) or {}
    old_pw = data.get("old_password") or ""
    new_pw = data.get("new_password") or ""
    if len(new_pw) < 6:
        return jsonify({"success": False, "message": "Password too short"}), 400
    username = current_username()
    if is_admin_session():
        if old_pw != ADMIN_PASSWORD:
            return jsonify({"success": False, "message": "Wrong password"}), 403
        ADMIN_PASSWORD = new_pw
        return jsonify({"success": True, "message": "Password changed"})
    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404
    if not check_password_hash(u.get("password_hash", ""), old_pw):
        return jsonify({"success": False, "message": "Wrong password"}), 403
    u["password_hash"] = generate_password_hash(new_pw)
    save_users(db)
    return jsonify({"success": True, "message": "Password changed"})


# ═══════════════════════════════════════════════════════════
# Admin
# ═══════════════════════════════════════════════════════════

@app.route("/api/admin/servers")
@admin_required
def admin_servers():
    return jsonify({"success": True, "servers": list_all_servers_for_admin()})


@app.route("/api/admin/server/ban", methods=["POST"])
@admin_required
def admin_server_ban():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    banned = bool(data.get("banned", True))

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Not found"}), 404

    meta = read_meta(owner, folder)
    meta["banned"] = banned
    write_meta(owner, folder, meta)

    if banned:
        stop_proc(key)
        set_state(key, "Banned")
    else:
        set_state(key, "Offline")
    return jsonify({"success": True})


@app.route("/api/admin/users")
@admin_required
def admin_users():
    db = load_users()
    counts = {}
    if os.path.isdir(USERS_ROOT):
        for owner in os.listdir(USERS_ROOT):
            root = get_user_servers_root(owner)
            if os.path.isdir(root):
                counts[owner] = len([d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))])

    users = []
    for u in db.get("users", []):
        users.append({
            "username": u.get("username"),
            "email": u.get("email"),
            "active": bool(u.get("active", True)),
            "premium": bool(u.get("premium", False)),
            "servers": counts.get(u.get("username") or "", 0),
        })
    return jsonify({"success": True, "users": users})


@app.route("/api/admin/user/update", methods=["POST"])
@admin_required
def admin_user_update():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400
    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "Not found"}), 404
    if "active" in data:
        u["active"] = bool(data["active"])
    if "premium" in data:
        u["premium"] = bool(data["premium"])
    save_users(db)
    return jsonify({"success": True})


@app.route("/api/admin/user/delete", methods=["POST"])
@admin_required
def admin_user_delete():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400
    db = load_users()
    if not find_user(db, username):
        return jsonify({"success": False, "message": "Not found"}), 404
    db["users"] = [x for x in db.get("users", []) if (x.get("username") or "").strip().lower() != username.lower()]
    save_users(db)
    for k in list(running_procs.keys()):
        if k.startswith(username + "::"):
            stop_proc(k)
            set_state(k, "Offline")
    return jsonify({"success": True})


@app.route("/api/admin/quickstats")
@admin_required
def admin_quickstats():
    total_servers = 0
    running = 0
    installing = 0
    banned = 0

    for s in list_all_servers_for_admin():
        total_servers += 1
        if s.get("status") == "Banned":
            banned += 1
        elif s.get("status") == "Running":
            running += 1
        elif s.get("status") in ("Installing", "Starting"):
            installing += 1

    db = load_users()
    total_users = len(db.get("users", []))
    active_users = sum(1 for u in db.get("users", []) if u.get("active", True))
    premium_users = sum(1 for u in db.get("users", []) if u.get("premium", False))

    try:
        host_cpu = psutil.cpu_percent(interval=None)
        host_ram = psutil.virtual_memory().percent
    except Exception:
        host_cpu, host_ram = 0, 0

    return jsonify({"success": True, "stats": {
        "servers_total": total_servers,
        "servers_running": running,
        "servers_installing": installing,
        "servers_banned": banned,
        "users_total": total_users,
        "users_active": active_users,
        "users_premium": premium_users,
        "host_cpu": host_cpu,
        "host_ram": host_ram
    }})


@app.route("/api/admin/signup-toggle", methods=["GET", "POST"])
@admin_required
def admin_signup_toggle():
    if request.method == "GET":
        return jsonify({"success": True, "signup_enabled": bool(load_settings().get("signup_enabled", True))})
    data = request.get_json(silent=True) or {}
    s = load_settings()
    s["signup_enabled"] = bool(data.get("enabled", True))
    save_settings(s)
    return jsonify({"success": True, "signup_enabled": s["signup_enabled"]})


@app.route("/api/admin/maintenance", methods=["GET", "POST"])
@admin_required
def admin_maintenance():
    if request.method == "GET":
        return jsonify({"success": True, "maintenance_mode": bool(load_settings().get("maintenance_mode", False))})
    data = request.get_json(silent=True) or {}
    s = load_settings()
    s["maintenance_mode"] = bool(data.get("enabled", False))
    save_settings(s)
    return jsonify({"success": True, "maintenance_mode": s["maintenance_mode"]})


@app.route("/api/admin/announcement", methods=["POST"])
@admin_required
def admin_announcement():
    data = request.get_json(silent=True) or {}
    s = load_settings()
    s["announcement"] = (data.get("text") or "").strip()[:500]
    save_settings(s)
    return jsonify({"success": True, "announcement": s["announcement"]})


@app.route("/api/admin/premium-all", methods=["POST"])
@admin_required
def admin_premium_all():
    data = request.get_json(silent=True) or {}
    premium = bool(data.get("premium", True))
    db = load_users()
    updated = 0
    for u in db.get("users", []):
        if bool(u.get("premium", False)) != premium:
            u["premium"] = premium
            updated += 1
    save_users(db)
    return jsonify({"success": True, "premium": premium, "updated": updated, "total": len(db.get("users", []))})


@app.route("/api/admin/stop-all", methods=["POST"])
@admin_required
def admin_stop_all():
    keys = list(running_procs.keys())
    for k in keys:
        stop_proc(k)
        set_state(k, "Offline")
    return jsonify({"success": True, "stopped": len(keys)})


@app.route("/api/admin/security")
@admin_required
def admin_security():
    now = time.time()
    banned = [{"ip": ip, "remaining": int(until - now)} for ip, until in _banned_ips.items() if until > now]
    return jsonify({"success": True,
                    "blocked_requests": _sec_stats["blocked"],
                    "ips_banned_total": _sec_stats["banned"],
                    "banned_ips": banned,
                    "rate_limit_per_min": RATE_LIMIT_PER_MIN,
                    "tracked_ips": len(_rate_buckets)})


@app.route("/api/admin/ip/unban", methods=["POST"])
@admin_required
def admin_ip_unban():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    _banned_ips.pop(ip, None)
    _rate_buckets.pop(ip, None)
    _login_fails.pop(ip, None)
    return jsonify({"success": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", os.environ.get("SERVER_PORT", 8008)))
    app.run(host="0.0.0.0", port=port, threaded=True)