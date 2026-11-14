"""
Bevins regression battery - shared harness.

Design contract (read this before changing anything):

  * The app under test is loaded from BEVINS_APP_PATH (default /opt/bevins/app.py).
    The guard engine sets that variable to a STAGED candidate file, so this battery
    must never assume it is testing the live file.
  * The candidate app.py is COPIED into a throwaway test-bed directory. app.py uses
    BASE = dirname(abspath(__file__)) to find fernet.key, index.html, sso.json,
    llm-matrix.json and the audit dir, so the copy resolves all of those inside the
    test bed and never reads or writes anything under /opt/bevins.
  * The database is a throwaway Postgres database created inside the live
    bevins-postgres container and dropped afterwards. It is owned by a dedicated
    NOSUPERUSER NOBYPASSRLS role so that ROW LEVEL SECURITY FORCE is actually
    enforced against it, exactly as it is against the live app role.
  * The live `bevins` database is never opened by this battery. Every database
    name is asserted against LIVE_DB before use.
  * All outbound network is blocked at the requests layer AND at the socket /
    DNS layer. Any attempt raises OutboundBlocked and is recorded, so a test can
    assert that a route did not phone home.
"""
from __future__ import annotations

import importlib.util
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import types
from urllib.parse import quote

import pytest

# ---------------------------------------------------------------- constants

LIVE_DB = "bevins"                       # never, ever touched by this battery
TEST_ROLE = "bevins_test"
PG_CONTAINER = os.environ.get("BEVINS_PG_CONTAINER", "bevins-postgres")
PG_HOST = os.environ.get("BEVINS_PG_HOST", "127.0.0.1")
PG_PORT = os.environ.get("BEVINS_PG_PORT", "5435")
_APP_PATH_ENV = os.environ.get("BEVINS_APP_PATH")
if not _APP_PATH_ENV:
    if os.environ.get("BEVINS_ALLOW_LIVE_APP_PATH") == "1":
        _APP_PATH_ENV = "/opt/bevins/app.py"
    else:
        raise RuntimeError(
            "BEVINS_APP_PATH is not set. The battery refuses to run rather than "
            "silently test the live /opt/bevins/app.py and hand back a green that "
            "says nothing about the candidate under review. "
            "Set BEVINS_APP_PATH=<candidate app.py>, or set "
            "BEVINS_ALLOW_LIVE_APP_PATH=1 to deliberately test the live file."
        )
APP_PATH = os.path.abspath(_APP_PATH_ENV)

BOOTSTRAP = "battery-bootstrap-" + secrets.token_urlsafe(16)
SCAN_SECRET = "battery-scan-" + secrets.token_urlsafe(16)

ADMIN = ("battery-admin@example.test", "Adm1n-battery-passphrase")
ALICE = ("battery-alice@example.test", "Al1ce-battery-passphrase")
BOB = ("battery-bob@example.test", "B0b-battery-passphrase")

OWNER_TABLES = ("byok_keys", "conversations", "messages", "bandit_stats", "health_records")

# every route the app exposes, and whether it sits behind @require_auth
PROTECTED_ROUTES = [
    ("POST", "/api/logout"),
    ("POST", "/api/logout-all"),
    ("GET", "/api/me"),
    ("POST", "/api/invite"),
    ("GET", "/api/activity"),
    ("GET", "/api/keys"),
    ("POST", "/api/keys"),
    ("GET", "/api/models"),
    ("POST", "/api/chat"),
    ("POST", "/api/research"),
    ("POST", "/api/delete-all"),
    ("GET", "/api/conversations"),
    ("POST", "/api/bandit"),
]
PUBLIC_ROUTES = [
    ("POST", "/api/signup"),
    ("POST", "/api/login"),
    ("POST", "/api/scan-email"),
    ("GET", "/auth/<prov>/start"),
    ("GET", "/auth/<prov>/callback"),
    ("POST", "/auth/<prov>/callback"),
    ("GET", "/"),
    ("GET", "/sw.js"),
]

# ------------------------------------------------------- outbound net guard


class OutboundBlocked(RuntimeError):
    """Raised whenever anything in the app tries to leave this box."""


NET_ATTEMPTS = []           # list of (thread_name, target)
_LOCAL = {"127.0.0.1", "::1", "localhost", "0.0.0.0", "", None}


def _block(target):
    NET_ATTEMPTS.append((threading.current_thread().name, str(target)))
    raise OutboundBlocked("outbound network blocked by the test battery: %s" % (target,))


def main_thread_net_attempts():
    """Attempts made on the request thread only.

    The app starts a daemon threat-feed refresher at import time; its (correctly
    blocked) attempts must not pollute per-request assertions.
    """
    me = threading.current_thread().name
    return [t for (th, t) in NET_ATTEMPTS if th == me]


def _install_network_block():
    import requests

    def blocked(*a, **k):
        _block(a[0] if a else k.get("url", "?"))

    for name in ("get", "post", "put", "patch", "delete", "head", "options", "request"):
        setattr(requests, name, blocked)
    requests.api.request = blocked
    requests.sessions.Session.request = blocked
    requests.Session.request = blocked

    real_connect = socket.socket.connect

    def guarded_connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            host = address[0] if isinstance(address, (tuple, list)) and address else address
            if isinstance(host, str) and host not in _LOCAL:
                _block("socket:%s" % (address,))
        return real_connect(self, address)

    socket.socket.connect = guarded_connect

    real_gai = socket.getaddrinfo

    def guarded_gai(host, *a, **k):
        if isinstance(host, str) and host not in _LOCAL:
            _block("dns:%s" % host)
        return real_gai(host, *a, **k)

    socket.getaddrinfo = guarded_gai


_install_network_block()

# ------------------------------------------------------------ postgres glue


def _run(cmd, stdin_text=None, check=True):
    p = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError("command failed: %s\nstdout: %s\nstderr: %s" % (cmd, p.stdout, p.stderr))
    return p.stdout.strip()


_DOCKER = []


def _docker():
    if not _DOCKER:
        p = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True)
        _DOCKER.extend(["docker"] if p.returncode == 0 else ["sudo", "-n", "docker"])
    return list(_DOCKER)


def psql_admin(sql, db="postgres"):
    """Superuser psql inside the container over the trusted local socket.

    Used ONLY for creating and dropping the throwaway database and for reading
    raw rows back out. Never points at LIVE_DB.
    """
    assert db != LIVE_DB, "the battery must never open the live bevins database"
    cmd = _docker() + ["exec", "-i", PG_CONTAINER, "psql", "-U", "postgres",
                       "-d", db, "-v", "ON_ERROR_STOP=1", "-At", "-f", "-"]
    return _run(cmd, stdin_text=sql)


def _lit(s):
    return "'" + str(s).replace("'", "''") + "'"


def sweep_orphan_test_databases():
    """Drop bevins_test_* databases stranded by a crashed run.

    Only touches names matching bevins_test_<pid>_<tag>. A database whose pid is
    still a live process belongs to a concurrent run and is left alone. LIVE_DB
    can never match the prefix, and is guarded explicitly anyway.
    """
    try:
        out = psql_admin(
            "SELECT datname FROM pg_database WHERE datname LIKE 'bevins_test\\_%';")
    except Exception:
        return []
    dropped = []
    for name in [ln.strip() for ln in out.splitlines() if ln.strip()]:
        if name == LIVE_DB or not name.startswith("bevins_test_"):
            continue
        parts = name.split("_")
        pid = parts[2] if len(parts) > 2 else ""
        if pid.isdigit() and os.path.exists("/proc/%s" % pid):
            continue
        try:
            psql_admin("DROP DATABASE IF EXISTS %s WITH (FORCE);" % name)
            dropped.append(name)
        except Exception:
            pass
    return dropped


def _new_database(password, tag):
    dbname = "bevins_test_%d_%s" % (os.getpid(), tag)
    assert dbname != LIVE_DB and dbname.startswith("bevins_test_")
    psql_admin("DROP DATABASE IF EXISTS %s WITH (FORCE);" % dbname)
    psql_admin("CREATE DATABASE %s OWNER %s;" % (dbname, TEST_ROLE))
    url = "postgresql://%s:%s@%s:%s/%s" % (TEST_ROLE, quote(password, safe=""), PG_HOST, PG_PORT, dbname)
    return dbname, url


# ---------------------------------------------------------------- test bed


def build_bed(directory, dburl, modname):
    """Copy the candidate app.py into an isolated dir and import it as a module."""
    os.makedirs(directory, exist_ok=True)
    shutil.copy2(APP_PATH, os.path.join(directory, "app.py"))
    with open(os.path.join(directory, "index.html"), "w") as f:
        f.write("<!doctype html><meta charset=utf-8><title>Bevins test bed</title><h1>bevins test bed</h1>")
    from cryptography.fernet import Fernet
    keyfile = os.path.join(directory, "fernet.key")
    with open(keyfile, "wb") as f:
        f.write(Fernet.generate_key())
    os.chmod(keyfile, 0o600)
    creds = os.path.join(directory, "creds")
    os.makedirs(creds, exist_ok=True)

    os.environ.update({
        "DATABASE_URL": dburl,
        "CREDENTIALS_DIRECTORY": creds,     # empty dir, so _cred() finds nothing and env wins
        "ADMIN_BOOTSTRAP_TOKEN": BOOTSTRAP,
        "TAVILY_API_KEY": "",
        "VT_API_KEY": "",
        "SAFEBROWSING_API_KEY": "",
        "SCAN_SECRET": SCAN_SECRET,
        "SERVER_LLM_KEY": "fw-testbed-not-a-real-key",
        "SERVER_OR_KEY": "",
        "FUNDED_USERS": "",                 # nobody is funded, so no server key is ever spent
        "BEVINS_AUDIT_DIR": os.path.join(directory, "audit"),
        "PORT": "0",
    })

    spec = importlib.util.spec_from_file_location(modname, os.path.join(directory, "app.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)            # init_db() runs here against the throwaway db
    return mod


@pytest.fixture(scope="session")
def role_password():
    assert psql_admin("SELECT 1;") == "1", "bevins-postgres is not reachable"
    pw = secrets.token_urlsafe(24)
    psql_admin(
        "DO $do$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=%s) "
        "THEN CREATE ROLE %s LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $do$;"
        % (_lit(TEST_ROLE), TEST_ROLE)
    )
    psql_admin("ALTER ROLE %s WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD %s;"
               % (TEST_ROLE, _lit(pw)))
    return pw


def _bed(directory, password, tag, modname):
    dbname, url = _new_database(password, tag)
    try:
        mod = build_bed(directory, url, modname)
    except BaseException:
        # A candidate that fails to import must not leave an orphan database
        # behind in the live container. Drop before re-raising.
        try:
            psql_admin("DROP DATABASE IF EXISTS %s WITH (FORCE);" % dbname)
        except Exception:
            pass
        raise
    return types.SimpleNamespace(mod=mod, dbname=dbname, url=url, dir=directory,
                                 bootstrap=BOOTSTRAP, scan_secret=SCAN_SECRET)


@pytest.fixture(scope="session", autouse=True)
def _orphan_db_sweep():
    """Runs once per session, before any bed, to clear stranded scratch DBs."""
    sweep_orphan_test_databases()
    yield


@pytest.fixture(scope="session")
def bed(tmp_path_factory, role_password):
    """Primary test bed: schema created, admin bootstrapped by the `users` fixture."""
    b = _bed(str(tmp_path_factory.mktemp("bevins_bed")), role_password, "main", "bevins_under_test")
    yield b
    psql_admin("DROP DATABASE IF EXISTS %s WITH (FORCE);" % b.dbname)


@pytest.fixture(scope="session")
def virgin_bed(tmp_path_factory, role_password):
    """A second, completely empty bed used to exercise the first-run admin path."""
    b = _bed(str(tmp_path_factory.mktemp("bevins_virgin")), role_password, "virgin", "bevins_virgin")
    yield b
    psql_admin("DROP DATABASE IF EXISTS %s WITH (FORCE);" % b.dbname)


@pytest.fixture
def client(bed):
    return bed.mod.app.test_client()


@pytest.fixture(autouse=True)
def _reset_between_tests(bed):
    """Clear in-process rate limiters and outbound-attempt log before each test."""
    bed.mod._RL.clear()
    bed.mod._RL_SWEEP[0] = 0
    NET_ATTEMPTS.clear()
    yield
    # wipe owner-scoped rows so tests cannot leak state into one another
    psql_admin("TRUNCATE %s RESTART IDENTITY;" % ", ".join(OWNER_TABLES), db=bed.dbname)


def auth(token):
    return {"Authorization": "Bearer " + token}


def db_query(bed, sql):
    return psql_admin(sql, db=bed.dbname)


def user_id(bed, email):
    return int(db_query(bed, "SELECT id FROM users WHERE email=%s;" % _lit(email)))


def login(client, email, password):
    r = client.post("/api/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()["token"]


@pytest.fixture(scope="session")
def users(bed):
    """Bootstrap one admin plus two ordinary invited users. Session-scoped."""
    c = bed.mod.app.test_client()
    r = c.post("/api/signup", json={"email": ADMIN[0], "password": ADMIN[1], "bootstrap": BOOTSTRAP})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()["role"] == "admin"
    admin_token = r.get_json()["token"]

    out = {"admin": {"email": ADMIN[0], "password": ADMIN[1]}}
    for label, (email, pw) in (("alice", ALICE), ("bob", BOB)):
        inv = c.post("/api/invite", json={"email": email}, headers=auth(admin_token))
        assert inv.status_code == 200, inv.get_data(as_text=True)
        code = inv.get_json()["code"]
        s = c.post("/api/signup", json={"email": email, "password": pw, "invite": code})
        assert s.status_code == 200, s.get_data(as_text=True)
        out[label] = {"email": email, "password": pw}
    for label in out:
        out[label]["id"] = user_id(bed, out[label]["email"])
    bed.mod._RL.clear()
    return out


@pytest.fixture
def rawdb(bed):
    """Direct connection AS THE APP ROLE, so RLS applies exactly as it does in the app."""
    import psycopg
    from psycopg.rows import dict_row
    conn = psycopg.connect(bed.url, autocommit=True, row_factory=dict_row)
    yield conn
    conn.close()


def set_owner(conn, uid):
    conn.execute("SELECT set_config('app.owner_id', %s, false)", (str(uid),))


def clear_owner(conn):
    conn.execute("SELECT set_config('app.owner_id', '', false)")
