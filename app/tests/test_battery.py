"""
Bevins LIVE-app regression battery.

Run against the live source:      pytest -q /opt/bevins/tests
Run against a staged candidate:   BEVINS_APP_PATH=/path/to/candidate/app.py pytest -q /opt/bevins/tests

This battery is the gate the guard pipeline runs before it is
allowed to ship a change. It is written to FAIL LOUDLY on any regression in
authentication, authorisation, tenant isolation (Postgres RLS) or secret
handling. If you weaken one of those in app.py, tests here must turn red.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import time
from urllib.parse import parse_qs, urlparse

import pytest

from conftest import (ADMIN, ALICE, APP_PATH, BOB, LIVE_DB, NET_ATTEMPTS, OWNER_TABLES,
                      PROTECTED_ROUTES, PUBLIC_ROUTES, OutboundBlocked, auth, clear_owner,
                      db_query, login, main_thread_net_attempts, set_owner, user_id, _lit)

# =====================================================================
# 1. Harness integrity and live-system safety
# =====================================================================


def test_app_under_test_is_loaded_from_bevins_app_path(bed):
    assert bed.mod.__file__ == os.path.join(bed.dir, "app.py")
    with open(APP_PATH, "rb") as a, open(bed.mod.__file__, "rb") as b:
        assert a.read() == b.read(), "test bed copy drifted from BEVINS_APP_PATH"


def test_base_relative_lookups_resolve_into_the_test_bed(bed):
    """fernet.key / index.html / audit must never resolve to /opt/bevins."""
    assert bed.mod.BASE == bed.dir
    assert bed.mod.KEYFILE.startswith(bed.dir)
    assert bed.mod.PWA.startswith(bed.dir)
    assert bed.mod.SSO_CONF.startswith(bed.dir)
    assert bed.mod.AUDIT_DIR.startswith(bed.dir)
    assert "/opt/bevins" not in bed.mod.BASE


def test_battery_never_targets_the_live_database(bed, virgin_bed):
    for b in (bed, virgin_bed):
        assert b.dbname.startswith("bevins_test_")
        assert b.dbname != LIVE_DB
        assert b.mod.DATABASE_URL.endswith("/" + b.dbname)
        assert not b.mod.DATABASE_URL.endswith("/" + LIVE_DB)


def test_app_db_role_is_not_superuser_and_cannot_bypass_rls(bed):
    """If the test role could bypass RLS, every isolation test below would be theatre."""
    row = db_query(bed, "SELECT rolsuper::int||'|'||rolbypassrls::int FROM pg_roles WHERE rolname='bevins_test';")
    assert row == "0|0", "test role must mirror the live app role: NOSUPERUSER NOBYPASSRLS"


def test_outbound_http_is_blocked_and_recorded():
    import requests
    with pytest.raises(OutboundBlocked):
        requests.get("https://api.tavily.com/search", timeout=1)
    with pytest.raises(OutboundBlocked):
        requests.post("https://openrouter.ai/api/v1/chat/completions", json={})
    assert len(main_thread_net_attempts()) == 2


def test_outbound_socket_and_dns_are_blocked():
    with pytest.raises(OutboundBlocked):
        socket.getaddrinfo("openrouter.ai", 443)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(OutboundBlocked):
            s.connect(("1.1.1.1", 443))
    finally:
        s.close()


def test_import_time_threat_feed_refresh_was_blocked(bed):
    """Blocked refreshes must remain unavailable in the per-source cache contract."""
    # Refresh explicitly: this checks the failure behavior rather than racing the
    # import-time daemon or relying on the removed aggregate-cache representation.
    bed.mod.refresh_threat_feeds()
    result = bed.mod.check_threat_feeds("https://bevins-regression-probe.invalid/")
    assert result["status"] == "unavailable", "failed feed refresh appeared available/current"
    assert result["hits"] == []
    assert result["stale_hits"] == []
    assert len(result["sources"]) == len(bed.mod._THREAT_FEEDS)
    assert all(s["fresh"] is False for s in result["sources"])
    assert all(s["last_refresh"] == "unavailable" for s in result["sources"])
    assert all(s["age_seconds"] is None for s in result["sources"])
    assert set(main_thread_net_attempts()) == {feed for feed, _ in bed.mod._THREAT_FEEDS}
    snapshots = bed.mod._THREAT["sources"]
    assert set(snapshots) == {feed for feed, _ in bed.mod._THREAT_FEEDS}
    for snapshot in snapshots.values():
        assert snapshot.get("ts") in (None, 0)
        assert not snapshot.get("domains", set())
        assert not snapshot.get("urls", set())
        assert snapshot["last_refresh"] == "unavailable"


# =====================================================================
# 2. Route surface
# =====================================================================


def test_route_surface_is_exactly_the_expected_twenty(bed):
    seen = set()
    for rule in bed.mod.app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        for m in rule.methods:
            if m in ("GET", "POST"):
                seen.add((m, str(rule)))
    expected = set(PROTECTED_ROUTES) | set(PUBLIC_ROUTES) | {("GET", "/image-origin/v1/<path:asset>")}
    assert seen == expected, "route surface changed: added=%s removed=%s" % (
        sorted(seen - expected), sorted(expected - seen))


# =====================================================================
# 3. Signup gating: admin bootstrap, invites
# =====================================================================


def test_admin_bootstrap_cannot_be_used_without_the_token(virgin_bed):
    """First account on an empty install requires the bootstrap token, full stop."""
    c = virgin_bed.mod.app.test_client()
    virgin_bed.mod._RL.clear()

    r = c.post("/api/signup", json={"email": "intruder@example.test", "password": "hunter2hunter2"})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert "bootstrap" in r.get_json()["error"].lower()

    r = c.post("/api/signup", json={"email": "intruder@example.test",
                                    "password": "hunter2hunter2", "bootstrap": "wrong-token"})
    assert r.status_code == 403

    assert db_query(virgin_bed, "SELECT count(*) FROM users;") == "0"

    r = c.post("/api/signup", json={"email": "founder@example.test",
                                    "password": "hunter2hunter2", "bootstrap": virgin_bed.bootstrap})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()["role"] == "admin"

    # second account no longer takes the bootstrap path; it needs an invite
    r = c.post("/api/signup", json={"email": "second@example.test",
                                    "password": "hunter2hunter2", "bootstrap": virgin_bed.bootstrap})
    assert r.status_code == 403
    assert "invite" in r.get_json()["error"].lower()


def test_only_one_admin_can_ever_exist(virgin_bed):
    idx = db_query(virgin_bed, "SELECT indexdef FROM pg_indexes WHERE indexname='users_one_admin';")
    assert "UNIQUE" in idx and "role" in idx and "admin" in idx


def test_signup_without_an_invite_is_refused(client, users):
    r = client.post("/api/signup", json={"email": "nobody@example.test", "password": "longenoughpw"})
    assert r.status_code == 403
    assert "invite" in r.get_json()["error"].lower()


def test_signup_with_wrong_invite_code_is_refused(client, users):
    admin = login(client, users["admin"]["email"], users["admin"]["password"])
    inv = client.post("/api/invite", json={"email": "carol@example.test"}, headers=auth(admin))
    assert inv.status_code == 200
    r = client.post("/api/signup", json={"email": "carol@example.test",
                                         "password": "longenoughpw", "invite": "not-the-code"})
    assert r.status_code == 403
    assert "invite code" in r.get_json()["error"].lower()


def test_signup_with_valid_invite_succeeds(client, users, bed):
    admin = login(client, users["admin"]["email"], users["admin"]["password"])
    email = "dave-%d@example.test" % int(time.time() * 1000 % 1000000)
    code = client.post("/api/invite", json={"email": email}, headers=auth(admin)).get_json()["code"]
    r = client.post("/api/signup", json={"email": email, "password": "longenoughpw", "invite": code})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()["role"] == "user"
    assert db_query(bed, "SELECT used FROM invites WHERE email=%s;" % _lit(email)) == "1"


def test_signup_rejects_short_password_and_bad_email(client, users):
    assert client.post("/api/signup", json={"email": "x@y.test", "password": "short"}).status_code == 400
    assert client.post("/api/signup", json={"email": "notanemail", "password": "longenoughpw"}).status_code == 400


def test_signup_duplicate_email_conflicts(client, users):
    r = client.post("/api/signup", json={"email": users["alice"]["email"], "password": "longenoughpw"})
    assert r.status_code == 409


def test_passwords_are_pbkdf2_hashed_not_stored_plaintext(bed, users):
    row = db_query(bed, "SELECT coalesce(salt,'')||'|'||coalesce(hash,'') FROM users WHERE email=%s;"
                   % _lit(users["alice"]["email"]))
    salt, h = row.split("|")
    assert salt and h
    assert users["alice"]["password"] not in row
    assert len(h) == 64                      # sha256-sized pbkdf2 output, hex
    assert bed.mod.PBKDF2_ITERS >= 100_000


# =====================================================================
# 4. Login and session lifecycle
# =====================================================================


def test_login_happy_path(client, users):
    r = client.post("/api/login", json={"email": users["alice"]["email"],
                                        "password": users["alice"]["password"]})
    assert r.status_code == 200
    assert r.get_json()["token"]
    assert r.get_json()["role"] == "user"


def test_login_wrong_password_is_401(client, users):
    r = client.post("/api/login", json={"email": users["alice"]["email"], "password": "wrong-password"})
    assert r.status_code == 401


def test_login_unknown_account_is_401(client, users):
    r = client.post("/api/login", json={"email": "ghost@example.test", "password": "whatever-long"})
    assert r.status_code == 401


@pytest.mark.parametrize("method,path", PROTECTED_ROUTES)
def test_protected_route_rejects_missing_token(client, users, method, path):
    r = client.open(path, method=method, json={})
    assert r.status_code in (401, 403), "%s %s allowed an unauthenticated caller" % (method, path)


@pytest.mark.parametrize("method,path", PROTECTED_ROUTES)
def test_protected_route_rejects_garbage_token(client, users, method, path):
    r = client.open(path, method=method, json={}, headers=auth("not-a-real-session-token"))
    assert r.status_code in (401, 403), "%s %s accepted a forged token" % (method, path)


def test_tampered_token_is_rejected(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    tampered = tok[:-1] + ("A" if tok[-1] != "A" else "B")
    assert client.get("/api/me", headers=auth(tampered)).status_code == 401
    assert client.get("/api/me", headers=auth(tok)).status_code == 200


def test_token_past_absolute_lifetime_is_rejected_and_purged(client, users, bed):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    th = hashlib.sha256(tok.encode()).hexdigest()
    old = int(time.time()) - bed.mod.TOKEN_ABSOLUTE - 60
    db_query(bed, "UPDATE sessions SET created=%d, seen=%d WHERE thash=%s;" % (old, int(time.time()), _lit(th)))
    assert client.get("/api/me", headers=auth(tok)).status_code == 401
    assert db_query(bed, "SELECT count(*) FROM sessions WHERE thash=%s;" % _lit(th)) == "0"


def test_idle_token_is_rejected(client, users, bed):
    tok = login(client, users["bob"]["email"], users["bob"]["password"])
    th = hashlib.sha256(tok.encode()).hexdigest()
    stale = int(time.time()) - bed.mod.TOKEN_IDLE - 60
    db_query(bed, "UPDATE sessions SET seen=%d WHERE thash=%s;" % (stale, _lit(th)))
    assert client.get("/api/me", headers=auth(tok)).status_code == 401


def test_logout_invalidates_that_session_only(client, users):
    a = login(client, users["alice"]["email"], users["alice"]["password"])
    b = login(client, users["alice"]["email"], users["alice"]["password"])
    assert client.post("/api/logout", headers=auth(a)).status_code == 200
    assert client.get("/api/me", headers=auth(a)).status_code == 401
    assert client.get("/api/me", headers=auth(b)).status_code == 200


def test_logout_all_invalidates_every_session_for_that_user(client, users):
    a = login(client, users["alice"]["email"], users["alice"]["password"])
    b = login(client, users["alice"]["email"], users["alice"]["password"])
    other = login(client, users["bob"]["email"], users["bob"]["password"])
    assert client.post("/api/logout-all", headers=auth(a)).status_code == 200
    assert client.get("/api/me", headers=auth(a)).status_code == 401
    assert client.get("/api/me", headers=auth(b)).status_code == 401
    assert client.get("/api/me", headers=auth(other)).status_code == 200


def test_me_returns_the_calling_identity(client, users):
    tok = login(client, users["bob"]["email"], users["bob"]["password"])
    r = client.get("/api/me", headers=auth(tok))
    assert r.status_code == 200
    assert r.get_json() == {"email": users["bob"]["email"], "role": "user"}


# =====================================================================
# 5. Privilege: admin-only routes
# =====================================================================


def test_invite_requires_admin_privilege(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    r = client.post("/api/invite", json={"email": "mallory@example.test"}, headers=auth(tok))
    assert r.status_code == 403
    assert r.get_json()["error"] == "admin only"


def test_invite_happy_path_for_admin(client, users, bed):
    tok = login(client, users["admin"]["email"], users["admin"]["password"])
    r = client.post("/api/invite", json={"email": "Erin@Example.Test"}, headers=auth(tok))
    assert r.status_code == 200
    assert r.get_json()["email"] == "erin@example.test"
    assert len(r.get_json()["code"]) >= 16


def test_invite_rejects_bad_email(client, users):
    tok = login(client, users["admin"]["email"], users["admin"]["password"])
    assert client.post("/api/invite", json={"email": "nope"}, headers=auth(tok)).status_code == 400


def test_activity_requires_admin_privilege(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    assert client.get("/api/activity", headers=auth(tok)).status_code == 403


def test_activity_happy_path_for_admin_never_leaks_secrets(client, users):
    tok = login(client, users["admin"]["email"], users["admin"]["password"])
    r = client.get("/api/activity", headers=auth(tok))
    assert r.status_code == 200
    accounts = r.get_json()["accounts"]
    assert any(a["email"] == users["alice"]["email"] for a in accounts)
    blob = json.dumps(accounts)
    assert "salt" not in blob and "hash" not in blob
    for pw in (ADMIN[1], ALICE[1], BOB[1]):
        assert pw not in blob


# =====================================================================
# 6. BYOK key handling
# =====================================================================

FAKE_KEY = "or-battery-plaintext-canary-0000"


def test_keys_roundtrip_returns_provider_names_only(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    r = client.post("/api/keys", json={"or": FAKE_KEY}, headers=auth(tok))
    assert r.status_code == 200
    assert r.get_json()["providers"] == ["or"]
    g = client.get("/api/keys", headers=auth(tok))
    assert g.status_code == 200
    assert g.get_json() == {"providers": ["or"]}


def test_stored_key_is_encrypted_at_rest(client, users, bed):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    client.post("/api/keys", json={"or": FAKE_KEY}, headers=auth(tok))
    enc = db_query(bed, "SELECT enc FROM byok_keys WHERE owner_id=%d AND provider='or';" % users["alice"]["id"])
    assert enc, "key row missing"
    assert FAKE_KEY not in enc
    assert enc.startswith("gAAAAA"), "expected a Fernet token, got %r" % enc[:16]
    assert bed.mod.fernet().decrypt(enc.encode()).decode() == FAKE_KEY


def test_get_keys_never_returns_plaintext_key_material(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    client.post("/api/keys", json={"or": FAKE_KEY, "fw": "fw-canary-plaintext-1111"}, headers=auth(tok))
    body = client.get("/api/keys", headers=auth(tok)).get_data(as_text=True)
    assert FAKE_KEY not in body and "fw-canary-plaintext-1111" not in body
    body2 = client.post("/api/keys", json={"or": FAKE_KEY}, headers=auth(tok)).get_data(as_text=True)
    assert FAKE_KEY not in body2


def test_empty_value_deletes_the_stored_key(client, users, bed):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    client.post("/api/keys", json={"or": FAKE_KEY}, headers=auth(tok))
    client.post("/api/keys", json={"or": ""}, headers=auth(tok))
    assert db_query(bed, "SELECT count(*) FROM byok_keys WHERE owner_id=%d;" % users["alice"]["id"]) == "0"


def test_one_user_cannot_see_another_users_keys(client, users):
    a = login(client, users["alice"]["email"], users["alice"]["password"])
    b = login(client, users["bob"]["email"], users["bob"]["password"])
    client.post("/api/keys", json={"or": FAKE_KEY}, headers=auth(a))
    assert client.get("/api/keys", headers=auth(b)).get_json() == {"providers": []}


# =====================================================================
# 7. Row Level Security: the database-level tenant isolation
# =====================================================================

INSERTS = {
    "byok_keys": "INSERT INTO byok_keys(owner_id,provider,enc) VALUES(%s,'or','ciphertext')",
    "conversations": "INSERT INTO conversations(owner_id,title,created) VALUES(%s,'t',1)",
    "messages": "INSERT INTO messages(owner_id,conversation_id,role,content,created) VALUES(%s,1,'user','secret',1)",
    "bandit_stats": "INSERT INTO bandit_stats(owner_id,job_class,model_id,alpha,beta) VALUES(%s,'assistant','m',1,1)",
    "health_records": "INSERT INTO health_records(owner_id,ts,title,payload) VALUES(%s,'2026-01-01','t','p')",
}
# second insert per table that cannot collide with the first on any primary key,
# so a failure below is provably an RLS refusal and not a duplicate-key accident
INSERTS2 = dict(INSERTS,
                byok_keys="INSERT INTO byok_keys(owner_id,provider,enc) VALUES(%s,'fw','ciphertext')",
                bandit_stats="INSERT INTO bandit_stats(owner_id,job_class,model_id,alpha,beta) "
                             "VALUES(%s,'assistant','m2',1,1)")


def test_rls_is_enabled_and_forced_on_every_owner_scoped_table(bed):
    rows = db_query(bed, "SELECT relname||'='||relrowsecurity::int||relforcerowsecurity::int FROM pg_class "
                         "WHERE relname IN (%s) ORDER BY relname;"
                         % ",".join(_lit(t) for t in OWNER_TABLES))
    got = dict(x.split("=") for x in rows.splitlines())
    assert set(got) == set(OWNER_TABLES)
    for t, flags in got.items():
        assert flags == "11", "%s must have ROW LEVEL SECURITY ENABLED and FORCED, got %r" % (t, flags)


@pytest.mark.parametrize("table", OWNER_TABLES)
def test_tenant_isolation_policy_exists_and_is_owner_scoped(bed, table):
    row = db_query(bed, "SELECT policyname||'|'||coalesce(qual,'')||'|'||coalesce(with_check,'') "
                        "FROM pg_policies WHERE tablename=%s;" % _lit(table))
    assert row, "no RLS policy on %s" % table
    name, qual, check = row.split("|", 2)
    assert name == "tenant_isolation"
    for clause in (qual, check):
        assert "owner_id" in clause and "app.owner_id" in clause, \
            "%s policy is not owner-scoped: %r" % (table, clause)
        assert clause.strip().lower() not in ("true", "(true)"), \
            "%s policy is wide open: %r" % (table, clause)


@pytest.mark.parametrize("table", OWNER_TABLES)
def test_unset_rls_context_fails_closed(rawdb, table, users):
    """No app.owner_id set means: read nothing, write nothing."""
    set_owner(rawdb, users["alice"]["id"])
    rawdb.execute(INSERTS[table] % "%s", (users["alice"]["id"],))

    clear_owner(rawdb)
    n = rawdb.execute("SELECT count(*) AS n FROM " + table).fetchone()["n"]
    assert n == 0, "%s leaked %d rows with no RLS context set" % (table, n)

    import psycopg
    with pytest.raises(psycopg.Error) as ei:
        rawdb.execute(INSERTS2[table] % "%s", (users["alice"]["id"],))
    assert "row-level security" in str(ei.value).lower(), \
        "%s insert with no RLS context failed for the wrong reason: %s" % (table, ei.value)


@pytest.mark.parametrize("table", OWNER_TABLES)
def test_user_b_cannot_read_user_a_rows(rawdb, table, users):
    set_owner(rawdb, users["alice"]["id"])
    rawdb.execute(INSERTS[table] % "%s", (users["alice"]["id"],))
    assert rawdb.execute("SELECT count(*) AS n FROM " + table).fetchone()["n"] == 1

    set_owner(rawdb, users["bob"]["id"])
    assert rawdb.execute("SELECT count(*) AS n FROM " + table).fetchone()["n"] == 0, \
        "%s: user B can read user A rows" % table


@pytest.mark.parametrize("table", OWNER_TABLES)
def test_user_b_cannot_delete_or_update_user_a_rows(rawdb, table, users):
    set_owner(rawdb, users["alice"]["id"])
    rawdb.execute(INSERTS[table] % "%s", (users["alice"]["id"],))

    set_owner(rawdb, users["bob"]["id"])
    assert rawdb.execute("DELETE FROM " + table).rowcount == 0, "%s: B deleted A rows" % table
    assert rawdb.execute("UPDATE %s SET owner_id=owner_id" % table).rowcount == 0, "%s: B updated A rows" % table

    set_owner(rawdb, users["alice"]["id"])
    assert rawdb.execute("SELECT count(*) AS n FROM " + table).fetchone()["n"] == 1, \
        "%s: A's row did not survive B's delete" % table


@pytest.mark.parametrize("table", OWNER_TABLES)
def test_a_cannot_forge_a_row_owned_by_b(rawdb, table, users):
    import psycopg
    set_owner(rawdb, users["alice"]["id"])
    with pytest.raises(psycopg.Error) as ei:
        rawdb.execute(INSERTS[table] % "%s", (users["bob"]["id"],))
    assert "row-level security" in str(ei.value).lower(), \
        "%s let user A write a row owned by user B: %s" % (table, ei.value)


# =====================================================================
# 8. Route-level tenant isolation
# =====================================================================


def test_conversations_are_scoped_to_the_caller(client, users, rawdb):
    set_owner(rawdb, users["alice"]["id"])
    rawdb.execute("INSERT INTO conversations(owner_id,title,created) VALUES(%s,'alice-private',1)",
                  (users["alice"]["id"],))
    a = login(client, users["alice"]["email"], users["alice"]["password"])
    b = login(client, users["bob"]["email"], users["bob"]["password"])

    mine = client.get("/api/conversations", headers=auth(a)).get_json()
    assert [c["title"] for c in mine] == ["alice-private"]

    theirs = client.get("/api/conversations", headers=auth(b))
    assert theirs.status_code == 200
    assert theirs.get_json() == []
    assert "alice-private" not in theirs.get_data(as_text=True)


def test_delete_all_only_destroys_the_callers_own_data(client, users, rawdb, bed):
    for uid in (users["alice"]["id"], users["bob"]["id"]):
        set_owner(rawdb, uid)
        for t in ("conversations", "messages", "bandit_stats", "health_records"):
            rawdb.execute(INSERTS[t] % "%s", (uid,))

    b = login(client, users["bob"]["email"], users["bob"]["password"])
    assert client.post("/api/delete-all", headers=auth(b)).status_code == 200

    for t in ("conversations", "messages", "bandit_stats", "health_records"):
        assert db_query(bed, "SELECT count(*) FROM %s WHERE owner_id=%d;" % (t, users["bob"]["id"])) == "0"
        assert db_query(bed, "SELECT count(*) FROM %s WHERE owner_id=%d;" % (t, users["alice"]["id"])) == "1", \
            "%s: delete-all crossed the tenant boundary" % t


def test_bandit_writes_are_scoped_to_the_caller(client, users, bed):
    a = login(client, users["alice"]["email"], users["alice"]["password"])
    b = login(client, users["bob"]["email"], users["bob"]["password"])
    assert client.post("/api/bandit", json={"job_class": "assistant", "model_id": "m1",
                                            "alpha": 3, "beta": 1}, headers=auth(a)).status_code == 200
    assert db_query(bed, "SELECT count(*) FROM bandit_stats WHERE owner_id=%d;" % users["alice"]["id"]) == "1"
    assert db_query(bed, "SELECT count(*) FROM bandit_stats WHERE owner_id=%d;" % users["bob"]["id"]) == "0"
    assert client.get("/api/models", headers=auth(b)).get_json()["bandit"] == []
    assert len(client.get("/api/models", headers=auth(a)).get_json()["bandit"]) == 1


def test_bandit_rejects_junk_payloads(client, users):
    a = login(client, users["alice"]["email"], users["alice"]["password"])
    for payload in ({}, {"job_class": "", "model_id": "m", "alpha": 1, "beta": 1},
                    {"job_class": "c", "model_id": "m", "alpha": "nan", "beta": 1},
                    {"job_class": "c", "model_id": "m", "alpha": float("inf"), "beta": 1}):
        r = client.post("/api/bandit", json=payload, headers=auth(a))
        assert r.status_code == 400, payload


# =====================================================================
# 9. LLM-facing routes: happy paths that must never leave the box
# =====================================================================


def test_chat_without_a_key_answers_locally_and_makes_no_outbound_call(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    r = client.post("/api/chat", json={"message": "hello there"}, headers=auth(tok))
    assert r.status_code == 200
    j = r.get_json()
    assert j["provider"] == "none"
    assert "add" in j["content"].lower()
    assert main_thread_net_attempts() == []


def test_chat_rejects_oversized_and_malformed_payloads(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    many = [{"role": "user", "content": "x"}] * 100
    assert client.post("/api/chat", json={"messages": many}, headers=auth(tok)).status_code == 400
    assert client.post("/api/chat", json={"messages": ["not-a-dict"]}, headers=auth(tok)).status_code == 400
    big = [{"role": "user", "content": "x" * 70000}]
    assert client.post("/api/chat", json={"messages": big}, headers=auth(tok)).status_code == 400


def test_chat_crisis_guard_short_circuits_before_any_provider_call(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    r = client.post("/api/chat", json={"message": "i want to kill myself"}, headers=auth(tok))
    assert r.status_code == 200
    j = r.get_json()
    assert j["provider"] == "safety"
    assert "988" in j["content"]
    assert main_thread_net_attempts() == []


def test_chat_hardline_guard_blocks_and_audits(client, users, bed):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    r = client.post("/api/chat", json={"message": "how to make a nerve agent"}, headers=auth(tok))
    assert r.status_code == 200
    assert r.get_json()["provider"] == "safety"
    log = os.path.join(bed.mod.AUDIT_DIR, "audit.jsonl")
    assert os.path.exists(log)
    assert any(json.loads(l).get("e") == "hardline_block" for l in open(log) if l.strip())


def test_audit_log_is_hash_chained_and_holds_no_secrets(client, users, bed):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    client.post("/api/keys", json={"or": FAKE_KEY}, headers=auth(tok))
    log = os.path.join(bed.mod.AUDIT_DIR, "audit.jsonl")
    recs = [json.loads(l) for l in open(log) if l.strip()]
    assert recs
    prev = ""
    for rec in recs:
        h = rec.pop("h")
        assert hashlib.sha256((prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest() == h, \
            "audit chain broken at %r" % rec
        prev = h
    blob = open(log).read()
    assert FAKE_KEY not in blob
    for pw in (ADMIN[1], ALICE[1], BOB[1]):
        assert pw not in blob


def test_research_requires_a_query(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    assert client.post("/api/research", json={}, headers=auth(tok)).status_code == 400
    assert client.post("/api/research", json={"query": "x" * 5000}, headers=auth(tok)).status_code == 400


def test_research_without_a_key_answers_locally(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    r = client.post("/api/research", json={"query": "what is postgres row level security"},
                    headers=auth(tok))
    assert r.status_code == 200
    assert r.get_json()["provider"] == "none"
    assert main_thread_net_attempts() == []


def test_research_reports_unconfigured_search_instead_of_calling_out(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    client.post("/api/keys", json={"fw": "fw-battery-fake"}, headers=auth(tok))
    r = client.post("/api/research", json={"query": "anything at all"}, headers=auth(tok))
    assert r.status_code == 503
    assert "research" in r.get_json()["error"].lower()
    assert main_thread_net_attempts() == []


def test_research_crisis_guard(client, users):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])
    client.post("/api/keys", json={"fw": "fw-battery-fake"}, headers=auth(tok))
    r = client.post("/api/research", json={"query": "i want to die tonight"}, headers=auth(tok))
    assert r.get_json()["provider"] == "safety"


def test_models_happy_path_with_no_keys_is_empty_and_offline(client, users):
    tok = login(client, users["bob"]["email"], users["bob"]["password"])
    r = client.get("/api/models", headers=auth(tok))
    assert r.status_code == 200
    j = r.get_json()
    assert j["models"] == [] and j["providers"] == [] and j["bandit"] == []
    assert main_thread_net_attempts() == []


def test_models_with_a_key_degrades_gracefully_when_the_provider_is_unreachable(client, users):
    tok = login(client, users["bob"]["email"], users["bob"]["password"])
    client.post("/api/keys", json={"fw": "fw-battery-fake"}, headers=auth(tok))
    r = client.get("/api/models", headers=auth(tok))
    assert r.status_code == 200
    assert r.get_json()["models"] == []


# =====================================================================
# 10. /api/scan-email: shared-secret endpoint, not a session route
# =====================================================================


def test_scan_email_is_503_when_not_configured(client, bed, monkeypatch):
    monkeypatch.setattr(bed.mod, "SCAN_SECRET", "")
    r = client.post("/api/scan-email", json={"secret": "x", "text": "hi"})
    assert r.status_code == 503


def test_scan_email_rejects_a_wrong_shared_secret(client, bed):
    r = client.post("/api/scan-email", json={"secret": "wrong-secret", "text": "click here"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "unauthorized"
    assert main_thread_net_attempts() == []


def test_scan_email_rejects_a_missing_secret(client, bed):
    assert client.post("/api/scan-email", json={"text": "click here"}).status_code == 403


def test_scan_email_with_the_right_secret_never_silently_succeeds_offline(client, bed):
    r = client.post("/api/scan-email", json={"secret": bed.scan_secret, "text": "you have won a prize"})
    # outbound is blocked, so the scam engine must fail loudly rather than return a bogus verdict
    assert r.status_code in (400, 502), r.get_data(as_text=True)


def test_scan_email_rejects_empty_text(client, bed):
    r = client.post("/api/scan-email", json={"secret": bed.scan_secret, "text": "   "})
    assert r.status_code == 400


# =====================================================================
# 11. SSO / OIDC
# =====================================================================

SSO_CONF_BODY = {
    "google": {
        "client_id": "battery-test-client-id",
        "client_secret": "battery-test-not-a-real-value",
        "redirect_uri": "https://localhost/auth/google/callback",
    }
}


@pytest.fixture
def sso_configured(bed):
    path = bed.mod.SSO_CONF
    with open(path, "w") as f:
        json.dump(SSO_CONF_BODY, f)
    yield
    os.unlink(path)


def test_sso_start_is_503_when_not_configured(client):
    assert client.get("/auth/google/start").status_code == 503


def test_sso_start_for_unknown_provider_is_503(client, sso_configured):
    assert client.get("/auth/pretendco/start").status_code == 503


def test_sso_start_redirects_and_pins_state_to_a_cookie(client, bed, sso_configured):
    r = client.get("/auth/google/start", base_url="https://localhost")
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert loc.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    q = parse_qs(urlparse(loc).query)
    state = q["state"][0]
    cookie = r.headers.get("Set-Cookie", "")
    assert "bv_state=" + state in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie
    assert db_query(bed, "SELECT count(*) FROM ssostate WHERE state=%s;" % _lit(state)) == "1"


def test_sso_callback_is_503_when_not_configured(client):
    r = client.get("/auth/google/callback?state=abc&code=def")
    assert r.status_code == 503


def test_sso_callback_rejects_missing_or_mismatched_state(client, sso_configured):
    r = client.get("/auth/google/callback?code=x", base_url="https://localhost")
    assert r.status_code == 302 and "sso_error=state" in r.headers["Location"]
    r = client.get("/auth/google/callback?state=forged&code=x", base_url="https://localhost")
    assert r.status_code == 302 and "sso_error=state" in r.headers["Location"]


class _FakeResp:
    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


class _FakeRequests:
    """Stands in for `requests` inside the app module for the token exchange only."""
    def __init__(self, payload):
        self._p = payload

    def post(self, *a, **k):
        return _FakeResp(self._p)

    def get(self, *a, **k):
        raise AssertionError("SSO callback must not make an outbound GET")


class _FakeJWT:
    def __init__(self, claims):
        self.claims = claims

    def decode(self, *a, **k):
        return self.claims


def _sso_roundtrip(client, bed, monkeypatch, email, verified=True, break_nonce=False):
    """Drive /auth/google/start then /auth/google/callback with the IdP fully stubbed."""
    r = client.get("/auth/google/start", base_url="https://localhost")
    state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
    nonce = db_query(bed, "SELECT nonce FROM ssostate WHERE state=%s;" % _lit(state))
    claims = {"email": email, "email_verified": verified,
              "nonce": "wrong-nonce" if break_nonce else nonce}
    monkeypatch.setattr(bed.mod, "requests", _FakeRequests({"id_token": "stub.id.token"}))
    monkeypatch.setattr(bed.mod, "jwt", _FakeJWT(claims))
    monkeypatch.setattr(bed.mod, "PyJWKClient",
                        lambda *a, **k: type("K", (), {"get_signing_key_from_jwt":
                                                       lambda s, t: type("S", (), {"key": "k"})()})())
    return client.get("/auth/google/callback?state=%s&code=abc" % state, base_url="https://localhost")


def test_sso_cannot_create_an_account_without_an_invite(client, bed, users, sso_configured, monkeypatch):
    r = _sso_roundtrip(client, bed, monkeypatch, "sso-uninvited@example.test")
    assert r.status_code == 302
    assert "sso_error=invite" in r.headers["Location"]
    assert db_query(bed, "SELECT count(*) FROM users WHERE email='sso-uninvited@example.test';") == "0"


def test_sso_rejects_an_unverified_email(client, bed, users, sso_configured, monkeypatch):
    r = _sso_roundtrip(client, bed, monkeypatch, "sso-unverified@example.test", verified=False)
    assert "sso_error=email" in r.headers["Location"]


def test_sso_rejects_a_replayed_or_mismatched_nonce(client, bed, users, sso_configured, monkeypatch):
    r = _sso_roundtrip(client, bed, monkeypatch, "sso-nonce@example.test", break_nonce=True)
    assert "sso_error=state" in r.headers["Location"]


def test_sso_cannot_take_over_a_password_account(client, bed, users, sso_configured, monkeypatch):
    """A password account has sso NULL, so no IdP may ever log in as it."""
    r = _sso_roundtrip(client, bed, monkeypatch, users["alice"]["email"])
    assert "sso_error=account" in r.headers["Location"]
    assert "sso_token" not in r.headers["Location"]


def test_sso_with_an_invite_provisions_a_plain_user_not_an_admin(client, bed, users, sso_configured, monkeypatch):
    email = "sso-invited@example.test"
    admin = login(client, users["admin"]["email"], users["admin"]["password"])
    client.post("/api/invite", json={"email": email}, headers=auth(admin))
    r = _sso_roundtrip(client, bed, monkeypatch, email)
    assert "sso_token=" in r.headers["Location"]
    assert db_query(bed, "SELECT role||'|'||sso FROM users WHERE email=%s;" % _lit(email)) == "user|google"


# =====================================================================
# 12. Static surface and platform hardening
# =====================================================================


def test_index_serves_the_pwa(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"bevins" in r.get_data().lower()


def test_service_worker_is_served_uncached(client):
    r = client.get("/sw.js")
    assert r.status_code == 200
    assert "javascript" in r.headers["Content-Type"]
    assert "no-store" in r.headers["Cache-Control"]
    assert b"caches.delete" in r.get_data()


def test_request_body_size_is_capped(bed):
    assert bed.mod.app.config["MAX_CONTENT_LENGTH"] == 256 * 1024


def test_client_ip_takes_the_proxy_appended_last_hop(bed):
    with bed.mod.app.test_request_context("/", headers={"X-Forwarded-For": "1.2.3.4, 9.9.9.9"}):
        assert bed.mod.client_ip() == "9.9.9.9"


def test_signup_and_login_are_rate_limited(client, users):
    for _ in range(12):
        client.post("/api/login", json={"email": "flood@example.test", "password": "nope-nope-nope"})
    r = client.post("/api/login", json={"email": "flood@example.test", "password": "nope-nope-nope"})
    assert r.status_code == 429


def test_unhandled_errors_do_not_leak_internals(client, users, bed, monkeypatch):
    tok = login(client, users["alice"]["email"], users["alice"]["password"])

    def boom(*a, **k):
        raise RuntimeError("internal detail: DATABASE_URL=%s" % bed.mod.DATABASE_URL)

    monkeypatch.setattr(bed.mod, "user_catalog", boom)
    r = client.get("/api/models", headers=auth(tok))
    assert r.status_code == 500
    body = r.get_data(as_text=True)
    assert "DATABASE_URL" not in body and bed.dbname not in body
    assert r.get_json()["error"] == "request could not be processed"
