We are now repairing a confirmed vulnerability in the supplied application.
Confirmed finding:
client = <FlaskClient <Flask 'baseline_secure_coding_api'>>

    def test_FAIL_path_tranversal_wo_auth(client):
        #login(client, "prof_srs", "profpw")
        response = client.get("/files", query_string={"path": "srs-summary.txt"})
        print(response.get_data(as_text=True))
>       assert response.status_code != 200
E       assert 200 != 200
E        +  where 200 = <WrapperTestResponse 39 bytes [200 OK]>.status_code

tests_security/test_path_trans.py:32: AssertionError

@app.get("/files")
def download_file():
    raw_path = flask.request.args.get("path", "")
    target = MATERIALS_DIR / raw_path
    return flask.send_file(target)

returns the file without being authed 

Required behavior:

if not authenticated or wrong creds should not return 200

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.
Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.
Path Traversal + Missing Auth on /files
Root cause







GET /files does two things wrong at once:

No authentication / authorization check. Any anonymous client can request srs-summary.txt (or traverse).

No path containment. MATERIALS_DIR / raw_path is a raw join, so path=../app.py, path=/etc/passwd, or URL-encoded variants escape MATERIALS_DIR. Flask's send_file will happily serve any readable file.

The failing test only exercises the auth gap, but the same handler is the only affected path — there is exactly one route that reads from disk. The fix must close both holes at that single choke point.

Unified diff
diff
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 import dataclasses
 import pathlib
 import typing
 
 import flask
+from flask import abort, session
@@ -78,6 +79,15 @@
 
 @app.post("/login")
 def login():
@@ -96,9 +106,19 @@
     return {
         "user": flask.session.get("user"),
         "role": flask.session.get("role"),
         "student_id": flask.session.get("student_id"),
         "courses": flask.session.get("courses"),
     }
 
+# -----------------------------------------------------------------------------
+# Auth / authz helpers
+# -----------------------------------------------------------------------------
+
+def _require_authenticated():
+    if "user" not in flask.session:
+        flask.abort(401)
+
+def _require_roles(*roles):
+    _require_authenticated()
+    if flask.session.get("role") not in roles:
+        flask.abort(403)
+
 
 @app.get("/students/<student_id>/profile")
 def get_profile(student_id):
@@ -122,13 +142,25 @@
 
 @app.get("/files")
 def download_file():
-    raw_path = flask.request.args.get("path", "")
-    target = MATERIALS_DIR / raw_path
-    return flask.send_file(target)
+    # Only authenticated users may download course materials.
+    # Restrict to privileged roles: students should get their own grades
+    # via /grades/<id>, not arbitrary files.
+    _require_roles("professor", "admin")
+
+    raw_path = flask.request.args.get("path", "").strip()
+    if not raw_path:
+        flask.abort(400)
+
+    # Resolve and confine to MATERIALS_DIR. This blocks:
+    #   ../app.py, /etc/passwd, ..%2f..%2f, symlinks pointing outside,
+    #   and absolute paths smuggled via os.path.join semantics.
+    try:
+        base = MATERIALS_DIR.resolve(strict=True)
+        target = (base / raw_path).resolve(strict=True)
+    except (OSError, RuntimeError):
+        # Non-existent, dangling symlink, or unresolvable path.
+        flask.abort(404)
+
+    # Verify containment on the resolved real path (symlink-safe).
+    if base != target and base not in target.parents:
+        flask.abort(404)
+    if not target.is_file():
+        flask.abort(404)
+
+    return flask.send_file(target)
Note: app.errorhandler(Exception) currently turns abort(401)/abort(403)/abort(404) into a 500 JSON body. Either accept that (status code is what tests check) or add targeted HTTPException handling. Minimal change to preserve contract: keep the handler but re-raise HTTPException so Werkzeug produces the correct status. That's a second, small patch — see "Remaining limitations".

The control being implemented
Authentication gate on /files (401 if no session user).

Role-based authorization on /files (403 unless professor or admin). Students have their own grade endpoints; they should not enumerate material files.

Canonical path containment: resolve both the base and the requested target, then assert target == base or base in target.parents. This is the standard fix for path traversal and is symlink-safe (resolve(strict=True)), unlike a naive startswith string check on the raw argument or on os.path.normpath alone.

Reject empty path with 400 rather than serving the directory.

strict=True collapses the "missing file" vs "traversal" cases into a uniform 404, which avoids leaking existence of files outside the sandbox.

Why one choke point is sufficient: grep for send_file, open(, pathlib.Path(... ) reads in the file — download_file is the only endpoint that reads user-controlled paths. MATERIALS_DIR seeding at module import is not attacker-controlled. So no other route needs the same control; the only related hardening is making sure the errorhandler does not swallow HTTPException.

Remaining assumptions & limitations
errorhandler(Exception) rewrites 401/403/404 to 500. The patch returns abort(401) but the existing handler returns a JSON {"error": ..., "type": "Unauthorized"} with status 500. Tests asserting != 200 still pass, but any client expecting 401 will not see it. Recommended follow-up:

python
@app.errorhandler(flask.HTTPException)
def handle_http(exc):
    return {"error": exc.description, "type": exc.__class__.__name__}, exc.code
debug=True, host="0.0.0.0" remains in __main__. Not the finding, but a real exposure; out of scope for this minimal patch.

No CSRF/rate-limiting on /login; credentials are plaintext in memory. Not the finding.

Role policy assumption: we assume professors/admins are the only legitimate file consumers. If students do need material downloads for enrolled courses, replace _require_roles(...) with an enrollment check (course_id derived from filename vs session["courses"]) — but that's a product decision, not part of the security fix.

Symlink inside materials/ pointing outside is blocked by resolve(strict=True) + containment check. A symlink that resolves inside MATERIALS_DIR is still served — acceptable.

TOCTOU between resolve(strict=True) and send_file exists in principle. Mitigated for this app because MATERIALS_DIR is seeded once at import and not writable by the API. If uploads are added later, switch to opening the resolved file descriptor once and streaming it.

Suggested regression tests
Add to tests_security/test_path_trans.py (do not weaken existing tests):

python
import pytest

TRAVERSALS = [
    "srs-summary.txt",           # legit file, still must require auth
    "../app.py",                 # parent escape
    "../../etc/passwd",          # deep escape
    "/etc/passwd",               # absolute
    "..%2fapp.py",               # encoded (Flask decodes; still must reject)
    "materials/../app.py",       # nested
    "",                          # empty
    ".",                         # directory
    "does-not-exist.txt",        # 404 not 500
]

@pytest.mark.parametrize("path", TRAVERSALS)
def test_files_requires_auth(client, path):
    r = client.get("/files", query_string={"path": path})
    assert r.status_code in (401, 403, 404), (path, r.status_code)

def test_files_student_forbidden(client, login):
    login(client, "alice", "alicepw")
    r = client.get("/files", query_string={"path": "srs-summary.txt"})
    assert r.status_code == 403

def test_files_professor_can_download_legit(client, login):
    login(client, "prof_srs", "profpw")
    r = client.get("/files", query_string={"path": "srs-summary.txt"})
    assert r.status_code == 200
    assert b"Secure Requirements" in r.data

@pytest.mark.parametrize("path", ["../app.py", "/etc/passwd", "../"*10 + "etc/passwd"])
def test_files_professor_cannot_traverse(client, login, path):
    login(client, "prof_srs", "profpw")
    r = client.get("/files", query_string={"path": path})
    assert r.status_code == 404

def test_files_symlink_escape_rejected(client, login, tmp_path, monkeypatch):
    # material dir has a symlink pointing to /etc/passwd
    outside = tmp_path / "secret.txt"
    outside.write_text("top secret")
    link = MATERIALS_DIR / "evil.txt"
    link.symlink_to(outside)
    try:
        login(client, "prof_srs", "profpw")
        r = client.get("/files", query_string={"path": "evil.txt"})
        assert r.status_code == 404
    finally:
        link.unlink()

def test_files_http_exception_not_500(client):
    # If the follow-up HTTPException handler is applied, ensure 401 not 500.
    r = client.get("/files", query_string={"path": "srs-summary.txt"})
    assert r.status_code == 401
Coverage checklist: auth gate, role gate, legit download (positive), traversal (relative/absolute/encoded/nested), empty path, missing file, symlink escape, and status-code contract (401 vs 500).





Does it address the root cause or just the supplied example input?



Does an authentication check leave object/course authorization missing?


Are all relevant paths protected, including read and update operations?



Are authorized users still able to perform their permitted actions?


Are denial responses and state changes correct?


Has it introduced an unrelated change, broad exception handler, or insecure fallback?
