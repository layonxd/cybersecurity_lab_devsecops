Path Traversal Fix — /files Endpoint
Root cause
download_file() concatenates the user-supplied path query parameter directly onto MATERIALS_DIR and passes the result to flask.send_file() without canonicalizing it or verifying that the resolved target still lives inside MATERIALS_DIR. A value like ../baseline_secure_coding_api.py (or an absolute path, depending on pathlib/os.path.join semantics) escapes the materials directory.

send_file itself does not sandbox paths — it will happily serve any file the process can read.

Control being implemented
Reject empty paths — nothing to serve.

Resolve the candidate path with pathlib.Path.resolve() (collapses .., symlinks, and makes the path absolute).

Verify containment with Path.is_relative_to(MATERIALS_DIR) — only serve if the canonical target is inside the canonical materials root. This blocks .. traversal, absolute paths, and symlink escapes.

Reject directories / non-files — send_file should only receive regular files.

Return 400 (not 404) for rejected input, so callers can distinguish "bad request" from "file not found"; missing in-bounds files still return 404 from send_file as before. The existing response contract (a send_file payload for legitimate names like srs-summary.txt) is preserved.

This is the only endpoint that reads from the filesystem using a caller-supplied path, so it is the only affected path.

Unified diff
diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@
 @app.get("/files")
 def download_file():
     raw_path = flask.request.args.get("path", "")
-    target = MATERIALS_DIR / raw_path
-    return flask.send_file(target)
+    if not raw_path:
+        return {"error": "missing path parameter"}, 400
+
+    # Canonicalize the candidate and the materials root, then require
+    # containment. This blocks "../" traversal, absolute paths, and
+    # symlink escapes because resolve() collapses all of them.
+    try:
+        target = (MATERIALS_DIR / raw_path).resolve()
+        materials_root = MATERIALS_DIR.resolve()
+    except (OSError, RuntimeError):
+        # Symlink loops, permission errors, etc.
+        return {"error": "invalid path"}, 400
+
+    if not target.is_relative_to(materials_root):
+        return {"error": "path outside materials directory"}, 400
+    if not target.is_file():
+        return {"error": "file not found"}, 404
+
+    return flask.send_file(target)

Why this is minimal and safe
One handler changed; no endpoints removed, no features disabled, no tests touched.

Legitimate requests (?path=srs-summary.txt, ?path=subdir/notes.txt) still work and still return the file bytes with send_file's usual headers/status.

Path.resolve() on Python ≥ 3.9 (this app requires 3.10) handles symlinks and .. reliably; is_relative_to is available since 3.9, so no manual prefix-string comparison (which would be vulnerable to materials-evil/ sharing a prefix with materials/).

Errors are explicit JSON, matching the API's existing error style, and status codes (400 for malformed/out-of-bounds, 404 for a well-formed but missing file) are distinguishable.

Remaining assumptions / limitations
Symlink policy: resolve() follows symlinks. A symlink inside MATERIALS_DIR pointing outside it will resolve outside and be rejected — that's the desired behavior, but if the deployment intends to allow symlinked materials, a different policy (e.g., os.path.realpath on the root only, and rejecting symlinks in lstat) would be needed.

TOCTOU: between resolve()/is_file() and send_file() the filesystem could change. Exploiting this requires local write access to materials/, which is out of scope for a web-only attacker; mitigating it fully would require opening a file descriptor and using send_file(fd), which is more invasive.

Case-insensitive filesystems (macOS/Windows): is_relative_to is lexical after resolution; a case-folded comparison is not performed. This app runs on Linux (/opt/hostedtoolcache/...), so it's fine here, but worth noting for portability.

SECRET_KEY and debug=True are separate issues surfaced by the same file (hardcoded secret, debug mode on 0.0.0.0, plaintext passwords, no auth on /grades/*, etc.) — not addressed here to keep the patch scoped to the confirmed path-traversal finding.

Suggested regression tests
Add alongside the existing tests_security/test_path_trans.py:

python
@pytest.mark.parametrize("bad", [
    "../baseline_secure_coding_api.py",
    "../../etc/passwd",
    "/etc/passwd",            # absolute
    "..%2fbaseline_secure_coding_api.py",  # if the client decodes
    "",
])
def test_files_rejects_outside_or_empty(client, bad):
    login(client, "prof_srs", "profpw")
    r = client.get("/files", query_string={"path": bad})
    assert r.status_code in (400, 404)
    # and ensure the source file contents did not leak
    assert b"Flask" not in r.data or r.status_code != 200


def test_files_allows_legit_material(client):
    login(client, "prof_srs", "profpw")
    r = client.get("/files", query_string={"path": "srs-summary.txt"})
    assert r.status_code == 200
    assert b"Secure Requirements Engineering" in r.data


def test_files_rejects_missing_in_bounds(client):
    login(client, "prof_srs", "profpw")
    r = client.get("/files", query_string={"path": "does-not-exist.txt"})
    assert r.status_code == 404


def test_files_rejects_symlink_escape(client, tmp_path, monkeypatch):
    # symlink inside materials/ pointing to a file outside
    outside = tmp_path / "secret.txt"
    outside.write_text("secret", encoding="utf-8")
    link = MATERIALS_DIR / "escape.txt"
    link.unlink(missing_ok=True)
    link.symlink_to(outside)
    try:
        login(client, "prof_srs", "profpw")
        r = client.get("/files", query_string={"path": "escape.txt"})
        assert r.status_code == 400
    finally:
        link.unlink(missing_ok=True)



Does it address the root cause or just the supplied example input?
Yes it validates the path is relative to the materials folder 


Does an authentication check leave object/course authorization missing?
no authentication or authorization was requested 

Are all relevant paths protected, including read and update operations?
Yes, they all were addressed


Are authorized users still able to perform their permitted actions?
Yes , as long as they do it  in the way it was designed  

Are denial responses and state changes correct?
yes 400 bad request and 404 file not found 

Has it introduced an unrelated change, broad exception handler, or insecure fallback?
No , it stayed within the requested task 