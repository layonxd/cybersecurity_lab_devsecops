# CHAT a 
Static Security Review — Baseline Secure Coding API
Findings Table
ID	Title	Location	Severity	Confidence
F1	Path traversal in /files	download_file, @app.get("/files")	High	High
F2	Missing authorization on grade/profile read endpoints (IDOR)	get_profile, get_grades	High	High
F3	Missing authentication & authorization on grade update (privilege escalation)	update_grade, @app.post("/grades/update")	Critical	High
F4	Missing authentication on /files	download_file	High	High
F5	Plaintext password storage and comparison	User dataclass, USERS, login	Medium	High
F6	Hardcoded secret key / credentials in source	app.config["SECRET_KEY"], USERS	Medium	High
F7	Debug mode enabled and server bound to all interfaces	__main__ block	Medium	High
F8	Unvalidated int() conversion of user-controlled student_id	get_profile, get_grades	Low	High
F9	Unvalidated JSON body in /grades/update (missing keys / type confusion)	update_grade	Medium	Medium
F10	Error handler leaks exception details and returns 500 for all errors	handle_error	Low	High
F11	No CSRF protection on state-changing endpoints (login/logout/grade update)	login, logout, update_grade	Medium	Medium
F12	Session fixation / no session regeneration on login	login	Low	Medium
F13	Demo file seeding overwrites files on every startup	Module top-level (MATERIALS_DIR seeding)	Low	High
Supporting Explanations
F1 — Path traversal in /files
Location: download_file, @app.get("/files"), lines where target = MATERIALS_DIR / raw_path and flask.send_file(target) are used.

Attacker input: Query parameter path, e.g. ?path=../../etc/passwd or an absolute path like ?path=/etc/passwd.

Data-flow: flask.request.args.get("path") → MATERIALS_DIR / raw_path → flask.send_file(target). pathlib's / operator with an absolute right-hand operand discards the left side, and .. segments escape the directory.

Missing control: No normalization, no resolve() + containment check against MATERIALS_DIR, no allowlist of filenames. Root cause: user-controlled path joined directly to a base directory and served.

Preconditions/impact: Endpoint is reachable; reading arbitrary files the Flask process can access (config, source, secrets, OS files). This endpoint also has no authentication (F4).

Proposed test: Request GET /files?path=../import_dataclasses.txt and GET /files?path=/etc/hostname; if file contents are returned outside materials/, confirmed.

Assumptions/confidence: Assumes OS allows the process to read the target files. High confidence — pathlib semantics are well-defined.

F2 — IDOR on profile and grades reads
Location: get_profile, get_grades (@app.get("/students/<student_id>/profile"), @app.get("/grades/<student_id>")).

Attacker input: Path parameter student_id (e.g. /grades/1002 while logged in as alice, student_id 1001).

Data-flow: student_id path param → int() → dictionary/list lookup → jsonify. No comparison against flask.session["student_id"] or role.

Missing control: Authorization check that the caller is the owning student, their professor, or an admin. Root cause: endpoint authenticates nothing and authorizes nothing; session data is never consulted.

Preconditions/impact: Unauthenticated (or any authenticated student) can enumerate all students' grades and PII (name, email, program).

Proposed test: Without a session (or as bob), GET /grades/1001 and GET /students/1001/profile; if data for Alice returns, confirmed.

Assumptions/confidence: Assumes grades/profiles are meant to be confidential per-user data (typical for a student records API). High confidence on absence of control; requirement inferred.

F3 — Missing authN/authZ on /grades/update
Location: update_grade, @app.post("/grades/update").

Attacker input: JSON body {student_id, course_id, grade}.

Data-flow: flask.request.get_json() → direct mutation of GRADES → returned to client. No flask.session inspection at all.

Missing control: Authentication required; authorization that caller is a professor for course_id (e.g. prof_srs has courses=["SRS"]) or admin. Root cause: no session/role check, no ownership/course-scope check, grade value not range-validated.

Preconditions/impact: Any unauthenticated client can create or overwrite any grade — integrity violation of academic records, and arbitrary grade values (e.g. 1000) accepted.

Proposed test: curl -X POST /grades/update -H 'Content-Type: application/json' -d '{"student_id":1001,"course_id":"SRS","grade":20}' with no cookies; then GET /grades/1001 to observe the change.

Assumptions/confidence: Assumes grade writes are privileged (professor/admin). High confidence.

F4 — Missing authentication on /files
Location: download_file.

Attacker input: Any request to /files.

Data-flow: No session check before send_file. Combined with F1 this permits unauthenticated arbitrary file read.

Missing control: Authentication (and authorization to course materials). Root cause: endpoint added without access control.

Preconditions/impact: Anonymous access to teaching materials and, via F1, to arbitrary files.

Proposed test: GET /files?path=srs-summary.txt with no session cookie; if served, confirmed.

Assumptions/confidence: Assumes materials are meant to be authenticated (context suggests a student/professor portal). Medium-high confidence; requirement inferred.

F5 — Plaintext passwords
Location: User dataclass field password; USERS seed literals; login comparison user.password != password.

Attacker input: N/A directly; risk materializes on any data exposure (logs, source leak, F1 read of import_dataclasses.txt).

Missing control: Password hashing (e.g. Werkzeug generate_password_hash) and constant-time verification. Root cause: credential model stores secrets in cleartext.

Preconditions/impact: Any read of the source/memory/session dump yields reusable credentials for all demo users.

Proposed test: Inspect USERS values; confirm they equal the literal passwords (no hash prefix such as pbkdf2:/scrypt:).

Assumptions/confidence: High confidence; low practical impact in a demo but a real control gap.

F6 — Hardcoded secret key and credentials
Location: app.config["SECRET_KEY"] = "dev-secret-key"; USERS literal passwords.

Attacker input: If source/secret leaks (see F1), attacker forges Flask session cookies (user, role, student_id, courses).

Data-flow: Forged cookie → Flask session deserialization → session["role"] trusted by endpoints. Note: current endpoints barely use role, but the session is the intended trust anchor.

Missing control: Secret from environment / secret manager, rotated; credentials not in VCS. Root cause: dev defaults shipped in source.

Preconditions/impact: Source disclosure (trivial via F1) → session forgery → impersonation of admin1/prof_srs.

Proposed test: With known SECRET_KEY, sign a session cookie setting user=admin1, role=admin, replay to /me; if accepted, confirmed.

Assumptions/confidence: High confidence on fact; impact depends on whether any endpoint later trusts role.

F7 — Debug mode and 0.0.0.0 binding
Location: app.run(debug=True, host="0.0.0.0", port=5001) in __main__.

Attacker input: Any request that triggers an exception → Werkzeug debugger page (interactive console if PIN is bypassed/known).

Data-flow: Unhandled exceptions reach Werkzeug debugger. Note: the app registers @app.errorhandler(Exception) returning 500, which suppresses the traceback page in request handling — so the debugger is only exposed for failures outside that handler. This reduces, but does not eliminate, the risk (e.g. debugger PIN, console on some paths, reloader).

Missing control: debug=False in any non-dev deployment; bind to loopback. Root cause: dev config shipped as default.

Preconditions/impact: If deployed as-is on a network, debug console exposure → RCE; also verbose error behavior.

Proposed test: Trigger an exception outside the handler (e.g. malformed request that bypasses the error handler, or inspect whether the Werkzeug console is served) on a test instance; verify debug is True by observing the reloader banner.

Assumptions/confidence: Medium confidence on exploitability given the catch-all handler; high confidence on the misconfiguration itself.

F8 — Unvalidated int() on path params
Location: get_profile, get_grades (int(student_id)).

Attacker input: student_id = "abc" or huge integer.

Data-flow: int(student_id) raises ValueError → caught by handle_error → 500 with exception text (see F10) instead of 400/404.

Missing control: Input validation and proper 400 handling; also unbounded integers.

Preconditions/impact: Low — information disclosure via error message and incorrect status codes; no memory-safety issue in Python.

Proposed test: GET /grades/abc; expect 400, observe 500 with ValueError text.

Assumptions/confidence: High confidence.

F9 — Unvalidated JSON body in /grades/update
Location: update_grade, direct data["student_id"], data["course_id"], data["grade"].

Attacker input: Missing keys → KeyError → 500; wrong types (e.g. grade: "twenty", student_id: {}) → stored as-is or crash; get_json() returns None for non-JSON → TypeError.

Data-flow: Body → dict access → GRADES mutation with no schema validation or grade range check.

Missing control: Schema validation (types, required fields, grade ∈ [0, 20] per typical Portuguese scale — assumption), 400 responses. Root cause: trusting client JSON.

Preconditions/impact: Data integrity (arbitrary grade values), 500s, possible denial of service via malformed bodies.

Proposed test: POST {} → expect 400, observe 500/KeyError; POST {"student_id":1001,"course_id":"SRS","grade":9999} → observe accepted value.

Assumptions/confidence: Grade-range requirement is inferred; type-safety gap is factual. Medium confidence on impact.

F10 — Verbose error handler
Location: handle_error, @app.errorhandler(Exception).

Attacker input: Any input triggering exceptions (F8, F9, missing file in F1 → FileNotFoundError).

Data-flow: Exception → {"error": str(exc), "type": exc.__class__.__name__} with status 500. Leaks internal paths, class names, and error text; also converts 4xx conditions into 500s, masking correct status codes.

Missing control: Generic error responses in production, logging server-side, distinguishing client vs server errors.

Preconditions/impact: Information disclosure aiding further attacks (e.g. absolute paths from F1). Low direct impact.

Proposed test: GET /grades/abc and GET /files?path=missing.txt; inspect response body for exception type/text.

Assumptions/confidence: High confidence.

F11 — No CSRF protection
Location: login, logout, update_grade (all POST, cookie-based session).

Attacker input: Cross-site form/JSON POST from a malicious origin while victim is logged in.

Data-flow: Browser sends session cookie automatically → state change. update_grade accepts JSON, which is harder to send cross-origin without CORS preflight (simple text/plain bodies won't satisfy get_json() unless Content-Type: application/json, which triggers preflight). So CSRF is most credible for login (login CSRF) and logout; grade update CSRF is constrained but not impossible (e.g. same-site subdomain, or if CORS is later added).

Missing control: CSRF tokens / SameSite cookie attributes / origin checks. Root cause: session-cookie-authenticated state changes without anti-CSRF measures.

Preconditions/impact: Login CSRF (session fixation-adjacent), forced logout; grade CSRF if JSON POST can be induced.

Proposed test: Serve an HTML page on another origin with a form POSTing to /logout and /login; load it while authenticated and observe effects.

Assumptions/confidence: Medium confidence on exploitability of update_grade CSRF; high on login/logout.

F12 — Session fixation
Location: login — sets flask.session keys but never rotates the session identifier.

Attacker input: Attacker sets victim's session cookie before login (classic fixation); after victim logs in, the same session ID is now authenticated.

Missing control: session.clear() + new session on login (Flask signs cookies; fixation is mitigated by signed-cookie sessions only if the attacker cannot forge a cookie — which F6 undermines). Root cause: no session regeneration; compounded by predictable SECRET_KEY.

Preconditions/impact: Requires ability to set victim's cookie (subdomain/XSS) or knowledge of SECRET_KEY (F6); then impersonation.

Proposed test: With known SECRET_KEY, pre-sign a session cookie, have victim "log in", verify the cookie value is unchanged and now authenticated.

Assumptions/confidence: Medium confidence; largely subsumed by F6.

F13 — Startup overwrites seeded files
Location: Module top-level MATERIALS_DIR / "srs-summary.txt".write_text(...) and secure-coding.txt.

Attacker input: N/A; operational issue.

Data-flow: Every process start rewrites the two demo files, clobbering any real content placed there (e.g. uploaded teaching materials).

Missing control: Idempotent seeding (only write if absent). Root cause: demo seeding executed unconditionally at import.

Preconditions/impact: Data loss on restart if materials/ is used for real content.

Proposed test: Put custom content in materials/srs-summary.txt, restart the app, observe it replaced.

Assumptions/confidence: High confidence on behavior; impact depends on deployment intent.

Notes on scope and assumptions
Facts demonstrated by source: F1 (path join + send_file), F2/F3/F4 (no session checks in those functions), F5/F6 (literal secrets), F7 (debug=True, 0.0.0.0), F8/F9/F10 (raw conversions and catch-all handler), F13 (unconditional writes).

Inferred requirements (assumptions, not proven by source):

Grades/profiles are confidential per-user data (F2).

Grade writes are restricted to professors/admins, and grades have a valid range (F3, F9).

/files is intended for authenticated users only (F4).

Session cookie flags (Secure, HttpOnly, SameSite) are not set anywhere in the provided source — implied by absence of SESSION_COOKIE_* config; worth verifying against deployment config.

Not assessed (out of scope / no evidence in source): TLS termination, reverse-proxy config, dependency CVEs, rate limiting on /login (no lockout/throttling visible — a brute-force gap), logging/monitoring, and whether materials/ is served by another handler.

Absence of findings ≠ safety: This review covers only the provided file and its explicit behavior.

If you'd like, I can follow up with proposed patches for F1–F4 and F9–F10, but per your instruction I have not generated them here.