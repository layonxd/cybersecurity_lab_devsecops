# CHAT b
Static Security Review
Findings Table
ID	Title	Location	Severity	Confidence
F-01	Broken Access Control on Grade Update	/grades/update (update_grade)	Critical	High
F-02	Broken Access Control / IDOR on Grade Retrieval	/grades/<student_id> (get_grades)	High	High
F-03	Broken Access Control / IDOR on Student Profile	/students/<student_id>/profile (get_profile)	High	High
F-04	Path Traversal in File Download	/files (download_file)	Critical	High
F-05	Unauthenticated Access to Sensitive Endpoints	get_profile, get_grades, update_grade, download_file	High	High
F-06	Plaintext Password Storage and Comparison	USERS seed data; login()	Medium	High
F-07	Hardcoded Secret Key and Debug Mode / 0.0.0.0 Binding	app.config["SECRET_KEY"], app.run(debug=True, host="0.0.0.0")	High	High
F-08	Unvalidated JSON Input on Grade Update (type/range/mass-input)	/grades/update (update_grade)	Medium	High
F-09	Verbose Error Handler Leaks Exception Details	handle_error	Low–Medium	High
F-10	No CSRF Protection on State-Changing Forms	/login, /logout, /grades/update	Medium	Medium
F-11	Missing Type/None Handling on student_id Path Param (DoS)	get_profile, get_grades	Low	High
F-12	Session Fixation / No Session Regeneration on Login	login()	Medium	Medium
F-13	Redirect After Login Enables Open-Redirect-Adjacent Behavior / Info Leak	login() → flask.redirect("/me")	Low	Low
Supporting Explanations
F-01 — Broken Access Control on Grade Update
File/function: import dataclasses.txt, update_grade() (POST /grades/update).

Attacker input: JSON body fields student_id, course_id, grade.

Data flow: flask.request.get_json() → data["student_id"]/data["course_id"]/data["grade"] → find_grade → mutate GRADES → returned. No check of flask.session["role"], no check that a professor teaches course_id, no check that a student is updating only their own record.

Missing control: Authentication/authorization (role + object ownership/course-assignment checks). Root cause: endpoint trusts client-supplied identifiers and exposes mutation without any session-based authorization.

Preconditions/impact: Any unauthenticated caller (or any authenticated student) can insert or overwrite any grade for any student/course. Integrity compromise of academic records; privilege escalation in effect.

Proposed test: Send POST /grades/update with {"student_id":1002,"course_id":"SRS","grade":20} using no session cookie and with a student session; assert the response and re-read GET /grades/1002 to confirm mutation. Expected secure behavior: 401/403 and unchanged data.

Assumptions/uncertainty: The application context states roles exist and professors have assigned courses, implying authorization is expected. This is an inferred requirement from context, not explicitly coded. Confidence high on the code fact; severity assumes grades are sensitive.

F-02 — IDOR on Grade Retrieval
File/function: get_grades() (GET /grades/<student_id>).

Attacker input: student_id path segment.

Data flow: int(student_id) → list comprehension over GRADES → jsonify(rows). No session check; no comparison to flask.session["student_id"] or professor course list.

Missing control: Object-level authorization (student can read only own grades; professor only for taught courses; admin allowed). Root cause: trust in path parameter only.

Preconditions/impact: Any caller can enumerate student IDs (1001, 1002, …) and read all grades. Privacy/integrity (confidentiality) breach.

Proposed test: As unauthenticated user and as alice (student_id 1001), request /grades/1002; confirm 200 with Bob's grades. Expected: 403 unless authorized.

Assumptions/uncertainty: Same role assumptions as F-01. Confidence high on code fact.

F-03 — IDOR on Student Profile
File/function: get_profile() (GET /students/<student_id>/profile).

Attacker input: student_id path segment.

Data flow: int(student_id) → STUDENT_PROFILES.get(...) → jsonify(profile) (contains name, email, program).

Missing control: Object-level authorization and authentication. Root cause: directory lookup keyed solely by user-supplied ID.

Preconditions/impact: Unauthenticated enumeration of all student PII (email addresses, names, programs). Confidentiality breach; useful for phishing/social engineering.

Proposed test: GET /students/1002/profile without a session; expect 200 with Bob's data. Expected secure: 401/403.

Assumptions/uncertainty: Profiles are considered PII/sensitive in the academic context. Confidence high on code fact.

F-04 — Path Traversal in File Download
File/function: download_file() (GET /files).

Attacker input: Query parameter path.

Data flow: raw_path = flask.request.args.get("path","") → target = MATERIALS_DIR / raw_path → flask.send_file(target).

Missing control: Canonicalization + containment check (e.g., resolve path and verify it is within MATERIALS_DIR), and input validation/allowlist. Root cause: pathlib / operator with an absolute or ../-laden string yields a path outside the intended directory; Flask's send_file will serve whatever the resolved path points to.

Preconditions/impact: No auth required. Examples: path=../../etc/passwd, path=/etc/passwd (absolute path replaces MATERIALS_DIR), or path=../app.py. Arbitrary file read of any file the process can access, including source, secrets, and system files. Critical confidentiality breach; possible further compromise if readable files contain credentials.

Proposed test: GET /files?path=../app.py and GET /files?path=/etc/passwd; observe response body. Expected secure: 400/404 and no file content.

Assumptions/uncertainty: Assumes default Flask/send_file behavior with a Path object (documented behavior; stated as code fact from the expression, not executed). Confidence high.

F-05 — Unauthenticated Access to Sensitive Endpoints
File/functions: get_profile, get_grades, update_grade, download_file.

Attacker input: Any request to these routes.

Data flow: Routes have no if "user" not in flask.session guard (contrast me() which does).

Missing control: Authentication enforcement (e.g., before_request or per-route check). Root cause: only me() and implicitly login are session-aware; other routes never check session.

Preconditions/impact: Enables F-01–F-04 without any credentials. Amplifies all other findings.

Proposed test: Call each endpoint with no Cookie header; compare with GET /me which returns {"user": null}. Expected secure: 401 for protected routes.

Assumptions/uncertainty: The / index lists these as API endpoints alongside /login; context implies they are meant for authenticated users. Explicit authorization policy not coded — inferred. Confidence high on code fact; medium on intended policy (though academic records are clearly sensitive).

F-06 — Plaintext Passwords
File/function: USERS literal; login() comparison user.password != password.

Attacker input: Login form fields (indirect).

Data flow: Stored plaintext in module memory; direct string comparison.

Missing control: Password hashing (e.g., Werkzeug generate_password_hash/check_password_hash) and constant-time comparison. Root cause: demo seed data stored verbatim; comparison uses !=.

Preconditions/impact: If the process memory/source is exposed (see F-04, F-09), all credentials are disclosed. Timing side-channel on != is theoretically possible but low practical risk over HTTP. Also no password policy/lockout.

Proposed test: Read source/USERS via traversal (F-04); or inspect login timing distribution. Expected secure: only hashes stored, check_password_hash used.

Assumptions/uncertainty: Context says "small dataset simplifies teaching environment; not a production database" — may be intentional for the exercise, but still a vulnerability class worth recording. Confidence high on fact; severity depends on deployment assumptions.

F-07 — Hardcoded Secret Key, Debug Mode, Broad Bind
File: module top (SECRET_KEY) and __main__ (app.run(debug=True, host="0.0.0.0", port=5001)).

Attacker input: None directly; configuration exposure.

Data flow: SECRET_KEY = "dev-secret-key" used to sign session cookies; debug mode enables Werkzeug debugger and interactive console; 0.0.0.0 exposes on all interfaces.

Missing control: Secret from environment/secret store; debug disabled in any shared environment; bind restricted. Root cause: dev defaults shipped in code.

Preconditions/impact: Known secret allows forging Flask session cookies (e.g., set role=admin, student_id arbitrary) → full auth bypass combined with F-05. Debug mode exposes an interactive debugger (potentially RCE) if an exception is triggered and the debugger is reachable; combined with handle_error returning 500 on Exception, many errors are caught, but debug middleware may still be active. 0.0.0.0 broadens exposure.

Proposed test: With the known key, craft a signed session cookie for {"user":"admin1","role":"admin"} and request /me; observe acceptance. Also trigger an unhandled error path to check for debugger. Expected secure: unknown secret, debug off.

Assumptions/uncertainty: Whether this is run in a shared/lab environment determines impact. The @app.errorhandler(Exception) catches many errors, which may reduce debugger exposure, but debug=True still adds the Werkzeug debugger middleware. Confidence high on code fact; impact conditional.

F-08 — Unvalidated JSON Input on Grade Update
File/function: update_grade().

Attacker input: JSON body.

Data flow: get_json() (may be None if content-type wrong) → direct data["student_id"] etc. → find_grade/append. No schema validation, type checks, grade range check (e.g., 0–20), or course existence check.

Missing control: Input validation and schema enforcement. Root cause: trusting client-supplied JSON structure and values.

Preconditions/impact: Malformed body causes 500 (via KeyError/TypeError) — handled by handle_error leaking type/message (F-09). Arbitrary grade values (e.g., 9999, negative) and arbitrary course IDs can be stored; unknown students can be inserted, creating inconsistent records.

Proposed test: POST /grades/update with {}, with {"student_id":"x"}, and with grade: 9999; observe 500 details and stored values. Expected secure: 400 with validation errors; range enforced.

Assumptions/uncertainty: Grade scale (0–20) inferred from seed data (14, 15, 16) and academic context — not stated. Confidence high on lack of validation; medium on required range.

F-09 — Verbose Error Handler
File/function: handle_error().

Attacker input: Any malformed request that raises.

Data flow: exc → str(exc) and exc.__class__.__name__ returned in JSON with 500.

Missing control: Generic error responses; server-side logging only. Root cause: echoing exception text to clients.

Preconditions/impact: Aids reconnaissance (e.g., file paths from FileNotFoundError, type names from bad input, internal logic hints). Low direct impact but facilitates other attacks.

Proposed test: GET /students/notanint/profile → observe ValueError message and type. Expected secure: generic 400.

Assumptions/uncertainty: Impact depends on what exceptions leak (e.g., path info via F-04/F-11). Confidence high on fact.

F-10 — No CSRF Protection
File/functions: login(), logout(), update_grade() (accepts JSON; browser form can't easily send JSON but a cross-origin script could if CORS were permissive — note no CORS config present, so update_grade is less exposed; login uses form encoding).

Attacker input: Cross-site form/scripted request from a victim's browser.

Data flow: Session cookie auto-attached; no CSRF token checked in flask.request.form or headers; no SameSite configuration shown (Flask defaults SESSION_COOKIE_SAMESITE is unset → typically Lax in modern browsers, which mitigates some but not all cases; state-changing GETs absent here).

Missing control: CSRF token validation (e.g., Flask-WTF) and/or explicit SameSite=Strict. Root cause: no CSRF middleware.

Preconditions/impact: Login CSRF (forcing victim into attacker's account) is plausible since /login is a form POST. logout CSRF forces logout. update_grade CSRF requires the attacker to send JSON with credentials — cross-origin JSON POST triggers CORS preflight (no CORS configured → blocked), so this is lower risk; however, if SameSite is None and CORS is later added, risk rises.

Proposed test: Serve an HTML page on another origin that auto-submits a form to /login with attacker credentials; observe victim's session. Expected secure: token required.

Assumptions/uncertainty: Session cookie SameSite default and deployment (HTTPS, domain) are unknown — stated as assumption. Confidence medium.

F-11 — Malformed student_id Causes 500 (DoS surface)
File/functions: get_profile, get_grades — int(student_id).

Attacker input: Non-numeric path segment.

Data flow: int("abc") → ValueError → handle_error → 500 with type/message.

Missing control: Input validation / abort(400) on parse failure. Root cause: unguarded int().

Preconditions/impact: Low-severity DoS/recon; each bad request is cheap. Combined with F-09 leaks ValueError text.

Proposed test: GET /grades/abc; observe 500 JSON with "type": "ValueError". Expected secure: 400.

Assumptions/uncertainty: Minimal impact alone. Confidence high on fact.

F-12 — No Session Regeneration on Login (Session Fixation)
File/function: login().

Attacker input: Pre-set session cookie value (if attacker can set victim's cookie via subdomain/XSS or fixation vector).

Data flow: flask.session["user"] = ... mutates existing session; no flask.session.clear() or new session ID issued at authentication boundary.

Missing control: Session ID rotation on privilege change. Root cause: reuse of pre-auth session.

Preconditions/impact: Classic session fixation requires an injection vector (e.g., URL parameter in some frameworks; Flask's cookie-based sessions are harder to fixate than server-side ones, since the cookie is signed and the attacker would need to control the victim's cookie). In Flask's default client-side session, fixation is much less practical because the cookie content is signed and the server does not accept an attacker-supplied session ID server-side. Impact thus low unless the app is moved to server-side sessions.

Proposed test: Set a session cookie, log in, compare cookie signatures/values before and after; check whether server accepts a pre-set cookie as the same session. Expected secure: new session identifier.

Assumptions/uncertainty: Flask's default client-side signed-cookie sessions substantially reduce fixation risk; this finding is speculative for the current stack. Confidence low–medium; flagged for completeness.

F-13 — Minor: Redirect After Login / Information Surfacing
File/function: login() returns flask.redirect("/me").

Attacker input: None direct.

Data flow: Fixed target, so no open redirect. However, /me returns role/student_id/courses, which combined with F-07's known secret is a convenient oracle for forged-session testing.

Missing control: None strictly; noted as context that amplifies F-07.

Proposed test: Log in with known secret-forged cookie and inspect /me. Expected secure: unknown secret makes forgery infeasible.

Assumptions/uncertainty: This is a supporting observation rather than a standalone vulnerability. Confidence high on code fact; low standalone severity.

Cross-Cutting Notes and Assumptions
Demonstrated code facts: absence of auth checks in get_profile, get_grades, update_grade, download_file; direct path concatenation in download_file; plaintext passwords in USERS; hardcoded SECRET_KEY; debug=True; 0.0.0.0 bind; verbose handle_error; unguarded int() and get_json() field access.

Inferred security requirements (not coded): role-based authorization (students read own grades; professors write only their courses; admins manage), authentication on all non-login routes, password hashing, secret management, CSRF protection, input validation (grade range, course existence), and path confinement. These are inferred from the provided application context ("users have roles", "grades associate student/course/grade", "used by multiple users"), not from explicit policy text; the review states them as assumptions rather than proven violations of a written policy.

Out of scope / not assessed: TLS configuration, reverse-proxy behavior, cookie flags (Secure, HttpOnly, SameSite) since they are not configured in the shown source (Flask defaults apply and were not enumerated), dependency versions, and whether materials/ contains sensitive files beyond the two seeded demos.

Compounding effect: F-07 (known secret) + F-05 (no auth checks) + F-01/F-02/F-03 (no object-level checks) together allow an attacker to forge an admin session and read/modify any student's data, while F-04 permits arbitrary file read. F-01 is the highest-impact standalone integrity issue; F-04 is the highest-impact confidentiality issue.

Not proof of safety: The absence of further findings does not imply the application is free of other vulnerabilities (e.g., dependency, deployment, or platform issues not visible here).