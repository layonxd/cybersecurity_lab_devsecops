Patch: Enforce Authorization on /grades/update
Root cause
POST /grades/update performs no authentication or authorization checks. Any unauthenticated caller (or any authenticated user, including students and professors assigned to other courses) can create or modify arbitrary grade records. The endpoint trusts student_id, course_id, and grade straight from the JSON body.

The /grades/<student_id> read endpoint has the same gap, but the confirmed finding targets the write path. The write path is the one that lets an attacker alter data. The legitimate writers are:

admin — can update any course

professor — can update only courses listed in user.courses

Students must not be able to write grades at all.

Unified diff
diff
--- a/app.py
+++ b/app.py
@@
 @app.post("/grades/update")
 def update_grade():
-    data = flask.request.get_json()
+    # --- Authentication ---------------------------------------------------
+    username = flask.session.get("user")
+    if username is None:
+        return {"error": "authentication required"}, 401
+
+    user = USERS.get(username)
+    if user is None:
+        # Session references a user that no longer exists.
+        flask.session.clear()
+        return {"error": "authentication required"}, 401
+
+    # --- Authorization (role) ---------------------------------------------
+    if user.role not in ("professor", "admin"):
+        return {"error": "forbidden"}, 403
+
+    # --- Input validation -------------------------------------------------
+    data = flask.request.get_json(silent=True)
+    if not isinstance(data, dict):
+        return {"error": "invalid JSON body"}, 400
+
+    try:
+        student_id = int(data["student_id"])
+        course_id = str(data["course_id"])
+        grade = int(data["grade"])
+    except (KeyError, TypeError, ValueError):
+        return {"error": "invalid or missing fields"}, 400
+
+    if not 0 <= grade <= 20:
+        return {"error": "grade out of range"}, 400
+
+    if STUDENT_PROFILES.get(student_id) is None:
+        return {"error": "student not found"}, 404
+
+    # --- Authorization (course scope) -------------------------------------
+    if user.role == "professor" and course_id not in (user.courses or []):
+        return {"error": "forbidden: not assigned to this course"}, 403
+
+    # --- Mutation (only after all checks pass) ----------------------------
+    row = find_grade(student_id, course_id)
+    if row is None:
+        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
+    else:
+        row["grade"] = grade
+
+    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}
Control implemented
The endpoint now enforces a check-before-mutate sequence with four gates, in this order:

Authentication — flask.session["user"] must resolve to a live User. Missing/expired session → 401.

Role authorization — only professor and admin may write grades. Students (and any future role not explicitly allowed) get 403. This is an allow-list, not a deny-list.

Input validation — body must be a JSON object with coercible student_id, course_id, and grade; grade bounded to 0..20; target student must exist. Failures → 400/404. This prevents the "create a grade for a nonexistent student" and malformed-payload variants.

Course-scope authorization — a professor may only write grades for courses in user.courses. Admins bypass this check. A professor targeting an unassigned course → 403.

The mutation (append/update) happens only after all four gates pass, so a rejected request cannot alter GRADES. This directly satisfies "should not succeed, and not alter any data."

Affected paths sharing the root cause
The same missing-control pattern exists elsewhere and should be reviewed in the same hardening pass:

GET /grades/<student_id> — no auth check; any caller can enumerate any student's grades. Not in scope of this finding (it's a read), but the identical int(student_id) + no session check shape means it will likely surface as a separate finding. Recommended: require auth, and restrict students to their own student_id; restrict professors to their assigned courses; allow admin.

GET /students/<student_id>/profile — same pattern: unauthenticated PII disclosure. Recommended: require authentication and scope by role (student only self; professor/admin broader).

GET /files — path traversal is a separate class of bug (MATERIALS_DIR / raw_path with no normalization/containment check). Not addressed here, but note it so it isn't conflated with this fix.

@app.errorhandler(Exception) — returns str(exc) and exc.__class__.__name__ to the client, which leaks internals and also converts any HTTPException (including the 403/401 above if raised) into a 500. The patch returns tuples rather than raising, so it is unaffected, but the handler should be narrowed to not swallow HTTPException and not echo exception text.

Remaining assumptions / limitations
Session-based identity is trusted. If Flask's SECRET_KEY is the dev default ("dev-secret-key"), sessions are forgeable and all the above is moot. That must be replaced with a real secret in any non-demo deployment. Out of scope for this patch but a hard prerequisite.

Passwords are stored in plaintext and compared with !=. A real fix needs hashing (e.g., werkzeug.security) and constant-time comparison. Not in scope; noted because the auth gate above is only as strong as the login it depends on.

user.courses is the only course-assignment source. If course ownership ever moves to a DB or per-term assignment, this check must be updated in lockstep. The check is intentionally localized to one place.

No CSRF protection. Session-cookie auth + state-changing POST means CSRF is possible. The SECRET_KEY and cookie settings matter here too.

/grades/update now returns 401/403/400/404 instead of the previous unconditional 200. Callers relying on the old permissive contract will break — that is the intended behavior change. The success-path response body is unchanged, preserving the legitimate contract.

Concurrent writes are still not locked (GRADES is a module-level list). Not a security issue for this finding, but a correctness one under load.

Suggested regression tests
Add to tests_security/test_grade_authorization.py:

python
def test_unauthenticated_cannot_update_grade(client):
    r = client.post("/grades/update",
                    json={"student_id": 1001, "course_id": "SRS", "grade": 20})
    assert r.status_code == 401
    assert find_grade(1001, "SRS")["grade"] == 14  # unchanged

def test_student_cannot_update_grade(client):
    login(client, "alice", "alicepw")
    r = client.post("/grades/update",
                    json={"student_id": 1001, "course_id": "SRS", "grade": 20})
    assert r.status_code == 403
    assert find_grade(1001, "SRS")["grade"] == 14

def test_assigned_professor_can_update_own_course(client):
    login(client, "prof_srs", "profpw")
    r = client.post("/grades/update",
                    json={"student_id": 1001, "course_id": "SRS", "grade": 17})
    assert r.status_code == 200
    assert find_grade(1001, "SRS")["grade"] == 17

def test_professor_wrong_course_does_not_alter_data(client):
    login(client, "prof_srs", "profpw")
    before = find_grade(1001, "SSD")["grade"]
    r = client.post("/grades/update",
                    json={"student_id": 1001, "course_id": "SSD", "grade": 18})
    assert r.status_code == 403
    assert find_grade(1001, "SSD")["grade"] == before  # explicitly assert no mutation

def test_admin_can_update_any_course(client):
    login(client, "admin1", "adminpw")
    r = client.post("/grades/update",
                    json={"student_id": 1002, "course_id": "SSD", "grade": 12})
    assert r.status_code == 200

def test_invalid_grade_rejected_without_mutation(client):
    login(client, "admin1", "adminpw")
    before = find_grade(1001, "SRS")["grade"]
    r = client.post("/grades/update",
                    json={"student_id": 1001, "course_id": "SRS", "grade": 99})
    assert r.status_code == 400
    assert find_grade(1001, "SRS")["grade"] == before

def test_unknown_student_rejected(client):
    login(client, "admin1", "adminpw")
    r = client.post("/grades/update",
                    json={"student_id": 9999, "course_id": "SRS", "grade": 10})
    assert r.status_code == 404
    assert find_grade(9999, "SRS") is None
The key regression shape is: assert the status code and assert the data is unchanged — a 403 that still mutates would pass a status-only check but fail the goal.



Does it address the root cause or just the supplied example input?
It adresses the root cause aswell as more than what was requested ,
request - must be in course you want to change 
changes - return codes 
        authentication 
        authorization...
        range check (the other tests requirement)
due to this for the final patch we decided to prune the changes to stay more in range of what was asked 


Does an authentication check leave object/course authorization missing?
no , authentication is checked prior to authorization

Are all relevant paths protected, including read and update operations?
yes no writing gets preformed , checks are done before any updates 


Are authorized users still able to perform their permitted actions?
Yes authorized users in the correct course perform theyr action , and get a diferent error if outside theyr course 

Are denial responses and state changes correct?
Yes they are correct 

Has it introduced an unrelated change, broad exception handler, or insecure fallback?
not "unrelated" but unasked change , range validation
no boread exception handler or insecure fallback



pruned fix :


@app.post("/grades/update")
def update_grade():
    data = flask.request.get_json()

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    #added from the test to prevent profs from updating grades for courses they are not assigned to
    username = flask.session.get("user")
    user = USERS.get(username)
    if user is None:
        # Session references a user that no longer exists.
        flask.session.clear()
        return {"error": "authentication required"}, 401
    if user.role == "professor" and course_id not in (user.courses or []):
        return {"error": "forbidden: not assigned to this course"}, 403
    #added from the test to prevent profs from updating grades for courses they are not assigned to~

    ...