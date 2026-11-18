We are now repairing a confirmed vulnerability in the supplied application.
Confirmed finding:

test_FAIL_assigned_professor_can_update_grade_no_upper_bound _________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>

    def test_FAIL_assigned_professor_can_update_grade_no_upper_bound(client):
        login(client, "prof_srs", "profpw")
        response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SRS", "grade": 21},
        )
>       assert response.status_code != 200 , "was able to update grade above upper bound"
E       AssertionError: was able to update grade above upper bound
E       assert 200 != 200
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:40: AssertionError

affected code : update grades api 
Required behavior:
grades should not be allowed to be outside the range 0-20

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.
Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.
Root cause
POST /grades/update accepts grade from the client and writes it into GRADES with no validation. Any authenticated user (the endpoint has no auth check at all) can set a grade to any value, e.g. 21, -5, or a non-integer/bool. The confirmed finding only flags the missing upper bound, but the same code path has additional defects that must be fixed together so the control is complete:

No numeric range check (0 <= grade <= 20).

No type check — "grade": "20" or true would be stored as-is and later break comparisons/serialization.

No authentication/authorization at all on a grade-mutating endpoint (out of scope for this specific test, but a real issue worth noting).

int(student_id) / int(course_id) coercion and missing keys raise KeyError/ValueError → caught by the broad handler and returned as 500 with an exception string (info leak), rather than a clean 400.

The minimal fix for the reported vulnerability is range + type validation on the grade in the update handler. I'll also make the endpoint fail cleanly with 400 on bad input, since that is part of "relevant response contracts" and avoids the info-leaking 500 path.

Patch
diff
--- a/app.py
+++ b/app.py
@@
 @app.post("/grades/update")
 def update_grade():
-    data = flask.request.get_json()
-
-    student_id = data["student_id"]
-    course_id = data["course_id"]
-    grade = data["grade"]
+    data = flask.request.get_json(silent=True)
+    if not isinstance(data, dict):
+        return {"error": "invalid request body"}, 400
+
+    student_id = data.get("student_id")
+    course_id = data.get("course_id")
+    grade = data.get("grade")
+
+    # Validate identifiers.
+    if not isinstance(student_id, int) or isinstance(student_id, bool):
+        return {"error": "student_id must be an integer"}, 400
+    if not isinstance(course_id, str) or not course_id:
+        return {"error": "course_id must be a non-empty string"}, 400
+
+    # Validate grade: integer within the closed interval [0, 20].
+    if not isinstance(grade, int) or isinstance(grade, bool):
+        return {"error": "grade must be an integer"}, 400
+    if grade < 0 or grade > 20:
+        return {"error": "grade must be between 0 and 20"}, 400
 
     row = find_grade(student_id, course_id)
     if row is None:
         GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
     else:
         row["grade"] = grade
 
     return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}
(Only update_grade is touched; find_grade, the seed data, and all other endpoints are unchanged.)

Control being implemented
Server-side validation as the authoritative gate. The client-supplied grade is validated on the server before any mutation: it must be a real int (not bool, which is an int subclass in Python) and must satisfy 0 <= grade <= 20. Out-of-range or wrongly-typed values are rejected with 400 and no mutation occurs, so find_grade/GRADES are never touched.

Input shape hardening on the same code path: get_json(silent=True) plus explicit key/type checks convert malformed requests into 400 responses instead of the broad handler's 500 with str(exc) (which leaked exception types/messages).

Contract preserved: a valid request still returns {"status": "ok", "student_id": ..., "course_id": ..., "grade": ...} with 200, and the existing find_grade upsert semantics are unchanged.

Remaining assumptions / limitations
Authorization is still absent on this endpoint. The finding is about the range check, but the test name (assigned_professor_can_update_grade) implies the intended model is "only the assigned professor may update grades for their course." The patch does not add authz; that is a separate finding and should be tracked separately (e.g. require a session, role professor, and course_id in session["courses"], and reject student_id/course_id mismatches).

Grade scale assumption: the closed range [0, 20] is hard-coded per the requirement. If the scale ever becomes configurable, this becomes a policy constant that must be centralized.

Existing bad data: seed GRADES are all in range, but if this were a real DB the patch would not retroactively fix out-of-range rows. A data-migration/cleanup step would be needed.

bool handling is deliberate (rejects True/False as grades). If a client legitimately needs 0/1 grades, they must send integers.

get_profile / get_grades still call int(student_id) without a guard; a non-numeric path segment yields a 500 via the broad handler. Not part of this finding, but the same pattern exists there — worth a follow-up.

Suggested regression tests
test_grade_above_upper_bound_rejected — grade=21 → 400, and confirm find_grade(1001, "SRS")["grade"] is unchanged (this is the confirmed finding).

test_grade_below_lower_bound_rejected — grade=-1 → 400.

test_grade_bounds_accepted — parametrize grade in (0, 20) → 200, value stored.

test_grade_wrong_type_rejected — grade="15", grade=15.5, grade=None, grade=True → 400.

test_update_missing_field_rejected — omit grade / student_id / course_id → 400 (not 500).

test_update_malformed_body_rejected — non-JSON body, JSON array → 400.

test_out_of_range_does_not_create_row — update a non-existent (student_id, course_id) with grade=21 → 400 and no new row appended.

Follow-up (separate finding): test_unauthenticated_cannot_update_grade, test_student_cannot_update_grade, test_professor_cannot_update_other_course_grade — once authz is added.



Does it address the root cause or just the supplied example input?
It adresses the root cause directly
request - value must be 0-20
changes -  value must be 0-20
        value validation



Does an authentication check leave object/course authorization missing?
no authentication check was requested for this test

Are all relevant paths protected, including read and update operations?
no change was made to path protection

Are authorized users still able to perform their permitted actions?
Yes authorized users can perform theyr action , within the bounds defined

Are denial responses and state changes correct?
Yes they are correct 

Has it introduced an unrelated change, broad exception handler, or insecure fallback?
no , no broad exception was added or unrelated change , but 
data = flask.request.get_json(silent=True)
+    if not isinstance(data, dict):
+        return {"error": "invalid request body"}, 400
is slightly out of context for what was asked so we pruned the fix to :

pruned fix : 

 #range check for grade
    if not isinstance(student_id, int) or isinstance(student_id, bool):
        return {"error": "student_id must be an integer"}, 400
    if not isinstance(course_id, str) or not course_id:
        return {"error": "course_id must be a non-empty string"}, 400

    # Validate grade: integer within the closed interval [0, 20].
    if not isinstance(grade, int) or isinstance(grade, bool):
        return {"error": "grade must be an integer"}, 400
    if grade < 0 or grade > 20:
        return {"error": "grade must be between 0 and 20"}, 400
#range check for grade