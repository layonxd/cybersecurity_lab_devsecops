tests_security/test_grade_authorization.py::test_FAIL_assigned_professor_can_update_grade_wrong_course FAILED [ 16%]
tests_security/test_grade_authorization.py::test_assigned_professor_can_update_grade PASSED [ 33%]
tests_security/test_grade_authorization.py::test_FAIL_assigned_professor_can_update_grade_no_upper_bound FAILED [ 50%]


=================================== FAILURES ===================================
__________ test_FAIL_assigned_professor_can_update_grade_wrong_course __________

client = <FlaskClient <Flask 'baseline_secure_coding_api'>>

    def test_FAIL_assigned_professor_can_update_grade_wrong_course(client):
        login(client, "prof_srs", "profpw")
        response = client.post(
            "/grades/update",
            json={"student_id": 1001, "course_id": "SSD", "grade": 18},
        )
>       assert response.status_code != 200 , "oops prof_srs was able to update a grade for a course he is not assigned to"
E       AssertionError: oops prof_srs was able to update a grade for a course he is not assigned to
E       assert 200 != 200
E        +  where 200 = <WrapperTestResponse streamed [200 OK]>.status_code

tests_security/test_grade_authorization.py:20: AssertionError
_________ test_FAIL_assigned_professor_can_update_grade_no_upper_bound _________

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



