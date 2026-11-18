import pytest

import cybersecurity_lab_devsecops.secure_coding_testing.baseline_secure_coding_api as baseline_secure_coding_api


@pytest.fixture
def client():
    baseline_secure_coding_api.app.config["TESTING"] = True
    with baseline_secure_coding_api.app.test_client() as client:
        yield client


def login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


# Negative test
# ASVS: V4 Access Control
# Requirement: R2, R3
def test_student_cannot_update_grades(client):
    login(client, "alice", "alicepw")

    response = client.post(
        "/grades/update",
        json={
            "student_id": 1001,
            "course_id": "SRS",
            "grade": 18,
        },
    )

    assert response.status_code in (401, 403)


# Positive test
# ASVS: V4 Access Control
# Requirement: R2, R3
def test_professor_can_update_grade(client):
    login(client, "prof_srs", "profpw")

    response = client.post(
        "/grades/update",
        json={
            "student_id": 1001,
            "course_id": "SRS",
            "grade": 18,
        },
    )

    assert response.status_code == 200